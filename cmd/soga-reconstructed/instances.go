package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const instanceRoot = "/etc/soga"

var instanceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func instanceDir(root, name string) (string, error) {
	if !instanceName.MatchString(name) {
		return "", errors.New("instance name must be 1..64 letters, digits, underscores or hyphens")
	}
	if name == "default" {
		return root, nil
	}
	return filepath.Join(root, name), nil
}

func instanceRun(args []string, out, errOut io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(errOut, "instance-run requires one instance name")
		return 2
	}
	dir, err := instanceDir(instanceRoot, args[0])
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	return serve([]string{"-c", filepath.Join(dir, "soga.conf"),
		"-b", filepath.Join(dir, "blockList"), "-w", filepath.Join(dir, "whiteList"),
		"-d", filepath.Join(dir, "dns.yml"), "-r", filepath.Join(dir, "routes.toml"),
		"-state-dir", filepath.Join(dir, "state"), "-acme-executable", "/root/.acme.sh/acme.sh", "-restart-after-update"}, out, errOut)
}

func systemCommand(out, errOut io.Writer, program string, args ...string) error {
	cmd := exec.Command(program, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = out, errOut, os.Stdin
	return cmd.Run()
}

func instances(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("instance", flag.ContinueOnError)
	fs.SetOutput(errOut)
	root := fs.String("root", instanceRoot, "instance configuration root (custom roots are for offline configuration management)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	args = fs.Args()
	if len(args) == 0 {
		fmt.Fprintln(out, `instance [-root DIR] <command>
  list                          List configured instances
  new NAME [key=value ...]       Inherit default configuration and create NAME
  config [NAME] [key=value ...]  View or atomically edit an instance configuration
  remove NAME [...]             Stop, disable, and remove named instances
  rename OLD NEW                Rename a stopped, disabled instance
  start|stop|restart [NAME]      Manage a systemd service
  enable|disable|status [NAME]   Manage or inspect a systemd service
  log [NAME] [-f]               Read the last 1000 journal lines

The default instance cannot be removed or renamed. New instances are not started
automatically. Commands that use systemd require the installed default root.`)
		return 0
	}
	action, rest := args[0], args[1:]
	err := manageInstances(*root, action, rest, out, errOut)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func manageInstances(root, action string, args []string, out, errOut io.Writer) error {
	unit := func(name string) string {
		if name == "default" {
			return "soga.service"
		}
		return "soga@" + name + ".service"
	}
	checkRoot := func() error {
		if filepath.Clean(root) != instanceRoot {
			return errors.New("systemd commands require /etc/soga; custom roots support only offline file operations")
		}
		return nil
	}
	switch action {
	case "list":
		if len(args) != 0 {
			return errors.New("list takes no names")
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		var names []string
		if _, err = os.Stat(filepath.Join(root, "soga.conf")); err == nil {
			names = append(names, "default")
		}
		for _, entry := range entries {
			if entry.Name() == "default" || !entry.IsDir() || !instanceName.MatchString(entry.Name()) {
				continue
			}
			if _, err = os.Stat(filepath.Join(root, entry.Name(), "soga.conf")); err == nil {
				names = append(names, entry.Name())
			}
		}
		slices.Sort(names)
		for _, name := range names {
			status := "configuration only"
			if filepath.Clean(root) == instanceRoot {
				data, _ := exec.Command("systemctl", "is-active", unit(name)).Output()
				if s := strings.TrimSpace(string(data)); s != "" {
					status = s
				}
			}
			fmt.Fprintf(out, "%s\t%s\n", name, status)
		}
		return nil
	case "new":
		if len(args) < 1 || args[0] == "default" {
			return errors.New("new requires a non-default instance name")
		}
		dir, err := instanceDir(root, args[0])
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(root, "soga.conf"))
		if err != nil {
			return fmt.Errorf("read default template: %w", err)
		}
		data, err = editInstanceConfig(data, args[1:])
		if err != nil {
			return err
		}
		if err = os.Mkdir(dir, 0700); err != nil {
			return err
		}
		if err = writeInstanceFile(filepath.Join(dir, "soga.conf"), data); err != nil {
			_ = os.Remove(dir)
			return err
		}
		fmt.Fprintln(out, "created", args[0])
		return nil
	case "config":
		name := "default"
		if len(args) > 0 && !strings.Contains(args[0], "=") {
			name, args = args[0], args[1:]
		}
		dir, err := instanceDir(root, name)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "soga.conf")
		if len(args) == 0 {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = out.Write(data)
			return err
		}
		lock, err := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("configuration is locked: %w", err)
		}
		lock.Close()
		defer os.Remove(path + ".lock")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data, err = editInstanceConfig(data, args)
		if err != nil {
			return err
		}
		if err = writeInstanceFile(path, data); err != nil {
			return err
		}
		fmt.Fprintln(out, "updated", name, "(restart the instance to reload its main configuration)")
		return nil
	case "remove":
		if len(args) == 0 {
			return errors.New("remove requires at least one non-default name")
		}
		// Validate the whole request before stopping or deleting any instance.
		for _, name := range args {
			if name == "default" {
				return errors.New("default cannot be removed")
			}
			dir, err := instanceDir(root, name)
			if err != nil {
				return err
			}
			if _, err = os.Stat(filepath.Join(dir, "soga.conf")); err != nil {
				return err
			}
		}
		for _, name := range args {
			if filepath.Clean(root) == instanceRoot {
				if err := systemCommand(out, errOut, "systemctl", "disable", "--now", unit(name)); err != nil {
					return err
				}
			}
			dir, _ := instanceDir(root, name)
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
			fmt.Fprintln(out, "removed", name)
		}
		return nil
	case "rename":
		if len(args) != 2 || args[0] == "default" || args[1] == "default" {
			return errors.New("rename requires two non-default names")
		}
		oldDir, err := instanceDir(root, args[0])
		if err != nil {
			return err
		}
		newDir, err := instanceDir(root, args[1])
		if err != nil {
			return err
		}
		if _, err = os.Lstat(newDir); !errors.Is(err, os.ErrNotExist) {
			return errors.New("destination already exists or cannot be inspected")
		}
		if _, err = os.Stat(filepath.Join(oldDir, "soga.conf")); err != nil {
			return err
		}
		if filepath.Clean(root) == instanceRoot {
			if err = systemCommand(out, errOut, "systemctl", "disable", "--now", unit(args[0])); err != nil {
				return err
			}
		}
		if err = os.Rename(oldDir, newDir); err != nil {
			return err
		}
		fmt.Fprintln(out, "renamed", args[0], "to", args[1], "(stopped and disabled)")
		return nil
	case "start", "stop", "restart", "enable", "disable", "status", "log":
		if err := checkRoot(); err != nil {
			return err
		}
		name := "default"
		if len(args) > 0 && args[0] != "-f" {
			name, args = args[0], args[1:]
		}
		dir, err := instanceDir(root, name)
		if err != nil {
			return err
		}
		if _, err = os.Stat(filepath.Join(dir, "soga.conf")); err != nil {
			return err
		}
		if action == "log" {
			command := []string{"--no-pager", "-u", unit(name), "-n", "1000"}
			if len(args) == 1 && args[0] == "-f" {
				command = append(command, "-f")
			} else if len(args) != 0 {
				return errors.New("log accepts only an optional -f")
			}
			return systemCommand(out, errOut, "journalctl", command...)
		}
		if len(args) != 0 {
			return errors.New("unexpected instance command arguments")
		}
		return systemCommand(out, errOut, "systemctl", action, unit(name))
	default:
		return fmt.Errorf("unknown instance command %q", action)
	}
}

func editInstanceConfig(data []byte, changes []string) ([]byte, error) {
	values := map[string]string{}
	var order []string
	for _, change := range changes {
		key, value, ok := strings.Cut(change, "=")
		if !ok || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid key=value argument")
		}
		key = strings.ToLower(key)
		if _, exists := values[key]; !exists {
			order = append(order, key)
		}
		values[key] = value
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var result []string
	for _, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			if _, changed := values[strings.ToLower(strings.TrimSpace(key))]; changed {
				continue
			}
		}
		result = append(result, line)
	}
	for len(result) > 0 && result[len(result)-1] == "" {
		result = result[:len(result)-1]
	}
	for _, key := range order {
		result = append(result, key+"="+values[key])
	}
	return []byte(strings.Join(result, "\n") + "\n"), nil
}

func writeInstanceFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
