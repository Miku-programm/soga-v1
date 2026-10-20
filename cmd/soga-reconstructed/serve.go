package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/engine"
	"reconstructed.local/soga/logging"
	"reconstructed.local/soga/monitor"
	"reconstructed.local/soga/updater"
)

func serve(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var file string
	fs.StringVar(&file, "c", "/etc/soga-reconstructed/soga.conf", "configuration file")
	fs.StringVar(&file, "config", "/etc/soga-reconstructed/soga.conf", "configuration file")
	paths := engine.Paths{}
	fs.StringVar(&paths.BlockList, "b", "/etc/soga-reconstructed/blockList", "local block list")
	fs.StringVar(&paths.WhiteList, "w", "/etc/soga-reconstructed/whiteList", "local white list")
	fs.StringVar(&paths.DNS, "d", "/etc/soga-reconstructed/dns.yml", "DNS rules")
	fs.StringVar(&paths.Routes, "r", "/etc/soga-reconstructed/routes.toml", "outbound routes")
	fs.StringVar(&paths.StateDir, "state-dir", "", "persistent state (default: state beside configuration)")
	fs.StringVar(&paths.GeoSite, "geosite", "", "V2Ray geosite.dat")
	fs.StringVar(&paths.GeoIP, "geoip", "", "V2Ray geoip.dat")
	fs.StringVar(&paths.ACMEExecutable, "acme-executable", "", "optional acme.sh executable")
	updateManifest := fs.String("update-manifest", "", "release manifest for this reconstruction (required for auto_update)")
	restartAfterUpdate := fs.Bool("restart-after-update", false, "exit 75 after an update so the service supervisor restarts this process")
	values := make(map[string]*string)
	for _, key := range config.Keys() {
		values[key] = fs.String(key, "", "configuration override")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "serve takes no positional arguments")
		return 2
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	flags := make(map[string]string)
	fs.Visit(func(f *flag.Flag) {
		if p, ok := values[f.Name]; ok {
			flags[f.Name] = *p
		}
	})
	loaded, err := config.Load(f, config.LoadOptions{Flags: flags, Environ: os.Environ()})
	_ = f.Close()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if *updateManifest == "" {
		*updateManifest = loaded.Values["reconstruction_update_url"]
	}
	if loaded.Config.AutoUpdate {
		if err := updater.ValidateURL(*updateManifest); err != nil {
			fmt.Fprintln(errOut, "auto_update requires a reconstruction release manifest: use -update-manifest or reconstruction_update_url:", err)
			return 1
		}
	}
	if paths.StateDir == "" {
		paths.StateDir = filepath.Join(filepath.Dir(file), "state")
	}
	paths.GeoSite, paths.GeoIP, err = discoverGeoPaths(file, paths.GeoSite, paths.GeoIP)
	if err != nil {
		fmt.Fprintln(errOut, "local geodata:", err)
		return 1
	}
	ids := loaded.Config.NodeId
	if len(ids) == 0 {
		fmt.Fprintln(errOut, "node_id is required")
		return 1
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			fmt.Fprintln(errOut, "duplicate node_id", id)
			return 1
		}
		seen[id] = true
	}
	var level slog.Level
	switch loaded.Config.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "", "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		fmt.Fprintln(errOut, "unknown log_level", loaded.Config.LogLevel)
		return 1
	}
	logWriter := errOut
	if dir := loaded.Config.LogFileDir; dir != "" && dir != "false" {
		file, err := logging.NewRotating(dir, "soga-", false, int(loaded.Config.LogFileRetentionDays))
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		defer file.Close()
		logWriter = io.MultiWriter(errOut, file)
	}
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level}))
	// Install termination handlers before opening any listeners. Once the
	// readiness line is emitted, SIGTERM must always enter graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.Signal(15))
	defer cancel()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.Signal(1), syscall.Signal(10))
	defer signal.Stop(signals)
	var nodes []*engine.Node
	var diagnostics *monitor.Servers
	shutdown := func() error {
		cancel()
		finalCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		var err error
		err = errors.Join(err, diagnostics.Close(finalCtx))
		for _, node := range nodes {
			err = errors.Join(err, node.Close(finalCtx))
		}
		return err
	}
	for _, id := range ids {
		node, err := engine.StartNode(ctx, engine.Options{
			Config: loaded.Config, Values: loaded.Values, Explicit: loaded.Explicit, Paths: paths, NodeID: id, Logger: logger,
		})
		if err != nil {
			logger.Error("startup failed", "node_id", id, "error", err)
			if err := shutdown(); err != nil {
				logger.Error("shutdown report incomplete; traffic remains in state directory", "error", err)
			}
			return 1
		}
		nodes = append(nodes, node)
	}
	diagnostics, err = monitor.Start(loaded.Config, nodes)
	if err != nil {
		logger.Error("diagnostics startup failed", "error", err)
		_ = shutdown()
		return 1
	}
	fmt.Fprintf(out, "started %d node(s)\n", len(nodes))
	// Linux signal 10 matches the recovered refresh callback; SIGHUP is also
	// accepted by this new CLI. Constants as numbers preserve Windows builds.
	updates := make(chan updater.Result, 1)
	if loaded.Config.AutoUpdate {
		executable, err := os.Executable()
		if err != nil {
			_ = shutdown()
			fmt.Fprintln(errOut, err)
			return 1
		}
		go func() {
			for {
				result, err := updater.CheckAndInstall(ctx, updater.Options{ManifestURL: *updateManifest, Executable: executable, CurrentVersion: reconstructionVersion})
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					logger.Warn("automatic update failed; current executable retained", "error", err)
				}
				if result.Updated || result.RestartRequired {
					updates <- result
					return
				}
				timer := time.NewTimer(24 * time.Hour)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	for {
		var sig os.Signal
		select {
		case <-ctx.Done():
		case result := <-updates:
			logger.Info("reconstruction release ready on disk", "version", result.Version, "backup", result.Backup)
			if *restartAfterUpdate {
				if err := shutdown(); err != nil {
					logger.Error("final report incomplete; pending traffic retained", "error", err)
				}
				return 75
			}
			logger.Info("restart this process or container to load the installed release")
			continue
		case sig = <-signals:
		}
		if sig == syscall.Signal(1) || sig == syscall.Signal(10) {
			for _, node := range nodes {
				if err := node.Sync(ctx); err != nil {
					logger.Error("refresh failed; previous configuration retained when validation fails", "error", err)
				}
			}
			continue
		}
		if err := shutdown(); err != nil {
			logger.Error("shutdown report incomplete; traffic remains in state directory", "error", err)
			return 1
		}
		return 0
	}
}
