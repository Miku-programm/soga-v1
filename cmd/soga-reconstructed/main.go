// soga-reconstructed combines recovered configuration logic with independently
// implemented panel and protocol compatibility code.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/rulelist"
)

const recoveredVersion = "2.17.0"

// This version belongs to the independent source project, not the sample.
var reconstructionVersion = "0.1.0"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(out, `soga-reconstructed: independent compatibility reconstruction of soga 2.17.0

Commands:
  version                 Print source-sample version and reconstruction status
  defaults                Print 157 recovered configuration defaults as JSON
  inspect -c FILE          Parse a configuration file and report normalized values
  list -file FILE         Parse a local blockList or whiteList file
  serve -c FILE           Start panel-managed proxy nodes
  instance COMMAND        Manage isolated instances (use instance for help)
  update -manifest URL    Verify and install a reconstruction release
  self-update            Alias of update; management commands are built in

inspect options:
  -with-env               Apply this process's environment as the binary does
  -show-secrets           Include credential values in JSON
  -CONFIG_KEY VALUE       Apply a recovered configuration key as a command-line value

list options:
  -forbidden-ports VALUE  Append comma-separated port rules (blockList behavior)

serve applies environment variables and configuration overrides.
Use serve -h for paths and available settings.

This is an independent compatibility reconstruction, not original soga source.
Consult the delivered feature matrix for validated features and limitations.`)
		return 0
	}
	switch args[0] {
	case "version", "-version", "--version", "-v":
		fmt.Fprintf(out, "soga-reconstructed %s (reference sample: soga %s; independent reconstruction, not original source)\n", reconstructionVersion, recoveredVersion)
		return 0
	case "defaults":
		if len(args) != 1 {
			fmt.Fprintln(errOut, "defaults takes no arguments")
			return 2
		}
		return writeJSON(out, errOut, config.DefaultValues())
	case "inspect":
		return inspect(args[1:], out, errOut)
	case "list":
		return inspectList(args[1:], out, errOut)
	case "serve":
		return serve(args[1:], out, errOut)
	case "instance":
		return instances(args[1:], out, errOut)
	case "instance-run":
		return instanceRun(args[1:], out, errOut)
	case "update", "self-update":
		return updateCommand(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown command %q; use help\n", args[0])
		return 2
	}
}

func inspect(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var path string
	fs.StringVar(&path, "c", "", "configuration file to read")
	fs.StringVar(&path, "config", "", "configuration file to read")
	withEnv := fs.Bool("with-env", false, "apply process environment")
	showSecrets := fs.Bool("show-secrets", false, "include credentials in output")
	values := make(map[string]*string)
	for _, key := range config.Keys() {
		values[key] = fs.String(key, "", "recovered configuration value")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if path == "" || fs.NArg() != 0 {
		fmt.Fprintln(errOut, "inspect requires -c FILE and no positional arguments")
		return 2
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	defer f.Close()
	flags := make(map[string]string)
	fs.Visit(func(f *flag.Flag) {
		if p, exists := values[f.Name]; exists {
			flags[f.Name] = *p
		}
	})
	opts := config.LoadOptions{Flags: flags}
	if *withEnv {
		opts.Environ = os.Environ()
	}
	loaded, err := config.Load(f, opts)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	reported := make(map[string]string, len(loaded.Values))
	redacted := 0
	for key, value := range loaded.Values {
		if !*showSecrets && value != "" && secretKey(key) {
			value = "[REDACTED]"
			redacted++
		}
		reported[key] = value
	}
	result := struct {
		SourceVersion          string            `json:"source_version"`
		ReconstructionStatus   string            `json:"reconstruction_status"`
		NormalizedServerType   string            `json:"normalized_server_type"`
		EffectiveAPIKeyPresent bool              `json:"effective_api_key_present"`
		LegacyAPIKeySelected   bool              `json:"legacy_api_key_selected"`
		RedactedValues         int               `json:"redacted_values"`
		Values                 map[string]string `json:"values"`
	}{
		SourceVersion:          recoveredVersion,
		ReconstructionStatus:   "independent compatibility reconstruction; see feature matrix",
		NormalizedServerType:   config.NormalizeServerType(loaded.Config.ServerType),
		EffectiveAPIKeyPresent: loaded.Config.EffectiveWebAPIKey() != "",
		LegacyAPIKeySelected:   loaded.Config.UsesLegacyWebAPIKey(),
		RedactedValues:         redacted,
		Values:                 reported,
	}
	return writeJSON(out, errOut, result)
}

func inspectList(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := fs.String("file", "", "local rule-list file")
	ports := fs.String("forbidden-ports", "", "comma-separated forbidden ports")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(errOut, "list requires -file FILE")
		return 2
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	defer f.Close()
	var forbidden []string
	for _, port := range strings.Split(*ports, ",") {
		if port = strings.TrimSpace(port); port != "" {
			forbidden = append(forbidden, port)
		}
	}
	rules, err := rulelist.ReadLocal(f, forbidden)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return writeJSON(out, errOut, rules)
}

func secretKey(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "password") || strings.Contains(key, "secret") ||
		strings.Contains(key, "token") || strings.HasSuffix(key, "_key") ||
		strings.HasSuffix(key, "_mukey") || strings.Contains(key, "private_key") ||
		strings.Contains(key, "privatekey")
}

func writeJSON(out, errOut io.Writer, value any) int {
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	if err := e.Encode(value); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}
