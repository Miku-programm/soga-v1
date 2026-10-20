package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"reconstructed.local/soga/updater"
)

func updateCommand(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(errOut)
	manifest := fs.String("manifest", "", "HTTPS URL of a reconstruction release manifest")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *manifest == "" {
		fmt.Fprintln(errOut, "update requires -manifest URL")
		return 2
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := updater.CheckAndInstall(ctx, updater.Options{ManifestURL: *manifest, Executable: executable, CurrentVersion: reconstructionVersion})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if result.Updated {
		fmt.Fprintln(out, "installed", result.Version, "backup:", result.Backup, "; restart running instances")
	} else if result.RestartRequired {
		fmt.Fprintln(out, "already installed", result.Version, "; restart running instances")
	} else {
		fmt.Fprintln(out, "no newer release")
	}
	return 0
}
