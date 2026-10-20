//go:build !linux

package certificates

import (
	"os/exec"
	"time"
)

func configureProcessCancellation(cmd *exec.Cmd) {
	cmd.WaitDelay = 5 * time.Second
}
