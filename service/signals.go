package service

import (
	"os"
	"syscall"
)

// Lifecycle uses the method names retained by the original receiver.
// Implementations must provide the actual startup and shutdown behavior.
// The complete soga implementation of InitLinux is not reconstructed.
type Lifecycle interface {
	InitLinux()
	InitUnix()
}

// RunSignals reconstructs the callback main.main.func1 at 0x2019e80.
// It initializes before receiving a signal, then cleans up. Linux signal 10
// (SIGUSR1) starts another cycle; every other received value returns.
// Signal registration is left to the caller, making this reusable without
// installing process-wide handlers or suggesting a complete server exists.
func RunSignals(instance Lifecycle, signals <-chan os.Signal) {
	for {
		instance.InitLinux()
		sig := <-signals
		instance.InitUnix()
		if sig != syscall.Signal(10) {
			return
		}
	}
}
