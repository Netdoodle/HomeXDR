//go:build !windows

package selfupdate

import (
	"os"
	"syscall"
)

// Exec replaces the running process with exe, keeping the PID, arguments and
// environment, so service managers see the same process continue.
func Exec(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
