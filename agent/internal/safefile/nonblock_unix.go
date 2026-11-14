//go:build !windows

package safefile

import "syscall"

// nonblock keeps open from waiting for a writer on a FIFO.
const nonblock = syscall.O_NONBLOCK
