package main

import (
	"os/exec"
	"syscall"
)

// createNoWindow keeps Claude Code's console from flashing up on the desktop when the
// runner runs in the background (built with -H=windowsgui, started by Task Scheduler).
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
