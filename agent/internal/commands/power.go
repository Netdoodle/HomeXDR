package commands

import (
	"context"
	"strconv"

	"github.com/Netdoodle/homexdr/shared/api"
)

// powerExec runs the OS shutdown command. It is a variable so tests never run it.
var powerExec = execShutdown

// unixShutdownArgv builds the arguments of shutdown(8) for Linux (systemd, sysvinit and
// Slackware/Unraid) and macOS: `-r|-h +M [msg]` with M the delay in whole minutes,
// rounded up, or `now` for no delay.
func unixShutdownArgv(shutdown bool, delaySec int, msg string) []string {
	flag := "-r"
	if shutdown {
		flag = "-h"
	}
	when := "now"
	if delaySec > 0 {
		when = "+" + strconv.Itoa((delaySec+59)/60)
	}
	argv := []string{flag, when}
	if msg != "" {
		argv = append(argv, msg)
	}
	return argv
}

// windowsShutdownArgv builds the arguments of shutdown.exe: `/r|/s /t SEC [/c msg]`.
func windowsShutdownArgv(shutdown bool, delaySec int, msg string) []string {
	flag := "/r"
	if shutdown {
		flag = "/s"
	}
	argv := []string{flag, "/t", strconv.Itoa(delaySec)}
	if msg != "" {
		argv = append(argv, "/c", msg)
	}
	return argv
}

// schedulePower asks the OS to reboot or power off after p.DelaySec seconds.
func schedulePower(ctx context.Context, shutdown bool, p api.HostPowerParams) error {
	name, argv := shutdownCommand(shutdown, p)
	return powerExec(ctx, name, argv...)
}
