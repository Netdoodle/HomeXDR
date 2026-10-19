//go:build linux

// Package linux is the Linux platform: eBPF process, network and DNS sensors (with
// netlink, /proc and packet-capture fallbacks), a fanotify/inotify file sensor, an auth
// log sensor, nftables or iptables isolation, the artifact collectors, and systemd
// integration.
package linux

import (
	"context"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Platform implements platform.Platform for Linux.
type Platform struct{}

// New returns the Linux platform.
func New() *Platform { return &Platform{} }

// Name returns "linux".
func (*Platform) Name() string { return event.PlatformLinux }

// Paths returns default locations.
func (*Platform) Paths() platform.Paths {
	return platform.Paths{
		ConfigFile:   "/etc/homexdr/agent.json",
		DataDir:      "/var/lib/homexdr",
		FIMDefaults:  []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/root/.ssh"},
		FileDefaults: []string{"/etc", "/tmp", "/var/tmp", "/dev/shm", "/home", "/root"},
	}
}

// HostInfo returns host details.
func (*Platform) HostInfo(ctx context.Context) api.HostInfo { return hostInfo(ctx) }

// Sensors returns the Linux sensors for the enabled kinds. Library-load telemetry is
// not implemented on Linux; the core reports it as unavailable.
func (p *Platform) Sensors(cfg api.SensorsConfig, env platform.Env) []platform.Sensor {
	var out []platform.Sensor
	if cfg.Process.Enabled {
		out = append(out, newProcessSensor(cfg.Process, env))
	}
	if cfg.Network.Enabled {
		out = append(out, newNetworkSensor(env))
	}
	if cfg.DNS.Enabled {
		out = append(out, newDNSSensor(env))
	}
	if cfg.File.Enabled {
		out = append(out, newFileSensor(cfg.File, p.Paths().FileDefaults, env))
	}
	if cfg.Auth.Enabled {
		out = append(out, newAuthSensor(env))
	}
	return out
}

// Responder returns the Linux responder.
func (*Platform) Responder(env platform.Env) platform.Responder { return &responder{env: env} }

// Collectors returns the Linux artifact collectors.
func (*Platform) Collectors(env platform.Env) map[string]platform.Collector { return collectors(env) }

// Service returns the systemd integration.
func (*Platform) Service() platform.Service { return systemdService{} }
