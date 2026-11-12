//go:build darwin

// Package darwin is the macOS platform (Intel and Apple silicon). Process, auth and
// file telemetry come from Endpoint Security through Apple's eslogger (macOS 13+; the
// agent needs Full Disk Access), with process-table polling and the unified log as
// fallbacks; network connections from lsof polling; isolation from pf; the service from
// launchd. Everything is pure Go (no cgo), so the agent cross-compiles.
package darwin

import (
	"context"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Platform implements platform.Platform for macOS.
type Platform struct{}

// New returns the macOS platform.
func New() *Platform { return &Platform{} }

// Name returns "darwin".
func (*Platform) Name() string { return event.PlatformDarwin }

// Paths returns default locations.
func (*Platform) Paths() platform.Paths {
	return platform.Paths{
		ConfigFile: "/Library/Application Support/HomeXDR/agent.json",
		DataDir:    "/Library/Application Support/HomeXDR/data",
		FIMDefaults: []string{"/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents", "/usr/local/bin",
			"/var/root/.ssh", "/etc/ssh", "/etc/sudoers.d"},
		FileDefaults: []string{"/Users", "/tmp", "/Library/LaunchDaemons", "/Library/LaunchAgents", "/usr/local/bin", "/Applications"},
	}
}

// HostInfo returns host details.
func (*Platform) HostInfo(ctx context.Context) api.HostInfo { return hostInfo(ctx) }

// Sensors returns the macOS sensors for the enabled kinds. DNS and library-load
// telemetry are not implemented yet; the core reports them as unavailable.
func (p *Platform) Sensors(cfg api.SensorsConfig, env platform.Env) []platform.Sensor {
	var out []platform.Sensor
	if cfg.Process.Enabled {
		out = append(out, newProcessSensor(cfg.Process, env))
	}
	if cfg.Network.Enabled {
		out = append(out, newNetworkSensor(env))
	}
	if cfg.File.Enabled {
		out = append(out, newFileSensor(cfg.File, p.Paths().FileDefaults, env))
	}
	if cfg.Auth.Enabled {
		out = append(out, newAuthSensor(env))
	}
	return out
}

// Responder returns the macOS responder.
func (*Platform) Responder(env platform.Env) platform.Responder { return &responder{env: env} }

// Collectors returns the macOS artifact collectors.
func (*Platform) Collectors(env platform.Env) map[string]platform.Collector { return collectors(env) }

// Service returns the launchd integration.
func (*Platform) Service() platform.Service { return launchdService{} }
