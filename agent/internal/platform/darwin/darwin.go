//go:build darwin

// Package darwin is the macOS platform. It is a placeholder: the agent builds and
// reports host info, but has no sensors or response actions yet. Full support needs the
// Endpoint Security framework, which requires an Apple-granted entitlement.
package darwin

import (
	"context"
	"os"
	"runtime"

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
		ConfigFile:   "/Library/Application Support/HomeXDR/agent.json",
		DataDir:      "/Library/Application Support/HomeXDR/data",
		FIMDefaults:  []string{"/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents"},
		FileDefaults: []string{"/Users", "/tmp"},
	}
}

// HostInfo returns basic host details.
func (*Platform) HostInfo(context.Context) api.HostInfo {
	h, _ := os.Hostname()
	return api.HostInfo{Hostname: h, OS: event.OS{Platform: event.PlatformDarwin, Family: "macos", Name: "macOS"},
		Arch: runtime.GOARCH, CPUs: runtime.NumCPU()}
}

// Sensors returns none yet.
func (*Platform) Sensors(api.SensorsConfig, platform.Env) []platform.Sensor { return nil }

// Responder rejects actions.
func (*Platform) Responder(platform.Env) platform.Responder { return platform.UnsupportedResponder{} }

// Collectors returns none yet.
func (*Platform) Collectors(platform.Env) map[string]platform.Collector {
	return map[string]platform.Collector{}
}

// Service has no launchd integration yet.
func (*Platform) Service() platform.Service { return platform.UnsupportedService{} }
