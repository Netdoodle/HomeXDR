//go:build windows

// Package windows is the Windows platform.
package windows

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/windows"
)

// Platform implements platform.Platform for Windows.
type Platform struct{}

// New returns the Windows platform.
func New() *Platform { return &Platform{} }

// Name returns "windows".
func (*Platform) Name() string { return event.PlatformWindows }

// Paths returns default locations.
func (*Platform) Paths() platform.Paths {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return platform.Paths{
		ConfigFile: pd + `\HomeXDR\agent.json`,
		DataDir:    pd + `\HomeXDR\data`,
		FIMDefaults: []string{
			`C:\Windows\System32\drivers\etc`,
			`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
		},
		FileDefaults: []string{`C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`},
	}
}

// HostInfo returns host details.
func (*Platform) HostInfo(context.Context) api.HostInfo {
	h, _ := os.Hostname()
	info := api.HostInfo{Hostname: h, OS: event.OS{Platform: event.PlatformWindows, Family: "windows"}, Arch: runtime.GOARCH, CPUs: runtime.NumCPU()}
	v := windows.RtlGetVersion()
	info.OS.Version = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	return info
}

// Sensors returns the Windows sensors.
func (*Platform) Sensors(api.SensorsConfig, platform.Env) []platform.Sensor { return nil }

// Responder returns the Windows responder.
func (*Platform) Responder(platform.Env) platform.Responder { return platform.UnsupportedResponder{} }

// Collectors returns the Windows artifact collectors.
func (*Platform) Collectors(platform.Env) map[string]platform.Collector {
	return map[string]platform.Collector{}
}

// Service returns the Windows service integration.
func (*Platform) Service() platform.Service { return platform.UnsupportedService{} }
