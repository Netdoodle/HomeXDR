// Package platform defines the boundary between the agent's cross-platform core and its
// OS-specific code. Each supported OS has a package under platform/ (linux, windows,
// darwin) that implements Platform; package osplatform picks the one for the build.
package platform

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// Env is what the core gives platform code.
type Env struct {
	// AgentID is the enrolled agent ID, used for process entity IDs.
	AgentID string
	// DataDir is writable and private to the agent (0700 / SYSTEM-only).
	DataDir string
	Log     *slog.Logger
}

// EntityID returns the process entity ID for a PID and platform start key
// (see event.ProcessEntityID for what the start key is on each OS).
func (e Env) EntityID(pid int64, startKey uint64) string {
	return event.ProcessEntityID(e.AgentID, pid, startKey)
}

// Emitter receives telemetry. Emit must return quickly; the core filters and spools to
// disk. Emitters are safe for concurrent use.
type Emitter interface {
	Emit(e *event.Event)
}

// EmitterFunc adapts a function to Emitter.
type EmitterFunc func(e *event.Event)

// Emit calls f(e).
func (f EmitterFunc) Emit(e *event.Event) { f(e) }

// Sensor is a telemetry source.
type Sensor interface {
	// Name is the sensor kind reported in heartbeats and matched to the central config:
	// "process", "network", "file", "registry", "dns", "library", "auth", "eventlog".
	Name() string
	// Run streams events until ctx is cancelled. It returns a non-nil error only when the
	// sensor cannot run at all; the core then reports it as failed and retries later.
	Run(ctx context.Context, out Emitter) error
	// Status reports health. Impl names the active implementation (an event.Module*
	// value), so a fallback shows up as e.g. "procconn" instead of "ebpf".
	Status() api.SensorStatus
}

// Isolation describes what stays reachable while a host is isolated. Loopback, DHCP and
// DNS to the host's configured resolvers are always allowed in addition.
type Isolation struct {
	ServerIPs  []netip.Addr
	ServerPort int
	Allow      []netip.Prefix
}

// Responder performs host response actions.
type Responder interface {
	// KillProcess terminates a process (and its descendants if p.Tree). If p.EntityID is
	// set it must first confirm the PID still belongs to that entity.
	KillProcess(ctx context.Context, p api.KillParams) (api.KillResult, error)
	// Isolate blocks all network traffic except what iso allows. It must be idempotent
	// and survive an agent restart (the core calls Isolate again on start if the
	// persisted state says the host is isolated).
	Isolate(ctx context.Context, iso Isolation) error
	// Release removes isolation. It must succeed even if isolation is not in place.
	Release(ctx context.Context) error
	// Isolated reports whether isolation rules are currently in place.
	Isolated() bool
}

// Row is one artifact result row. Keys follow the artifact's Columns in shared/api.
type Row = map[string]any

// Collector runs one built-in, read-only artifact and emits its rows.
type Collector func(ctx context.Context, params map[string]string, emit func(Row) error) error

// Service integrates with the OS service manager.
type Service interface {
	// Install registers the agent as a service that runs `<exe> run`, and starts it.
	Install(exe string) error
	// Uninstall stops and removes the service.
	Uninstall() error
	// Status returns a short human-readable state, e.g. "running".
	Status() (string, error)
	// RunAsService runs fn under the service manager when the process was started by it.
	// It returns handled=false when the process is running interactively.
	RunAsService(fn func(ctx context.Context) error) (handled bool, err error)
}

// Paths are the platform's default locations.
type Paths struct {
	ConfigFile string // local config / policy file
	DataDir    string
	// FIMDefaults and FileDefaults are used when the central config lists no paths.
	FIMDefaults  []string
	FileDefaults []string
}

// PathProtector is optionally implemented by a Platform whose file permissions are not
// expressed by Unix mode bits (Windows ACLs). The core calls ProtectPath on the data dir
// and the config file after creating them, so only the agent's account (SYSTEM /
// Administrators) can read them. Platforms without it rely on 0700/0600 modes.
type PathProtector interface {
	ProtectPath(path string) error
}

// Platform is the OS-specific part of the agent.
type Platform interface {
	Name() string // event.PlatformLinux, event.PlatformWindows, event.PlatformDarwin
	Paths() Paths
	HostInfo(ctx context.Context) api.HostInfo
	// Sensors returns the sensors to run for the given config. Sensors for disabled
	// kinds may be omitted.
	Sensors(cfg api.SensorsConfig, env Env) []Sensor
	Responder(env Env) Responder
	// Collectors maps artifact names (from api.Artifacts) to implementations.
	Collectors(env Env) map[string]Collector
	Service() Service
}
