// Package api defines the wire protocol between HomeXDR agents and the server.
// See docs/protocol.md for the full description; this file is the source of truth for
// the JSON shapes.
package api

import (
	"encoding/json"
	"time"

	"github.com/Doodlebug12/homexdr/shared/event"
)

// ProtocolVersion is sent by agents in the X-HomeXDR-Protocol header.
const ProtocolVersion = "1"

// Agent API paths, served on the agent listener (default :8443, TLS).
// Everything except PathEnroll requires a client certificate issued at enrollment.
const (
	PathEnroll    = "/v1/enroll"
	PathHeartbeat = "/v1/heartbeat"
	PathEvents    = "/v1/events"
	// PathCommands is long-polled: GET /v1/commands?wait=<seconds> returns 200 with
	// []SignedCommand when commands are pending, or 204 after the wait expires.
	PathCommands = "/v1/commands"
	// Formatted with the command ID.
	PathCommandResultFmt = "/v1/commands/%s/result"
	PathCommandRowsFmt   = "/v1/commands/%s/rows"   // gzip NDJSON of artifact rows (map[string]any)
	PathCommandUploadFmt = "/v1/commands/%s/upload" // raw file body; ?name=<original path>
)

// Header names.
const (
	HeaderProtocol = "X-HomeXDR-Protocol"
	HeaderAgentID  = "X-HomeXDR-Agent" // informational; identity comes from the client cert
)

// Limits.
const (
	MaxEventBatchBytes = 8 << 20 // uncompressed NDJSON per POST /v1/events
	MaxRowsBatchBytes  = 8 << 20
	DefaultLongPoll    = 30 * time.Second
)

// EnrollRequest is POSTed to PathEnroll. The agent generates an ECDSA P-256 key, keeps
// the private key on disk, and sends a CSR. The server ignores the CSR subject and issues
// a certificate whose CommonName is the new agent ID.
//
// The server's TLS handshake presents [server cert, CA cert]. Before enrolling, the agent
// checks that SHA-256 of the CA certificate's DER equals the --ca-pin value and that the
// server cert chains to it with the ServerAuth key usage. Hostname matching is not
// required: the private, pinned CA only ever issues one server certificate.
type EnrollRequest struct {
	Token        string   `json:"token"`
	CSRPEM       string   `json:"csr_pem"`
	AgentVersion string   `json:"agent_version"`
	Host         HostInfo `json:"host"`
	// Labels are added to the token's labels.
	Labels []string `json:"labels,omitempty"`
}

// EnrollResponse is returned on successful enrollment.
type EnrollResponse struct {
	AgentID string `json:"agent_id"`
	CertPEM string `json:"cert_pem"` // client certificate, CN = AgentID
	CAPEM   string `json:"ca_pem"`   // CA that signs both server and client certs
	// CommandKey is the server's Ed25519 public key (base64 std encoding). The agent pins
	// it and rejects any command whose signature does not verify.
	CommandKey string      `json:"command_key"`
	Config     AgentConfig `json:"config"`
}

// HostInfo describes the machine an agent runs on.
type HostInfo struct {
	Hostname    string     `json:"hostname"`
	FQDN        string     `json:"fqdn,omitempty"`
	MachineID   string     `json:"machine_id,omitempty"` // /etc/machine-id, MachineGuid, IOPlatformUUID
	OS          event.OS   `json:"os"`
	Arch        string     `json:"arch"` // amd64, arm64
	IPs         []string   `json:"ips,omitempty"`
	MACs        []string   `json:"macs,omitempty"`
	BootTime    *time.Time `json:"boot_time,omitempty"`
	Timezone    string     `json:"timezone,omitempty"`
	CPUs        int        `json:"cpus,omitempty"`
	MemoryBytes uint64     `json:"memory_bytes,omitempty"`
	Container   bool       `json:"container,omitempty"` // agent runs inside a container
}

// Heartbeat is POSTed to PathHeartbeat every AgentConfig.HeartbeatIntervalSec.
type Heartbeat struct {
	Host   HostInfo    `json:"host"`
	Status AgentStatus `json:"status"`
}

// AgentStatus reports agent health.
type AgentStatus struct {
	Version       string         `json:"version"`
	StartedAt     time.Time      `json:"started_at"`
	ConfigVersion int64          `json:"config_version"`
	QueueEvents   int64          `json:"queue_events"` // events spooled on disk, not yet sent
	QueueBytes    int64          `json:"queue_bytes"`
	EventsSent    uint64         `json:"events_sent"`
	EventsDropped uint64         `json:"events_dropped"`
	Isolated      bool           `json:"isolated"`
	Sensors       []SensorStatus `json:"sensors,omitempty"`
	// AllowedActions is the agent's local policy (command types it will execute).
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

// Sensor states.
const (
	SensorRunning  = "running"
	SensorDegraded = "degraded" // running with reduced fidelity (e.g. fallback mode)
	SensorFailed   = "failed"
	SensorDisabled = "disabled"
)

// SensorStatus reports one sensor.
type SensorStatus struct {
	Name   string `json:"name"`  // "process", "network", "file", ...
	Impl   string `json:"impl"`  // event.Module* value of the active implementation
	State  string `json:"state"` // Sensor* constant
	Error  string `json:"error,omitempty"`
	Events uint64 `json:"events"`
}

// HeartbeatResponse is the server's reply to a heartbeat.
type HeartbeatResponse struct {
	ServerTime time.Time `json:"server_time"`
	// Config is set when the server has a config newer than Status.ConfigVersion.
	Config          *AgentConfig `json:"config,omitempty"`
	CommandsPending bool         `json:"commands_pending"`
}

// EventsResponse is the reply to POST /v1/events (body: gzip NDJSON of event.Event,
// Content-Encoding: gzip, Content-Type: application/x-ndjson).
type EventsResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

// AgentConfig is centrally managed by the server (per agent, falling back to the default
// config). It never controls which response actions run; that is local policy.
type AgentConfig struct {
	Version              int64         `json:"version"`
	HeartbeatIntervalSec int           `json:"heartbeat_interval_sec"`
	InventoryIntervalSec int           `json:"inventory_interval_sec"`
	Batch                BatchConfig   `json:"batch"`
	Sensors              SensorsConfig `json:"sensors"`
	FIM                  FIMConfig     `json:"fim"`
	Logs                 []LogSource   `json:"logs,omitempty"`
	Filters              []EventFilter `json:"filters,omitempty"`
	SpoolMaxBytes        int64         `json:"spool_max_bytes"`
}

// BatchConfig controls event batching.
type BatchConfig struct {
	MaxEvents       int `json:"max_events"`
	FlushIntervalMs int `json:"flush_interval_ms"`
}

// SensorsConfig toggles telemetry sensors.
type SensorsConfig struct {
	Process  ProcessSensorConfig `json:"process"`
	Network  ToggleConfig        `json:"network"`
	File     FileSensorConfig    `json:"file"`
	Registry ToggleConfig        `json:"registry"` // Windows only
	DNS      ToggleConfig        `json:"dns"`
	Library  ToggleConfig        `json:"library"`  // image/DLL loads, noisy
	Auth     ToggleConfig        `json:"auth"`     // logons, sudo, ssh
	EventLog EventLogConfig      `json:"eventlog"` // Windows only
}

// ToggleConfig is a sensor with only an on/off switch.
type ToggleConfig struct {
	Enabled bool `json:"enabled"`
}

// ProcessSensorConfig configures process telemetry.
type ProcessSensorConfig struct {
	Enabled         bool `json:"enabled"`
	HashExecutables bool `json:"hash_executables"`
}

// FileSensorConfig configures real-time file telemetry.
type FileSensorConfig struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths,omitempty"`   // empty = platform defaults
	Exclude []string `json:"exclude,omitempty"` // glob patterns
}

// EventLogConfig lists Windows Event Log channels to subscribe to.
type EventLogConfig struct {
	Enabled  bool     `json:"enabled"`
	Channels []string `json:"channels,omitempty"`
}

// FIMConfig configures periodic file integrity monitoring.
type FIMConfig struct {
	Enabled     bool     `json:"enabled"`
	Paths       []string `json:"paths,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
	IntervalSec int      `json:"interval_sec"`
	MaxFileSize int64    `json:"max_file_size"` // files larger than this are not hashed
}

// LogSource is a log file the agent tails and forwards.
type LogSource struct {
	Path    string `json:"path"`              // may contain globs
	Format  string `json:"format,omitempty"`  // raw (default), json, syslog
	Dataset string `json:"dataset,omitempty"` // event.dataset to stamp
}

// EventFilter drops matching events on the agent before they are spooled.
type EventFilter struct {
	Category string `json:"category,omitempty"` // only events with this category; "" = any
	Field    string `json:"field"`              // dotted ECS path, e.g. "process.executable"
	Op       string `json:"op"`                 // equals, prefix, suffix, contains (case-insensitive)
	Value    string `json:"value"`
}

// DefaultAgentConfig is the configuration a freshly enrolled agent receives.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		Version:              1,
		HeartbeatIntervalSec: 30,
		InventoryIntervalSec: 6 * 3600,
		Batch:                BatchConfig{MaxEvents: 500, FlushIntervalMs: 2000},
		Sensors: SensorsConfig{
			Process:  ProcessSensorConfig{Enabled: true, HashExecutables: true},
			Network:  ToggleConfig{Enabled: true},
			File:     FileSensorConfig{Enabled: true},
			Registry: ToggleConfig{Enabled: true},
			DNS:      ToggleConfig{Enabled: true},
			Library:  ToggleConfig{Enabled: false},
			Auth:     ToggleConfig{Enabled: true},
			EventLog: EventLogConfig{Enabled: true, Channels: []string{
				"Security",
				"System",
				"Microsoft-Windows-Sysmon/Operational",
				"Microsoft-Windows-PowerShell/Operational",
				"Microsoft-Windows-Windows Defender/Operational",
			}},
		},
		FIM: FIMConfig{
			Enabled:     true,
			IntervalSec: 3600,
			MaxFileSize: 64 << 20,
		},
		SpoolMaxBytes: 512 << 20,
	}
}

// Command types. Agents advertise the subset their local policy allows in
// AgentStatus.AllowedActions; the server must not queue others.
const (
	CmdProcessKill    = "process.kill"
	CmdHostIsolate    = "host.isolate"
	CmdHostRelease    = "host.release"
	CmdFileQuarantine = "file.quarantine"
	CmdFileRestore    = "file.restore"
	CmdFileGet        = "file.get"
	CmdFileHash       = "file.hash"
	CmdArtifact       = "artifact.collect"
)

// There is deliberately no "run arbitrary command" type. Every action is a fixed,
// typed operation, so the server (or anyone who compromises it) cannot turn the agent
// into a remote shell.

// DefaultAllowedActions is the local policy used when the agent config does not set one.
var DefaultAllowedActions = []string{
	CmdProcessKill, CmdHostIsolate, CmdHostRelease, CmdFileQuarantine,
	CmdFileRestore, CmdFileGet, CmdFileHash, CmdArtifact,
}

// SignedCommand is what the server hands an agent. Payload is the exact JSON encoding of
// a Command; Signature is Ed25519(Payload) with the server's command key. Agents verify
// before decoding, then check AgentID, ExpiresAt and that ID was not seen before.
type SignedCommand struct {
	Payload   []byte `json:"payload"`   // base64 in JSON
	Signature []byte `json:"signature"` // base64 in JSON
}

// Command is a response action or collection request.
type Command struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agent_id"`
	Type      string          `json:"type"` // Cmd* constant
	Params    json.RawMessage `json:"params,omitempty"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	IssuedBy  string          `json:"issued_by"` // username, or "rule:<id>" for automated response
	HuntID    string          `json:"hunt_id,omitempty"`
}

// Command statuses.
const (
	StatusQueued    = "queued"    // server-side only: waiting for the agent to pick it up
	StatusDelivered = "delivered" // server-side only: handed to the agent
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusRejected  = "rejected" // signature, expiry, policy or validation failure
	StatusExpired   = "expired"  // server-side only: never delivered before ExpiresAt
)

// CommandResult is POSTed to PathCommandResultFmt. An agent may post StatusRunning first
// and a final status later.
type CommandResult struct {
	CommandID  string          `json:"command_id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	Output     json.RawMessage `json:"output,omitempty"` // per-type result struct below
	RowCount   int             `json:"row_count,omitempty"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

// KillParams for CmdProcessKill. If EntityID is set the agent must confirm the PID still
// belongs to that entity before killing, so a recycled PID is never hit.
type KillParams struct {
	PID      int64  `json:"pid"`
	EntityID string `json:"entity_id,omitempty"`
	Tree     bool   `json:"tree,omitempty"` // also kill descendants
}

// KillResult lists the PIDs that were terminated.
type KillResult struct {
	Killed []int64 `json:"killed"`
}

// IsolateParams for CmdHostIsolate. The agent always keeps its server connection, DHCP
// and DNS to the configured resolvers working; Allow adds more IPs or CIDRs.
type IsolateParams struct {
	Allow []string `json:"allow,omitempty"`
}

// QuarantineParams for CmdFileQuarantine.
type QuarantineParams struct {
	Path string `json:"path"`
}

// QuarantineResult describes a quarantined file.
type QuarantineResult struct {
	ID           string `json:"id"`
	OriginalPath string `json:"original_path"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

// RestoreParams for CmdFileRestore. The result output is the restored file's
// QuarantineResult.
type RestoreParams struct {
	ID string `json:"id"`
}

// FileGetParams for CmdFileGet. The agent uploads the file to PathCommandUploadFmt.
type FileGetParams struct {
	Path     string `json:"path"`
	MaxBytes int64  `json:"max_bytes,omitempty"` // default 100 MiB
}

// FileHashParams for CmdFileHash.
type FileHashParams struct {
	Path string `json:"path"`
}

// FileHashResult is the output of CmdFileHash (and the metadata of CmdFileGet).
type FileHashResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// ArtifactParams for CmdArtifact. Rows are streamed to PathCommandRowsFmt.
type ArtifactParams struct {
	Name   string            `json:"name"` // a name from Artifacts
	Params map[string]string `json:"params,omitempty"`
}
