// Package event defines the normalized telemetry record that every HomeXDR producer
// (endpoint agents, syslog decoders, integrations) emits and the server stores.
//
// Field names follow the Elastic Common Schema (ECS) where ECS has a home for the value.
// Producers fill only what they know; every nested object is optional. Values that have no
// ECS home go in Data, keyed by a dotted, producer-specific name.
package event

import "time"

// Event is one normalized telemetry record.
type Event struct {
	// ID is a time-ordered unique ID assigned by the producer (see NewID).
	ID        string    `json:"id"`
	Timestamp time.Time `json:"@timestamp"`

	Agent Agent `json:"agent"`
	Host  Host  `json:"host"`
	Event Meta  `json:"event"`

	Message string            `json:"message,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`

	Process *Process `json:"process,omitempty"`
	// Container is the container the event's process runs in, if any. It is unset for
	// processes on the host itself.
	Container   *Container     `json:"container,omitempty"`
	File        *File          `json:"file,omitempty"`
	DLL         *DLL           `json:"dll,omitempty"`
	Registry    *Registry      `json:"registry,omitempty"`
	Network     *Network       `json:"network,omitempty"`
	Source      *Endpoint      `json:"source,omitempty"`
	Destination *Endpoint      `json:"destination,omitempty"`
	DNS         *DNS           `json:"dns,omitempty"`
	HTTP        *HTTP          `json:"http,omitempty"`
	TLS         *TLS           `json:"tls,omitempty"`
	User        *User          `json:"user,omitempty"`
	Service     *Service       `json:"service,omitempty"`
	Rule        *Rule          `json:"rule,omitempty"`
	Threat      *Threat        `json:"threat,omitempty"`
	Observer    *Observer      `json:"observer,omitempty"`
	Log         *Log           `json:"log,omitempty"`
	Package     *Package       `json:"package,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
}

// Agent identifies the producer. The server overwrites ID with the identity from the
// agent's client certificate, so a producer cannot spoof another host.
type Agent struct {
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
	// Type is AgentTypeEndpoint, AgentTypeSyslog or AgentTypeIntegration.
	Type string `json:"type,omitempty"`
}

// Host describes the machine the event happened on. The server enriches it from the
// host registry, so agents only need to send Name.
type Host struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	OS       *OS      `json:"os,omitempty"`
	IP       []string `json:"ip,omitempty"`
	MAC      []string `json:"mac,omitempty"`
	Arch     string   `json:"architecture,omitempty"`
}

// OS describes an operating system.
type OS struct {
	// Platform is PlatformWindows, PlatformLinux or PlatformDarwin.
	Platform string `json:"platform"`
	Family   string `json:"family,omitempty"`  // debian, rhel, windows, macos, ...
	Name     string `json:"name,omitempty"`    // "Windows 11 Pro", "Ubuntu"
	Version  string `json:"version,omitempty"` // "10.0.26200", "24.04"
	Kernel   string `json:"kernel,omitempty"`
}

// Meta is the ECS "event" object: what kind of thing happened.
type Meta struct {
	Kind     string   `json:"kind"`               // KindEvent, KindAlert, KindState
	Category []string `json:"category,omitempty"` // Category* constants
	Type     []string `json:"type,omitempty"`     // Type* constants
	Action   string   `json:"action,omitempty"`   // producer verb: "exec", "connect", "logon-failed"
	Outcome  string   `json:"outcome,omitempty"`  // OutcomeSuccess, OutcomeFailure, OutcomeUnknown
	Module   string   `json:"module,omitempty"`   // producing sensor: Module* constants
	Dataset  string   `json:"dataset,omitempty"`  // "windows.security", "linux.auth", "suricata.eve"
	Provider string   `json:"provider,omitempty"` // "Microsoft-Windows-Security-Auditing"
	Code     string   `json:"code,omitempty"`     // source event ID, e.g. Windows "4624"
	// Severity is the source's own severity, normalized to 0 (none) .. 100 (critical).
	Severity int `json:"severity,omitempty"`
	// Original is the raw source record, kept for syslog-style inputs.
	Original string     `json:"original,omitempty"`
	Ingested *time.Time `json:"ingested,omitempty"` // set by the server
	Duration int64      `json:"duration,omitempty"` // nanoseconds
}

// Process describes a process. Parent uses the same shape; producers fill what they know.
type Process struct {
	// EntityID is stable for the life of the process and unique across hosts.
	// Compute it with ProcessEntityID.
	EntityID         string         `json:"entity_id,omitempty"`
	PID              int64          `json:"pid,omitempty"`
	Name             string         `json:"name,omitempty"`
	Executable       string         `json:"executable,omitempty"`
	CommandLine      string         `json:"command_line,omitempty"`
	Args             []string       `json:"args,omitempty"`
	WorkingDirectory string         `json:"working_directory,omitempty"`
	Start            *time.Time     `json:"start,omitempty"`
	End              *time.Time     `json:"end,omitempty"`
	ExitCode         *int64         `json:"exit_code,omitempty"`
	User             *User          `json:"user,omitempty"`
	Hash             *Hash          `json:"hash,omitempty"`
	CodeSignature    *CodeSignature `json:"code_signature,omitempty"`
	PE               *PE            `json:"pe,omitempty"`
	// IntegrityLevel is the Windows mandatory label: "low", "medium", "high", "system".
	IntegrityLevel string `json:"integrity_level,omitempty"`
	// Elevated is true for an elevated token (Windows) or effective UID 0 (Unix).
	Elevated  *bool    `json:"elevated,omitempty"`
	SessionID int64    `json:"session_id,omitempty"`
	TTY       string   `json:"tty,omitempty"`
	Parent    *Process `json:"parent,omitempty"`
}

// Container identifies a container (ECS container.*). ID is the runtime's full ID; Name
// has no leading slash. Image fields are empty when the runtime could not be asked.
type Container struct {
	ID      string          `json:"id,omitempty"`
	Name    string          `json:"name,omitempty"`
	Runtime string          `json:"runtime,omitempty"` // docker, containerd, cri-o, podman, lxc
	Image   *ContainerImage `json:"image,omitempty"`
}

// ContainerImage is the image a container was created from.
type ContainerImage struct {
	Name string `json:"name,omitempty"` // "binhex/arch-sonarr", "ghcr.io/org/app"
	Tag  string `json:"tag,omitempty"`  // "latest"
}

// Hash holds file digests as lowercase hex.
type Hash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// CodeSignature describes an Authenticode / codesign signature.
type CodeSignature struct {
	Exists      bool   `json:"exists"`
	Valid       *bool  `json:"valid,omitempty"`
	Trusted     *bool  `json:"trusted,omitempty"`
	SubjectName string `json:"subject_name,omitempty"`
	Status      string `json:"status,omitempty"`
}

// PE holds Windows version-resource metadata.
type PE struct {
	OriginalFileName string `json:"original_file_name,omitempty"`
	Company          string `json:"company,omitempty"`
	Product          string `json:"product,omitempty"`
	Description      string `json:"description,omitempty"`
	FileVersion      string `json:"file_version,omitempty"`
	Imphash          string `json:"imphash,omitempty"`
}

// File describes a file system object.
type File struct {
	Path      string `json:"path,omitempty"`
	Name      string `json:"name,omitempty"`
	Directory string `json:"directory,omitempty"`
	Extension string `json:"extension,omitempty"` // without the dot, lowercase
	// OldPath is the previous path for renames and moves (not in ECS).
	OldPath       string         `json:"old_path,omitempty"`
	TargetPath    string         `json:"target_path,omitempty"` // symlink target
	Type          string         `json:"type,omitempty"`        // file, dir, symlink
	Size          int64          `json:"size,omitempty"`
	Mode          string         `json:"mode,omitempty"` // octal string on Unix, e.g. "0755"
	Owner         string         `json:"owner,omitempty"`
	Group         string         `json:"group,omitempty"`
	MTime         *time.Time     `json:"mtime,omitempty"`
	CTime         *time.Time     `json:"ctime,omitempty"`
	Hash          *Hash          `json:"hash,omitempty"`
	CodeSignature *CodeSignature `json:"code_signature,omitempty"`
	PE            *PE            `json:"pe,omitempty"`
}

// DLL describes a loaded library (Windows DLL, Linux shared object).
type DLL struct {
	Path          string         `json:"path,omitempty"`
	Name          string         `json:"name,omitempty"`
	Hash          *Hash          `json:"hash,omitempty"`
	CodeSignature *CodeSignature `json:"code_signature,omitempty"`
	PE            *PE            `json:"pe,omitempty"`
}

// Registry describes a Windows registry operation.
type Registry struct {
	Hive  string        `json:"hive,omitempty"`  // HKLM, HKU, ...
	Key   string        `json:"key,omitempty"`   // key path without hive
	Path  string        `json:"path,omitempty"`  // full path: hive\key\value
	Value string        `json:"value,omitempty"` // value name
	Data  *RegistryData `json:"data,omitempty"`
}

// RegistryData is the value written.
type RegistryData struct {
	Type    string   `json:"type,omitempty"` // REG_SZ, REG_DWORD, ...
	Strings []string `json:"strings,omitempty"`
}

// Network describes a connection or flow.
type Network struct {
	Transport   string `json:"transport,omitempty"`    // tcp, udp, icmp, ipv6-icmp
	Type        string `json:"type,omitempty"`         // ipv4, ipv6
	Protocol    string `json:"protocol,omitempty"`     // application protocol: dns, http, tls, ssh
	Direction   string `json:"direction,omitempty"`    // Direction* constants
	CommunityID string `json:"community_id,omitempty"` // see package communityid
	Bytes       int64  `json:"bytes,omitempty"`
	Packets     int64  `json:"packets,omitempty"`
}

// Endpoint is one side of a connection (ECS source / destination).
type Endpoint struct {
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`
	Domain  string `json:"domain,omitempty"`
	MAC     string `json:"mac,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Packets int64  `json:"packets,omitempty"`
}

// DNS describes a DNS query and, when known, its answers.
type DNS struct {
	Type         string      `json:"type,omitempty"` // query, answer
	Question     DNSQuestion `json:"question"`
	ResponseCode string      `json:"response_code,omitempty"` // NOERROR, NXDOMAIN, ...
	Answers      []DNSAnswer `json:"answers,omitempty"`
	ResolvedIP   []string    `json:"resolved_ip,omitempty"`
}

// DNSQuestion is the queried name.
type DNSQuestion struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"` // A, AAAA, TXT, ...
}

// DNSAnswer is one resource record in a response.
type DNSAnswer struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Data string `json:"data,omitempty"`
	TTL  int    `json:"ttl,omitempty"`
}

// HTTP describes an HTTP transaction (simplified from ECS http/url/user_agent).
type HTTP struct {
	Method     string `json:"method,omitempty"`
	URL        string `json:"url,omitempty"`
	Host       string `json:"host,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
}

// TLS describes a TLS handshake.
type TLS struct {
	ServerName string `json:"server_name,omitempty"` // SNI
	Version    string `json:"version,omitempty"`
	JA3        string `json:"ja3,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
}

// User identifies an account. Target is the account acted upon (logon target,
// created user, ...).
type User struct {
	ID     string `json:"id,omitempty"` // SID on Windows, UID on Unix
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	Target *User  `json:"target,omitempty"`
}

// Service describes an OS service (Windows service, systemd unit, launchd job).
type Service struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type,omitempty"`
	StartType   string `json:"start_type,omitempty"` // auto, manual, disabled, boot, system
	Path        string `json:"path,omitempty"`       // binary path / ExecStart
	Account     string `json:"account,omitempty"`
	State       string `json:"state,omitempty"`
}

// Rule identifies the detection rule that produced an IDS event or alert.
type Rule struct {
	ID          string `json:"id,omitempty"` // Suricata sid, Sigma rule id
	Name        string `json:"name,omitempty"`
	Category    string `json:"category,omitempty"`
	Ruleset     string `json:"ruleset,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// Threat holds MITRE ATT&CK mappings.
type Threat struct {
	Framework  string      `json:"framework,omitempty"` // "MITRE ATT&CK"
	Tactics    []MitreItem `json:"tactics,omitempty"`
	Techniques []MitreItem `json:"techniques,omitempty"`
}

// MitreItem is one tactic or technique, e.g. {ID: "T1059.001", Name: "PowerShell"}.
type MitreItem struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Observer is the device that saw a network event (firewall, IDS).
type Observer struct {
	Name     string   `json:"name,omitempty"`
	Type     string   `json:"type,omitempty"` // firewall, ids, router
	Vendor   string   `json:"vendor,omitempty"`
	Product  string   `json:"product,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	IP       []string `json:"ip,omitempty"`
}

// Log describes where a log-derived event came from.
type Log struct {
	Level    string `json:"level,omitempty"`
	Logger   string `json:"logger,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	Facility string `json:"facility,omitempty"` // syslog facility name
	AppName  string `json:"app_name,omitempty"` // syslog app-name / tag
}

// Package describes installed software.
type Package struct {
	Name         string     `json:"name,omitempty"`
	Version      string     `json:"version,omitempty"`
	Vendor       string     `json:"vendor,omitempty"`
	Architecture string     `json:"architecture,omitempty"`
	InstallPath  string     `json:"install_path,omitempty"`
	Installed    *time.Time `json:"installed,omitempty"`
	Type         string     `json:"type,omitempty"` // deb, rpm, msi, winget, brew
}
