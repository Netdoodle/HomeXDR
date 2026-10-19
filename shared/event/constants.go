package event

// Agent types.
const (
	AgentTypeEndpoint    = "endpoint"
	AgentTypeSyslog      = "syslog"
	AgentTypeIntegration = "integration"
)

// Platforms (host.os.platform).
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformDarwin  = "darwin"
)

// Event kinds (event.kind).
const (
	KindEvent = "event" // something happened
	KindAlert = "alert" // a detection fired (Suricata alerts arrive as alerts)
	KindState = "state" // a snapshot: inventory, FIM baseline, artifact row
)

// Event categories (event.category), ECS values.
const (
	CategoryProcess            = "process"
	CategoryFile               = "file"
	CategoryNetwork            = "network"
	CategoryRegistry           = "registry"
	CategoryLibrary            = "library"
	CategoryAuthentication     = "authentication"
	CategoryIAM                = "iam"
	CategorySession            = "session"
	CategoryConfiguration      = "configuration"
	CategoryDriver             = "driver"
	CategoryPackage            = "package"
	CategoryHost               = "host"
	CategoryIntrusionDetection = "intrusion_detection"
	CategoryMalware            = "malware"
	CategoryWeb                = "web"
)

// Event types (event.type), ECS values.
const (
	TypeStart        = "start"
	TypeEnd          = "end"
	TypeCreation     = "creation"
	TypeDeletion     = "deletion"
	TypeChange       = "change"
	TypeAccess       = "access"
	TypeConnection   = "connection"
	TypeProtocol     = "protocol"
	TypeInfo         = "info"
	TypeAllowed      = "allowed"
	TypeDenied       = "denied"
	TypeUser         = "user"
	TypeGroup        = "group"
	TypeAdmin        = "admin"
	TypeInstallation = "installation"
	TypeIndicator    = "indicator"
)

// Outcomes (event.outcome).
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeUnknown = "unknown"
)

// Network directions (network.direction).
const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"
	DirectionInternal = "internal"
	DirectionExternal = "external"
	DirectionUnknown  = "unknown"
)

// Modules (event.module): the sensor or decoder that produced the event.
const (
	ModuleETW       = "etw"       // Windows Event Tracing
	ModuleEventLog  = "eventlog"  // Windows Event Log channels (Security, Sysmon, PowerShell)
	ModuleEBPF      = "ebpf"      // Linux eBPF sensor
	ModuleProcConn  = "procconn"  // Linux netlink proc connector fallback
	ModuleProcfs    = "procfs"    // Linux /proc polling fallback
	ModuleFanotify  = "fanotify"  // Linux fanotify file sensor
	ModuleInotify   = "inotify"   // Linux inotify file sensor fallback
	ModuleAuthLog   = "authlog"   // Linux auth log / journald
	ModuleFIM       = "fim"       // file integrity monitoring
	ModuleInventory = "inventory" // host inventory snapshots
	ModuleLogfile   = "logfile"   // generic log file tailing
	ModuleArtifact  = "artifact"  // artifact collection rows
	ModuleResponse  = "response"  // response action audit events
	ModuleSyslog    = "syslog"    // generic syslog
	ModuleOPNsense  = "opnsense"  // OPNsense filterlog
	ModuleSuricata  = "suricata"  // Suricata EVE JSON
)
