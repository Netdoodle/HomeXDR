package api

// ArtifactDef describes a built-in collector that agents implement. The server serves the
// catalog to the UI; agents reject names they do not implement for their platform.
type ArtifactDef struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Platforms   []string      `json:"platforms"` // event.Platform* values
	Params      []ArtifactArg `json:"params,omitempty"`
	// Columns documents the keys each result row has. Rows may include extra keys.
	Columns []string `json:"columns"`
}

// ArtifactArg is a parameter of an artifact.
type ArtifactArg struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string, int, bool
	Default     string `json:"default,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description"`
}

var allPlatforms = []string{"windows", "linux", "darwin"}

// Artifacts is the built-in collector catalog.
var Artifacts = []ArtifactDef{
	{
		Name:        "system.info",
		Description: "Host details: OS, kernel, uptime, CPU, memory, domain membership.",
		Platforms:   allPlatforms,
		Columns:     []string{"hostname", "os_name", "os_version", "kernel", "arch", "boot_time", "cpus", "memory_bytes", "domain"},
	},
	{
		Name:        "process.list",
		Description: "Running processes with parent, user, command line and executable hash.",
		Platforms:   allPlatforms,
		Params: []ArtifactArg{
			{Name: "hash", Type: "bool", Default: "true", Description: "Compute SHA-256 of each executable."},
		},
		Columns: []string{"pid", "ppid", "entity_id", "name", "executable", "command_line", "user", "start", "sha256"},
	},
	{
		Name:        "network.connections",
		Description: "Open sockets (listening and established) with owning process.",
		Platforms:   allPlatforms,
		Columns:     []string{"transport", "state", "local_ip", "local_port", "remote_ip", "remote_port", "pid", "process_name", "community_id"},
	},
	{
		Name:        "users.list",
		Description: "Local user accounts and their group memberships.",
		Platforms:   allPlatforms,
		Columns:     []string{"name", "id", "groups", "shell", "home", "disabled", "admin", "last_logon"},
	},
	{
		Name:        "users.sessions",
		Description: "Currently logged-on users and sessions.",
		Platforms:   allPlatforms,
		Columns:     []string{"user", "session", "type", "source_ip", "started"},
	},
	{
		Name: "persistence.autoruns",
		Description: "Autostart locations: Run/RunOnce keys, services, scheduled tasks and startup " +
			"folders on Windows; cron, systemd units, rc.local, shell profiles, ld.so.preload and " +
			"authorized_keys on Linux; LaunchAgents/LaunchDaemons, login items and background tasks on macOS.",
		Platforms: allPlatforms,
		Columns:   []string{"type", "location", "name", "command", "user", "enabled", "sha256", "signed"},
	},
	{
		Name:        "services.list",
		Description: "Installed services with start type, state and binary path.",
		Platforms:   allPlatforms,
		Columns:     []string{"name", "display_name", "state", "start_type", "path", "account"},
	},
	{
		Name:        "software.list",
		Description: "Installed software packages.",
		Platforms:   allPlatforms,
		Columns:     []string{"name", "version", "vendor", "type", "install_date"},
	},
	{
		Name:        "file.find",
		Description: "Find files under a directory by glob, optionally hashing them.",
		Platforms:   allPlatforms,
		Params: []ArtifactArg{
			{Name: "root", Type: "string", Required: true, Description: "Directory to search."},
			{Name: "glob", Type: "string", Default: "*", Description: "File name pattern, e.g. *.exe"},
			{Name: "max_depth", Type: "int", Default: "5", Description: "Maximum directory depth."},
			{Name: "hash", Type: "bool", Default: "false", Description: "Compute SHA-256."},
			{Name: "max_results", Type: "int", Default: "1000", Description: "Stop after this many matches."},
		},
		Columns: []string{"path", "size", "mtime", "mode", "owner", "sha256"},
	},
	{
		Name:        "kernel.modules",
		Description: "Loaded kernel modules (Linux) or drivers (Windows).",
		Platforms:   []string{"windows", "linux"},
		Columns:     []string{"name", "path", "size", "signed", "state"},
	},
}

// FindArtifact returns the catalog entry with the given name.
func FindArtifact(name string) (ArtifactDef, bool) {
	for _, a := range Artifacts {
		if a.Name == name {
			return a, true
		}
	}
	return ArtifactDef{}, false
}
