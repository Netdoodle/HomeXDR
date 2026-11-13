package api

// Defender hardening: HomeXDR turns on a fixed set of Microsoft Defender protections on
// Windows hosts (Attack Surface Reduction rules, Network Protection, Controlled Folder
// Access in audit mode) in audit or enforce mode, and puts back what was there before
// when it is turned off. The rule list is built into the agent; the command only carries
// the mode, so it cannot be used to change other Defender settings.

// CmdDefenderHarden applies HomeXDR's Defender hardening profile (DefenderHardenParams).
const CmdDefenderHarden = "defender.harden"

func init() {
	// Kept out of the literal list in agent.go so the default policy grows by addition.
	DefaultAllowedActions = append(DefaultAllowedActions, CmdDefenderHarden)
}

// Defender hardening modes (DefenderHardenParams.Mode).
const (
	HardeningOff     = "off"     // put back the settings from before HomeXDR changed them
	HardeningAudit   = "audit"   // every protection logs what it would block
	HardeningEnforce = "enforce" // ASR rules block and Network Protection blocks; see docs/antivirus.md
)

// HardeningProfile is the revision of the agent's built-in rule list. The server puts it
// in the version, so a new list is applied to hosts once their agents carry it.
const HardeningProfile = "1"

// DefenderHardenParams for CmdDefenderHarden.
type DefenderHardenParams struct {
	Mode string `json:"mode"`
	// Version identifies the mode and profile; the agent reports it back once applied.
	Version string `json:"version"`
}

// DefenderHardenResult is the output of CmdDefenderHarden.
type DefenderHardenResult struct {
	Mode    string `json:"mode"`
	Version string `json:"version"`
	// Profile is the agent's rule list revision (HardeningProfile in the agent's build).
	Profile string `json:"profile,omitempty"`
	Message string `json:"message"`
	// Settings lists each managed setting and the value Defender reports after applying.
	Settings []HardeningSetting `json:"settings,omitempty"`
	// Failures are settings that did not take effect (Group Policy, MDM, Tamper
	// Protection, Defender not the active antivirus, ...).
	Failures []string `json:"failures,omitempty"`
}

// HardeningSetting is one setting as Defender reports it after the command.
type HardeningSetting struct {
	Name   string `json:"name"`
	Wanted string `json:"wanted"`
	Actual string `json:"actual"`
}
