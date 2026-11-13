package api

// Host firewall control: addresses blocked in each host's own firewall (Windows Firewall
// rules in the "HomeXDR" group, the nftables table inet homexdr_block on Linux, a pf
// anchor on macOS). The server sends the host's complete HomeXDR-owned rule set in one
// signed command; validation lives in shared/hostfw. See docs/firewall.md.

// CmdFirewall replaces the host's HomeXDR-owned firewall block rules with FirewallParams
// (an empty list removes them all). Like every command it is a fixed, typed operation:
// the agent only ever turns validated addresses into block rules.
const CmdFirewall = "firewall.apply"

// Firewall rule directions (FirewallRule.Direction). "" means both.
const (
	FirewallBoth = "both" // inbound from and outbound to the address
	FirewallIn   = "in"   // only inbound from the address
	FirewallOut  = "out"  // only outbound to the address
)

// Limits shared by the server and the agent.
const (
	// FirewallMaxRules caps the addresses in one host's rule set.
	FirewallMaxRules = 1000
	// FirewallMinPrefixV4 and FirewallMinPrefixV6 are the broadest prefixes accepted:
	// a /8 holds 16 million IPv4 addresses; a /32 is a large ISP's whole IPv6 allocation.
	FirewallMinPrefixV4 = 8
	FirewallMinPrefixV6 = 32
)

// FirewallWindowsGroup is the Windows Firewall rule group that holds every HomeXDR rule.
const FirewallWindowsGroup = "HomeXDR"

// FirewallParams for CmdFirewall.
type FirewallParams struct {
	// Version identifies the rule set ([A-Za-z0-9._-], at most 64 characters); the agent
	// reports it back once applied.
	Version string         `json:"version"`
	Rules   []FirewallRule `json:"rules"`
}

// FirewallRule blocks one address or network.
type FirewallRule struct {
	CIDR      string `json:"cidr"`                // an IP address or CIDR, IPv4 or IPv6
	Direction string `json:"direction,omitempty"` // Firewall* direction; "" = both
}

// FirewallResult is the output of CmdFirewall.
type FirewallResult struct {
	Version string `json:"version"`
	Rules   int    `json:"rules"`             // addresses blocked after merging overlaps
	Backend string `json:"backend,omitempty"` // windows-firewall, nftables, pf
	Message string `json:"message"`
}
