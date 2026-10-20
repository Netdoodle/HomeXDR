// Package config loads and saves the agent's local config file. The file is the local
// policy: it names the server and its CA pin, lists the response actions the agent will
// run (allowed_actions), and decides whether the agent updates itself and which release
// key updates must be signed with. Central config from the server can never change it.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/shared/api"
)

// Local is the on-disk config file (JSON, 0600).
type Local struct {
	ServerURL string `json:"server_url"`
	CAPin     string `json:"ca_pin"`
	// AllowedActions lists the command types this agent executes. A missing key means
	// api.DefaultAllowedActions; an empty list allows nothing.
	AllowedActions []string `json:"allowed_actions"`
	// IsolationAllow lists extra IPs or CIDRs that stay reachable while isolated.
	IsolationAllow []string `json:"isolation_allow,omitempty"`
	LogLevel       string   `json:"log_level,omitempty"` // debug, info, warn, error
	DataDir        string   `json:"data_dir,omitempty"`  // default: the platform's data dir
	// AutoUpdate lets the agent install new versions the server offers. They must be
	// signed with UpdateKey, a release key the server does not hold.
	AutoUpdate bool   `json:"auto_update,omitempty"`
	UpdateKey  string `json:"update_key,omitempty"` // "ed25519:<base64>"
}

// ErrNotFound is returned by Load when the file does not exist.
var ErrNotFound = errors.New("config file not found")

// Default returns a config with the default policy.
func Default() Local {
	return Local{AllowedActions: slices.Clone(api.DefaultAllowedActions), LogLevel: "info"}
}

// Load reads and validates the config file.
func Load(path string) (Local, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Local{}, fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	if err != nil {
		return Local{}, err
	}
	return Parse(b)
}

// Parse decodes and validates config JSON.
func Parse(b []byte) (Local, error) {
	// Decode allowed_actions through a pointer so a missing key (default policy) can be
	// told apart from an explicit empty list (allow nothing).
	var aux struct {
		Local
		AllowedActions *[]string `json:"allowed_actions"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&aux); err != nil {
		return Local{}, fmt.Errorf("config: %w", err)
	}
	c := aux.Local
	if aux.AllowedActions == nil {
		c.AllowedActions = slices.Clone(api.DefaultAllowedActions)
	} else {
		c.AllowedActions = *aux.AllowedActions
		if c.AllowedActions == nil {
			c.AllowedActions = []string{}
		}
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return c, c.Validate()
}

// Validate checks the values.
func (c Local) Validate() error {
	for _, a := range c.AllowedActions {
		if !slices.Contains(api.DefaultAllowedActions, a) {
			return fmt.Errorf("config: allowed_actions: unknown action %q (known: %s)",
				a, strings.Join(api.DefaultAllowedActions, ", "))
		}
	}
	if _, err := c.IsolationPrefixes(); err != nil {
		return err
	}
	switch strings.ToLower(c.LogLevel) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("config: log_level must be debug, info, warn or error")
	}
	if c.CAPin != "" && !ValidPin(c.CAPin) {
		return fmt.Errorf("config: ca_pin must be sha256:<64 hex chars>")
	}
	if c.UpdateKey != "" {
		if _, err := api.ParseUpdateKey(c.UpdateKey); err != nil {
			return fmt.Errorf("config: update_key: %w", err)
		}
	}
	if c.AutoUpdate && c.UpdateKey == "" {
		return fmt.Errorf("config: auto_update needs update_key (the release key updates must be signed with)")
	}
	return nil
}

// Allowed reports whether the local policy permits a command type.
func (c Local) Allowed(typ string) bool { return slices.Contains(c.AllowedActions, typ) }

// IsolationPrefixes parses IsolationAllow.
func (c Local) IsolationPrefixes() ([]netip.Prefix, error) {
	return ParsePrefixes(c.IsolationAllow)
}

// ParsePrefixes parses IPs and CIDRs; a bare IP becomes a host prefix.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// ValidPin reports whether s looks like "sha256:<64 hex>".
func ValidPin(s string) bool {
	h, ok := strings.CutPrefix(strings.ToLower(s), "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, r := range h {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// Save writes the config file atomically with mode 0600, creating its directory.
func Save(path string, c Local) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.AllowedActions == nil {
		c.AllowedActions = []string{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteJSONAtomic(path, c, 0o600)
}
