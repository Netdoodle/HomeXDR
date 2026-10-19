// Package state persists the agent's runtime state in the data dir (state.json): the
// current central config, whether the host is isolated, and the IDs of recently seen
// commands for replay protection.
package state

import (
	"errors"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/fsutil"
	"github.com/Doodlebug12/homexdr/shared/api"
)

// FileName is the state file inside the data dir.
const FileName = "state.json"

// MaxSeen is how many command IDs are remembered for replay protection.
const MaxSeen = 1000

// Data is the persisted state.
type Data struct {
	Config   api.AgentConfig `json:"config"`
	Isolated bool            `json:"isolated"`
	// IsolationAllow is the allow list of the active isolation (command params plus local
	// isolation_allow), re-applied on start.
	IsolationAllow []string `json:"isolation_allow,omitempty"`
	// ServerIPs are the server addresses resolved when isolation was applied, used if
	// the server name cannot be resolved again on restart.
	ServerIPs     []string  `json:"server_ips,omitempty"`
	SeenCommands  []string  `json:"seen_commands,omitempty"`
	LastInventory time.Time `json:"last_inventory,omitzero"`
}

// Store is the state file with a mutex. Every mutation is written to disk before it
// returns.
type Store struct {
	mu   sync.Mutex
	path string
	d    Data
	seen map[string]struct{}
}

// Open loads path, or starts empty state with the default config if it does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path, d: Data{Config: api.DefaultAgentConfig()}}
	if err := fsutil.ReadJSON(path, &s.d); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.d.Config = Sanitize(s.d.Config)
	s.seen = make(map[string]struct{}, len(s.d.SeenCommands))
	for _, id := range s.d.SeenCommands {
		s.seen[id] = struct{}{}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	return fsutil.WriteJSONAtomic(s.path, s.d, 0o600)
}

// Snapshot returns a copy of the state.
func (s *Store) Snapshot() Data {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.d
	d.SeenCommands = slices.Clone(s.d.SeenCommands)
	d.IsolationAllow = slices.Clone(s.d.IsolationAllow)
	d.ServerIPs = slices.Clone(s.d.ServerIPs)
	return d
}

// Config returns the current central config.
func (s *Store) Config() api.AgentConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Config
}

// SetConfig stores a new central config.
func (s *Store) SetConfig(c api.AgentConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Config = Sanitize(c)
	return s.saveLocked()
}

// SetIsolated records the isolation state.
func (s *Store) SetIsolated(on bool, allow, serverIPs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Isolated = on
	if on {
		s.d.IsolationAllow = slices.Clone(allow)
		s.d.ServerIPs = slices.Clone(serverIPs)
	} else {
		s.d.IsolationAllow, s.d.ServerIPs = nil, nil
	}
	return s.saveLocked()
}

// LastInventory returns when inventory last ran.
func (s *Store) LastInventory() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.LastInventory
}

// SetLastInventory records when inventory last ran.
func (s *Store) SetLastInventory(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.LastInventory = t
	return s.saveLocked()
}

// Seen reports whether a command ID was seen before.
func (s *Store) Seen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[id]
	return ok
}

// MarkSeen records a command ID and persists it. It returns false if the ID was already
// recorded (a replay). The oldest IDs are forgotten beyond MaxSeen; commands expire long
// before 1000 newer ones arrive, so the expiry check covers anything older.
func (s *Store) MarkSeen(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[id]; ok {
		return false, nil
	}
	s.seen[id] = struct{}{}
	s.d.SeenCommands = append(s.d.SeenCommands, id)
	for len(s.d.SeenCommands) > MaxSeen {
		delete(s.seen, s.d.SeenCommands[0])
		s.d.SeenCommands = s.d.SeenCommands[1:]
	}
	return true, s.saveLocked()
}

// Sanitize fills zero or out-of-range values of a central config with safe defaults, so
// a partial config from the server cannot make the agent spin or stall.
func Sanitize(c api.AgentConfig) api.AgentConfig {
	def := api.DefaultAgentConfig()
	if c.HeartbeatIntervalSec <= 0 {
		c.HeartbeatIntervalSec = def.HeartbeatIntervalSec
	}
	c.HeartbeatIntervalSec = clamp(c.HeartbeatIntervalSec, 5, 3600)
	if c.InventoryIntervalSec <= 0 {
		c.InventoryIntervalSec = def.InventoryIntervalSec
	}
	c.InventoryIntervalSec = clamp(c.InventoryIntervalSec, 300, 7*24*3600)
	if c.Batch.MaxEvents <= 0 {
		c.Batch.MaxEvents = def.Batch.MaxEvents
	}
	c.Batch.MaxEvents = clamp(c.Batch.MaxEvents, 1, 20000)
	if c.Batch.FlushIntervalMs <= 0 {
		c.Batch.FlushIntervalMs = def.Batch.FlushIntervalMs
	}
	c.Batch.FlushIntervalMs = clamp(c.Batch.FlushIntervalMs, 100, 60000)
	if c.FIM.IntervalSec <= 0 {
		c.FIM.IntervalSec = def.FIM.IntervalSec
	}
	c.FIM.IntervalSec = clamp(c.FIM.IntervalSec, 60, 7*24*3600)
	if c.FIM.MaxFileSize <= 0 {
		c.FIM.MaxFileSize = def.FIM.MaxFileSize
	}
	if c.SpoolMaxBytes <= 0 {
		c.SpoolMaxBytes = def.SpoolMaxBytes
	}
	if c.SpoolMaxBytes < 16<<20 {
		c.SpoolMaxBytes = 16 << 20
	}
	return c
}

func clamp(v, lo, hi int) int {
	return max(lo, min(v, hi))
}
