// Package core holds the server's business logic shared by the agent API, the console
// API and the syslog listener: ingest and detection, commands, hunts and rule management.
package core

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/pki"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
	"github.com/Netdoodle/homexdr/shared/api"
)

// Core wires the server's components together.
type Core struct {
	Cfg    config.Config
	Log    *slog.Logger
	State  *store.Store
	Events events.Store
	PKI    *pki.PKI
	Engine *detect.Engine
	Rules  *RuleSet
	// RuleRepos downloads and updates rule repositories (rulerepos.go).
	RuleRepos *RuleRepos
	Broker    *Broker
	Syslog    *SyslogStats
	// Release is the signed agent release offered to agents (release.go).
	Release *Release
	// Triage is the AI analyst; new alerts are handed to it (it decides whether to run).
	Triage *triage.Service
}

// New builds a Core and loads rules.
func New(ctx context.Context, cfg config.Config, log *slog.Logger, st *store.Store, ev events.Store, p *pki.PKI) (*Core, error) {
	c := &Core{
		Cfg: cfg, Log: log, State: st, Events: ev, PKI: p,
		Engine: detect.NewEngine(),
		Broker: NewBroker(),
		Syslog: NewSyslogStats(),
	}
	c.Release = NewRelease(cfg.DownloadsDir, cfg.SignaturesDir, log)
	if cfg.ReleasesDir != "" {
		c.Release.SetArchive(cfg.ReleasesDir, cfg.ReleasesKeep, c.pinnedVersions)
	}
	c.Triage = triage.New(st, ev, log)
	c.Rules = NewRuleSet(c)
	c.RuleRepos = NewRuleRepos(c)
	if err := c.Rules.Reload(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

const agentConfigKey = "agent_config"

// AgentConfig returns the current default agent config.
func (c *Core) AgentConfig(ctx context.Context) api.AgentConfig {
	var cfg api.AgentConfig
	if err := c.State.GetKV(ctx, agentConfigKey, &cfg); err != nil || cfg.Version == 0 {
		return api.DefaultAgentConfig()
	}
	return cfg
}

// SetAgentConfig stores a new default agent config, bumping its version.
func (c *Core) SetAgentConfig(ctx context.Context, cfg api.AgentConfig) (api.AgentConfig, error) {
	cur := c.AgentConfig(ctx)
	cfg.Version = cur.Version + 1
	if cfg.HeartbeatIntervalSec < 5 {
		cfg.HeartbeatIntervalSec = 5
	}
	if cfg.Batch.MaxEvents <= 0 {
		cfg.Batch.MaxEvents = 500
	}
	if cfg.Batch.FlushIntervalMs < 100 {
		cfg.Batch.FlushIntervalMs = 100
	}
	if cfg.SpoolMaxBytes <= 0 {
		cfg.SpoolMaxBytes = 512 << 20
	}
	return cfg, c.State.SetKV(ctx, agentConfigKey, cfg)
}

// Audit writes an audit record, logging failures.
func (c *Core) Audit(ctx context.Context, user, action, target, details string) {
	if err := c.State.Audit(ctx, user, action, target, details); err != nil {
		c.Log.Error("audit write failed", "err", err, "action", action)
	}
}

// RunMaintenance runs periodic jobs until ctx ends: command expiry, session cleanup and
// event retention (by age and by size).
func (c *Core) RunMaintenance(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastPurge, lastTrim, lastDecommission := time.Time{}, time.Time{}, time.Time{}
	for {
		if n, err := c.State.ExpireCommands(ctx); err != nil {
			c.Log.Warn("expire commands", "err", err)
		} else if n > 0 {
			c.Log.Info("expired commands", "count", n)
		}
		if err := c.State.PurgeExpired(ctx); err != nil {
			c.Log.Warn("purge sessions", "err", err)
		}
		// Pick up rule files added or changed in the rules folder without a restart.
		if _, err := c.Rules.ReloadIfChanged(ctx); err != nil {
			c.Log.Warn("reload rules", "err", err)
		}
		if c.Cfg.RetentionDays > 0 && time.Since(lastPurge) > 6*time.Hour {
			before := time.Now().AddDate(0, 0, -c.Cfg.RetentionDays)
			if err := c.Events.Purge(ctx, before); err != nil {
				c.Log.Warn("event retention purge", "err", err)
			}
			lastPurge = time.Now()
		}
		if time.Since(lastDecommission) > time.Hour {
			c.decommissionInactive(ctx)
			lastDecommission = time.Now()
		}
		if c.Cfg.RetentionMaxBytes > 0 && time.Since(lastTrim) > 10*time.Minute {
			c.trimEvents(ctx)
			lastTrim = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// trimEvents enforces the event store's size cap.
func (c *Core) trimEvents(ctx context.Context) {
	cutoff, err := c.Events.TrimToSize(ctx, c.Cfg.RetentionMaxBytes)
	if !cutoff.IsZero() {
		c.Log.Info("event store reached its size cap; removed the oldest events",
			"cap_bytes", c.Cfg.RetentionMaxBytes, "removed_before", cutoff.Format(time.RFC3339))
	}
	if err != nil {
		c.Log.Warn("event retention size cap", "err", err)
	}
}

// Broker wakes long-polling agents when commands are queued for them.
type Broker struct {
	mu      sync.Mutex
	waiters map[string]chan struct{}
}

// NewBroker returns an empty broker.
func NewBroker() *Broker { return &Broker{waiters: map[string]chan struct{}{}} }

// Wait returns a channel that is closed the next time Notify(agentID) is called.
func (b *Broker) Wait(agentID string) <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch, ok := b.waiters[agentID]
	if !ok {
		ch = make(chan struct{})
		b.waiters[agentID] = ch
	}
	return ch
}

// Notify wakes everyone waiting on agentID.
func (b *Broker) Notify(agentID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.waiters[agentID]; ok {
		close(ch)
		delete(b.waiters, agentID)
	}
}

// SyslogStats tracks syslog intake for the integrations page.
type SyslogStats struct {
	Listening atomic.Bool
	Addr      atomic.Value // string
	Received  atomic.Uint64
	Parsed    atomic.Uint64
	Failed    atomic.Uint64

	mu      sync.Mutex
	sources map[string]*SyslogSource
}

// SyslogSource is one device sending syslog.
type SyslogSource struct {
	IP       string    `json:"ip"`
	Name     string    `json:"name"`
	Kind     string    `json:"kind"`
	LastSeen time.Time `json:"last_seen"`
	Count    uint64    `json:"count"`
}

// NewSyslogStats returns empty stats.
func NewSyslogStats() *SyslogStats {
	s := &SyslogStats{sources: map[string]*SyslogSource{}}
	s.Addr.Store("")
	return s
}

// Seen records a message from a source.
func (s *SyslogStats) Seen(ip, name, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, ok := s.sources[ip]
	if !ok {
		src = &SyslogSource{IP: ip}
		s.sources[ip] = src
	}
	if name != "" {
		src.Name = name
	}
	if kind != "" {
		src.Kind = kind
	}
	src.LastSeen = time.Now().UTC()
	src.Count++
}

// Sources returns a snapshot of known sources.
func (s *SyslogStats) Sources() []SyslogSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SyslogSource, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, *src)
	}
	return out
}
