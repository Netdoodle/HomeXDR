package core

import (
	"context"
	"errors"
	"maps"
	"net/netip"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// An admin can bind a syslog sender to one parser when auto-detection picks the wrong one
// or cannot tell (pfSense and OPNsense send the same filterlog lines). The listener reads
// the binding for every message, so it is kept in memory and saved to the kv table.
const syslogBindingsKey = "syslog.bindings"

// maxSyslogBindings keeps the table small; a home network has a handful of senders.
const maxSyslogBindings = 512

// LoadSyslogBindings reads the saved bindings. The listener calls it when it starts.
func (c *Core) LoadSyslogBindings(ctx context.Context) {
	m := map[string]string{}
	if err := c.State.GetKV(ctx, syslogBindingsKey, &m); err != nil && !errors.Is(err, store.ErrNotFound) {
		c.Log.Warn("read syslog parser bindings", "err", err)
	}
	c.Syslog.mu.Lock()
	c.Syslog.bindings = m
	c.Syslog.mu.Unlock()
}

// SetSyslogBinding binds ip to parser, or removes the binding when parser is "". The
// caller checks that parser names a real decoder.
func (c *Core) SetSyslogBinding(ctx context.Context, ip, parser string) (string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", &ValidationError{Msg: "not an IP address: " + ip}
	}
	ip = a.Unmap().WithZone("").String()
	s := c.Syslog
	s.mu.Lock()
	next := maps.Clone(s.bindings)
	s.mu.Unlock()
	if next == nil {
		next = map[string]string{}
	}
	if parser == "" {
		delete(next, ip)
	} else {
		if _, ok := next[ip]; !ok && len(next) >= maxSyslogBindings {
			return "", &ValidationError{Msg: "too many parser bindings"}
		}
		next[ip] = parser
	}
	if err := c.State.SetKV(ctx, syslogBindingsKey, next); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.bindings = next
	s.mu.Unlock()
	return ip, nil
}

// Binding returns the parser bound to a sender, or "".
func (s *SyslogStats) Binding(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bindings[ip]
}
