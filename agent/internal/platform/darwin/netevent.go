package darwin

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// connEvent builds a network connection event. For inbound connections the remote end
// is the source; for outbound ones the local end is. community_id is left to the server.
func connEvent(transport, dir, action string, local, remote netip.AddrPort, proc *event.Process, module string, ts time.Time) *event.Event {
	src, dst := local, remote
	if dir == event.DirectionInbound {
		src, dst = remote, local
	}
	typ := "ipv4"
	if local.Addr().Is6() {
		typ = "ipv6"
	}
	msg := fmt.Sprintf("%s %s %s -> %s", transport, action, src, dst)
	if proc != nil && proc.Name != "" {
		msg += " (" + proc.Name + ")"
	}
	return &event.Event{
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryNetwork}, Type: []string{event.TypeConnection, event.TypeStart},
			Action: action, Outcome: event.OutcomeSuccess, Module: module, Dataset: "network",
		},
		Message:     msg,
		Network:     &event.Network{Transport: transport, Type: typ, Direction: dir},
		Source:      &event.Endpoint{IP: src.Addr().String(), Port: int(src.Port())},
		Destination: &event.Endpoint{IP: dst.Addr().String(), Port: int(dst.Port())},
		Process:     proc,
	}
}

// newConnections returns the established TCP connections in cur that were not in prev,
// each with its direction: inbound when its local port is listening.
type connKey struct {
	pid           int64
	local, remote netip.AddrPort
}

type newConn struct {
	sockEntry
	Inbound bool
}

func established(entries []sockEntry) map[connKey]sockEntry {
	m := map[connKey]sockEntry{}
	for _, e := range entries {
		if e.Transport == "tcp" && e.State == "ESTABLISHED" && e.Remote.IsValid() {
			m[connKey{e.PID, e.Local, e.Remote}] = e
		}
	}
	return m
}

func newConnections(prev map[connKey]sockEntry, entries []sockEntry) (cur map[connKey]sockEntry, fresh []newConn) {
	listening := map[uint16]bool{}
	for _, e := range entries {
		if e.Transport == "tcp" && e.State == "LISTEN" {
			listening[e.Local.Port()] = true
		}
	}
	cur = established(entries)
	for k, e := range cur {
		if _, ok := prev[k]; !ok {
			fresh = append(fresh, newConn{sockEntry: e, Inbound: listening[e.Local.Port()]})
		}
	}
	return cur, fresh
}
