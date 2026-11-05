package core

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// FlowStats tracks NetFlow and IPFIX intake for the integrations page.
type FlowStats struct {
	Listening atomic.Bool
	Addr      atomic.Value // string
	Packets   atomic.Uint64
	Records   atomic.Uint64
	// Dropped counts packets lost because the queue was full.
	Dropped atomic.Uint64
	// Refused counts packets from addresses not on the allow list.
	Refused   atomic.Uint64
	Malformed atomic.Uint64
	// Waiting counts data sets that arrived before their template. Discarded counts those
	// there was no room to keep.
	Waiting   atomic.Uint64
	Discarded atomic.Uint64
	// Failed counts records that could not be stored.
	Failed atomic.Uint64

	mu        sync.Mutex
	exporters map[string]*FlowExporter
}

// FlowExporter is one device sending flows.
type FlowExporter struct {
	IP        string    `json:"ip"`
	Version   int       `json:"version"`
	Packets   uint64    `json:"packets"`
	Records   uint64    `json:"records"`
	Templates int       `json:"templates"`
	LastSeen  time.Time `json:"last_seen"`
}

// NewFlowStats returns empty stats.
func NewFlowStats() *FlowStats {
	s := &FlowStats{exporters: map[string]*FlowExporter{}}
	s.Addr.Store("")
	return s
}

// Seen records a packet from an exporter.
func (s *FlowStats) Seen(ip string, version, records, templates int, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.exporters[ip]
	if !ok {
		e = &FlowExporter{IP: ip}
		s.exporters[ip] = e
	}
	e.Version, e.Templates, e.LastSeen = version, templates, now
	e.Packets++
	e.Records += uint64(records)
}

// Exporters returns a snapshot of known exporters.
func (s *FlowStats) Exporters() []FlowExporter {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FlowExporter, 0, len(s.exporters))
	for _, e := range s.exporters {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
