// Package events stores and queries telemetry. Two backends implement Store: ClickHouse
// (default for real deployments) and SQLite ("lite" mode and tests). Both index the same
// columns (see columns.go) and keep the full event as JSON.
package events

import (
	"context"
	"errors"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// CategoryDNS is a pseudo-category for SearchQuery.Categories and EntityCounts: events
// with a DNS question. DNS events are ECS category "network", so they are counted and
// filtered separately from other network events.
const CategoryDNS = "dns"

// ErrNotFound is returned by Get when no event has the ID.
var ErrNotFound = errors.New("event not found")

// Store is an event store.
type Store interface {
	// Insert stores events. It must be durable when it returns nil.
	Insert(ctx context.Context, evs []*event.Event) error
	// Search runs a query-language search.
	Search(ctx context.Context, q SearchQuery) (*SearchResult, error)
	// Get returns one event by ID.
	Get(ctx context.Context, id string) (*event.Event, error)
	// GetMany returns the events with the given IDs (missing IDs are skipped).
	GetMany(ctx context.Context, ids []string) ([]*event.Event, error)
	// ProcessEvents returns process start/end events for the given entity IDs on a host.
	ProcessEvents(ctx context.Context, hostID string, entityIDs []string) ([]*event.Event, error)
	// Children returns process start events whose parent is one of parentIDs.
	Children(ctx context.Context, hostID string, parentIDs []string, limit int) ([]*event.Event, error)
	// EntityCounts returns, per entity ID, event counts by category for non-process events.
	EntityCounts(ctx context.Context, hostID string, entityIDs []string) (map[string]map[string]int64, error)
	// Stats returns counts for the dashboard.
	Stats(ctx context.Context, from, to time.Time) (*Stats, error)
	// Scan calls fn for stored events in [from, to), newest first, until fn returns false
	// or limit events were visited.
	Scan(ctx context.Context, from, to time.Time, limit int, fn func(*event.Event) bool) error
	// Purge deletes events older than before (backends with native TTL may no-op).
	Purge(ctx context.Context, before time.Time) error
	Ping(ctx context.Context) error
	Close() error
}

// SearchQuery is a search request.
type SearchQuery struct {
	Query      string    // query language, see query.go
	From, To   time.Time // zero means unbounded
	HostID     string
	HostIDs    []string // any-of, combined with HostID
	EntityID   string   // process.entity_id
	Categories []string // event.category any-of
	Limit      int
	Offset     int
	Asc        bool
}

// SearchResult is a page of events.
type SearchResult struct {
	Events []*event.Event `json:"events"`
	Total  int64          `json:"total"`
	TookMs int64          `json:"took_ms"`
}

// TimeCount is one timeline bucket.
type TimeCount struct {
	T     time.Time `json:"t"`
	Count int64     `json:"count"`
}

// CategoryCount is events per category.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// Stats is dashboard data.
type Stats struct {
	Total      int64           `json:"total"`
	Timeline   []TimeCount     `json:"timeline"`
	Categories []CategoryCount `json:"categories"`
}

func clamp(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
