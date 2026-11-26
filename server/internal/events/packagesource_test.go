package events

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// package.source is not an indexed column: it rides in the raw JSON, so a read back
// through SampleSource must still carry it.
func TestPackageSourceRoundTrip(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute)
	e := &event.Event{
		ID: event.NewID(), Timestamp: at, Host: event.Host{ID: "h1", Name: "h"},
		Event:   event.Meta{Kind: event.KindState, Module: event.ModuleInventory, Dataset: "inventory.software.list"},
		Package: &event.Package{Name: "libssl3", Version: "3.0.11-1", Type: "deb", Source: "openssl"},
	}
	if err := s.Insert(ctx, []*event.Event{e}); err != nil {
		t.Fatal(err)
	}
	evs, err := SampleSource(ctx, s, "h1", event.ModuleInventory, "inventory.software.list", at.Add(-time.Hour), at.Add(time.Hour), 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("sample: %v %v", evs, err)
	}
	if evs[0].Package == nil || evs[0].Package.Source != "openssl" {
		t.Fatalf("package = %+v", evs[0].Package)
	}
}
