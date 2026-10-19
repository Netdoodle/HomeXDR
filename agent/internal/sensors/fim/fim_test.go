package fim

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type collector struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collector) Emit(e *event.Event) {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
}

func (c *collector) take() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.evs
	c.evs = nil
	return out
}

func byPath(evs []*event.Event) map[string]*event.Event {
	m := map[string]*event.Event{}
	for _, e := range evs {
		m[e.File.Path] = e
	}
	return m
}

func TestScanDetectsChanges(t *testing.T) {
	root := t.TempDir()
	data := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("keep.conf", "a")
	write("change.conf", "before")
	write("delete.conf", "x")
	write("ignored.swp", "x")
	os.Mkdir(filepath.Join(root, "sub"), 0o755)
	write("sub/nested.conf", "n")

	cfg := api.FIMConfig{Enabled: true, Paths: []string{root}, Exclude: []string{"*.swp"}, MaxFileSize: 1 << 20, IntervalSec: 3600}
	s := New(cfg, nil, data, slog.New(slog.NewTextHandler(io.Discard, nil)))
	out := &collector{}
	ctx := context.Background()

	base, err := s.ScanOnce(ctx, &Baseline{}, out)
	if err != nil {
		t.Fatal(err)
	}
	if evs := out.take(); len(evs) != 0 {
		t.Fatalf("first scan must only record a baseline, got %d events", len(evs))
	}
	if _, ok := base.Entries[filepath.Join(root, "ignored.swp")]; ok {
		t.Fatal("excluded file in baseline")
	}
	if base.Entries[filepath.Join(root, "change.conf")].SHA256 == "" {
		t.Fatal("file not hashed")
	}

	write("change.conf", "after the change")
	os.Remove(filepath.Join(root, "delete.conf"))
	write("new.conf", "new")
	write("ignored2.swp", "x")
	if runtime.GOOS != "windows" {
		os.Chmod(filepath.Join(root, "keep.conf"), 0o600)
	}

	base2, err := s.ScanOnce(ctx, &base, out)
	if err != nil {
		t.Fatal(err)
	}
	evs := byPath(out.take())
	check := func(name, typ, action string) *event.Event {
		t.Helper()
		e, ok := evs[filepath.Join(root, name)]
		if !ok {
			t.Fatalf("no event for %s (have %v)", name, evs)
		}
		if !slices.Equal(e.Event.Type, []string{typ}) || e.Event.Action != action || e.Event.Module != event.ModuleFIM {
			t.Fatalf("%s: type %v action %s module %s", name, e.Event.Type, e.Event.Action, e.Event.Module)
		}
		return e
	}
	ch := check("change.conf", event.TypeChange, "updated")
	if ch.File.Hash == nil || ch.File.Hash.SHA256 == base.Entries[filepath.Join(root, "change.conf")].SHA256 {
		t.Error("changed file should carry its new hash")
	}
	if changed, _ := ch.Data["fim.changed"].([]string); !slices.Contains(changed, "sha256") {
		t.Errorf("fim.changed = %v", ch.Data["fim.changed"])
	}
	check("delete.conf", event.TypeDeletion, "deleted")
	check("new.conf", event.TypeCreation, "created")
	if runtime.GOOS != "windows" {
		check("keep.conf", event.TypeChange, "attributes_modified")
	}
	if _, ok := evs[filepath.Join(root, "ignored2.swp")]; ok {
		t.Error("excluded file reported")
	}
	if _, ok := evs[filepath.Join(root, "sub/nested.conf")]; ok {
		t.Error("unchanged file reported")
	}

	// No changes: no events.
	if _, err := s.ScanOnce(ctx, &base2, out); err != nil {
		t.Fatal(err)
	}
	if evs := out.take(); len(evs) != 0 {
		t.Fatalf("unchanged tree produced %d events", len(evs))
	}
}

func TestNewRootIsBaselinedSilently(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(a, "1"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(b, "2"), []byte("2"), 0o644)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	out := &collector{}
	s1 := New(api.FIMConfig{Paths: []string{a}}, nil, t.TempDir(), log)
	base, _ := s1.ScanOnce(context.Background(), &Baseline{}, out)
	s2 := New(api.FIMConfig{Paths: []string{a, b}}, nil, t.TempDir(), log)
	if _, err := s2.ScanOnce(context.Background(), &base, out); err != nil {
		t.Fatal(err)
	}
	if evs := out.take(); len(evs) != 0 {
		t.Fatalf("adding a root reported %d creations", len(evs))
	}
}

func TestDataDirExcluded(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "agentdata")
	os.MkdirAll(data, 0o700)
	os.WriteFile(filepath.Join(data, "spool.seg"), []byte("x"), 0o600)
	s := New(api.FIMConfig{Paths: []string{root}}, nil, data, slog.New(slog.NewTextHandler(io.Discard, nil)))
	base, _ := s.ScanOnce(context.Background(), &Baseline{}, &collector{})
	for p := range base.Entries {
		if filepath.Dir(p) == data || p == data {
			t.Fatalf("data dir scanned: %s", p)
		}
	}
}
