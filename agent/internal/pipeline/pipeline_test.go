package pipeline

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type sink struct{ lines [][]byte }

func (s *sink) Append(l []byte) error {
	s.lines = append(s.lines, append([]byte(nil), l...))
	return nil
}

func procEvent(exe string) *event.Event {
	return &event.Event{
		Event:   event.Meta{Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart}},
		Process: &event.Process{Executable: exe, Args: []string{exe, "--flag"}},
		Data:    map[string]any{"fim.changed": []string{"sha256"}, "LogonType": "3"},
	}
}

func TestStamp(t *testing.T) {
	s := &sink{}
	p := New("agent-1", "v1.2.3", "host1", s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.Emit(&event.Event{})
	if len(s.lines) != 1 {
		t.Fatal("not spooled")
	}
	var e event.Event
	if err := json.Unmarshal(s.lines[0], &e); err != nil {
		t.Fatal(err)
	}
	if e.ID == "" || e.Timestamp.IsZero() || time.Since(e.Timestamp) > time.Minute {
		t.Errorf("id/timestamp not stamped: %+v", e)
	}
	if e.Agent.ID != "agent-1" || e.Agent.Version != "v1.2.3" || e.Agent.Type != event.AgentTypeEndpoint {
		t.Errorf("agent: %+v", e.Agent)
	}
	if e.Host.Name != "host1" || e.Event.Kind != event.KindEvent {
		t.Errorf("host/kind: %+v %+v", e.Host, e.Event)
	}
	// Producer values are kept.
	s.lines = nil
	p.Emit(&event.Event{ID: "keep", Event: event.Meta{Kind: event.KindState}})
	json.Unmarshal(s.lines[0], &e)
	if e.ID != "keep" || e.Event.Kind != event.KindState {
		t.Errorf("overwrote producer fields: %+v", e)
	}
}

func TestFilters(t *testing.T) {
	cases := []struct {
		name string
		f    api.EventFilter
		exe  string
		drop bool
	}{
		{"equals case-insensitive", api.EventFilter{Field: "process.executable", Op: "equals", Value: "/USR/BIN/LS"}, "/usr/bin/ls", true},
		{"equals no match", api.EventFilter{Field: "process.executable", Op: "equals", Value: "/usr/bin/l"}, "/usr/bin/ls", false},
		{"prefix", api.EventFilter{Field: "process.executable", Op: "prefix", Value: "/usr/lib/"}, "/usr/lib/x/y", true},
		{"suffix", api.EventFilter{Field: "process.executable", Op: "suffix", Value: "/updatedb"}, "/usr/bin/updatedb", true},
		{"contains", api.EventFilter{Field: "process.executable", Op: "contains", Value: "snap"}, "/snap/bin/foo", true},
		{"array field", api.EventFilter{Field: "process.args", Op: "equals", Value: "--flag"}, "/bin/x", true},
		{"category array", api.EventFilter{Field: "event.category", Op: "equals", Value: "process"}, "/bin/x", true},
		{"category restricts", api.EventFilter{Category: "network", Field: "process.executable", Op: "prefix", Value: "/"}, "/bin/x", false},
		{"category matches", api.EventFilter{Category: "process", Field: "process.executable", Op: "prefix", Value: "/"}, "/bin/x", true},
		{"dotted data key", api.EventFilter{Field: "data.fim.changed", Op: "equals", Value: "sha256"}, "/bin/x", true},
		{"data key case-insensitive", api.EventFilter{Field: "data.logontype", Op: "equals", Value: "3"}, "/bin/x", true},
		{"missing field", api.EventFilter{Field: "file.path", Op: "contains", Value: ""}, "/bin/x", false},
	}
	for _, c := range cases {
		s := &sink{}
		p := New("a", "v", "h", s, slog.New(slog.NewTextHandler(io.Discard, nil)))
		p.SetFilters([]api.EventFilter{c.f})
		p.Emit(procEvent(c.exe))
		if dropped := len(s.lines) == 0; dropped != c.drop {
			t.Errorf("%s: dropped=%v want %v", c.name, dropped, c.drop)
		}
	}
}

func TestInvalidFiltersIgnored(t *testing.T) {
	f, bad := Compile([]api.EventFilter{
		{Field: "process.name", Op: "regex", Value: ".*"},
		{Field: "", Op: "equals", Value: "x"},
		{Field: "process.name", Op: "Equals", Value: "x"},
	})
	if len(bad) != 2 || len(f.list) != 1 {
		t.Fatalf("bad=%d ok=%d", len(bad), len(f.list))
	}
	s := &sink{}
	p := New("a", "v", "h", s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.SetFilters([]api.EventFilter{{Field: "process.name", Op: "regex", Value: ".*"}})
	p.Emit(procEvent("/bin/x"))
	if len(s.lines) != 1 {
		t.Fatal("an invalid filter must not drop events")
	}
	if acc, filt, _ := p.Counters(); acc != 1 || filt != 0 {
		t.Fatalf("counters %d %d", acc, filt)
	}
}
