package detect

import (
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// The decoy rules against events shaped like the agent's decoy sensor.
func TestShippedRulesDecoy(t *testing.T) {
	rules, errs := LoadDir(filepath.Join("..", "..", "..", "rules"))
	for _, e := range errs {
		t.Errorf("load %s: %v", e.Path, e.Err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}
	e := NewEngine()
	e.SetRules(rules)
	byID := map[string]*Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	const tampered, opened = "c513c679-e88c-4143-8a7e-5d4dfd6314e6", "0df3d291-4293-43f3-b85b-053232c048e6"
	if r := byID[tampered]; r == nil || r.Level != "critical" {
		t.Fatalf("tampered rule: %+v", r)
	}
	if r := byID[opened]; r == nil || r.Level != "high" {
		t.Fatalf("opened rule: %+v", r)
	}

	decoy := func(platform, typ string) *event.Event {
		return &event.Event{
			Host: event.Host{OS: &event.OS{Platform: platform}},
			Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryFile}, Type: []string{typ},
				Module: event.ModuleDecoy, Dataset: "decoy.event"},
			Labels: map[string]string{"decoy": "true"},
			File:   &event.File{Path: `C:\Users\bob\Desktop\backup-codes.txt`},
		}
	}
	fim := decoy(event.PlatformLinux, event.TypeChange)
	fim.Event.Module, fim.Event.Dataset = event.ModuleFIM, "fim.event"

	cases := []struct {
		name string
		ev   *event.Event
		want string
	}{
		{"windows change", decoy(event.PlatformWindows, event.TypeChange), tampered},
		{"linux deletion", decoy(event.PlatformLinux, event.TypeDeletion), tampered},
		{"macos rename", decoy(event.PlatformDarwin, "rename"), tampered},
		{"linux open", decoy(event.PlatformLinux, event.TypeAccess), opened},
		{"windows open", decoy(event.PlatformWindows, event.TypeAccess), ""},
		{"fim change", fim, ""},
	}
	for _, c := range cases {
		var got []string
		for _, r := range e.Evaluate(c.ev) {
			if r.ID == tampered || r.ID == opened {
				got = append(got, r.ID)
			}
		}
		switch {
		case c.want == "" && len(got) > 0:
			t.Errorf("%s: unexpected hits %v", c.name, got)
		case c.want != "" && (len(got) != 1 || got[0] != c.want):
			t.Errorf("%s: hits %v, want %s", c.name, got, c.want)
		}
	}
}
