package detect

import (
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Defender's ASR, Network Protection and Controlled Folder Access events: blocks raise an
// alert, audit hits do not.
func TestShippedRulesDefenderHardening(t *testing.T) {
	rules, errs := LoadDir(filepath.Join("..", "..", "..", "rules"))
	for _, e := range errs {
		t.Errorf("load %s: %v", e.Path, e.Err)
	}
	e := NewEngine()
	e.SetRules(rules)
	ev := func(code string) *event.Event {
		return &event.Event{
			ID:   event.NewID(),
			Host: event.Host{ID: "h", Name: "desk", OS: &event.OS{Platform: "windows"}},
			Event: event.Meta{Kind: "event", Module: "eventlog", Dataset: "windows.windefend",
				Provider: "Microsoft-Windows-Windows Defender", Code: code},
			Data: map[string]any{"Channel": "Microsoft-Windows-Windows Defender/Operational", "ID": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"},
		}
	}
	cases := map[string]string{
		"1121": "9f5455a9-7b86-4415-9303-960ebc74786e",
		"1126": "a1692c61-2209-4465-813a-af4ae5f5581d",
		"1123": "33f78e2d-e200-47d2-aa39-8d1d72f53f1c",
		"1122": "", "1124": "", "1125": "",
	}
	ours := map[string]bool{"9f5455a9-7b86-4415-9303-960ebc74786e": true, "a1692c61-2209-4465-813a-af4ae5f5581d": true, "33f78e2d-e200-47d2-aa39-8d1d72f53f1c": true}
	for code, want := range cases {
		var got []string
		for _, r := range e.Evaluate(ev(code)) {
			if ours[r.ID] {
				got = append(got, r.ID)
			}
		}
		switch {
		case want == "" && len(got) > 0:
			t.Errorf("event %s: hits %v", code, got)
		case want != "" && (len(got) != 1 || got[0] != want):
			t.Errorf("event %s: hits %v, want %s", code, got, want)
		}
	}
}
