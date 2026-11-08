package core

import (
	"encoding/json"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestValidateDefenderParams(t *testing.T) {
	win := &store.Host{Kind: store.HostEndpoint, OS: event.OS{Platform: "windows"}}
	lin := &store.Host{Kind: store.HostEndpoint, OS: event.OS{Platform: "linux"}}
	ok := map[string]string{
		`{"action":"status","threat_id":5}`:                          `{"action":"status"}`,
		`{"action":"scan","scan_type":"quick","path":"C:\\x"}`:       `{"action":"scan","scan_type":"quick"}`,
		`{"action":"scan","scan_type":"path","path":"C:\\x\\a.exe"}`: `{"action":"scan","scan_type":"path","path":"C:\\x\\a.exe"}`,
		`{"action":"allow_threat","threat_id":2147519003}`:           `{"action":"allow_threat","threat_id":2147519003}`,
	}
	for in, want := range ok {
		got, err := validateParams(win, api.CmdDefender, json.RawMessage(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	for _, in := range []string{
		`{"action":"run","cmd":"x"}`,
		`{"action":"nuke"}`,
		`{"action":"allow_threat"}`,
		`{"action":"scan","scan_type":"path","path":"relative.exe"}`,
		`{"action":"scan","scan_type":"everything"}`,
	} {
		if _, err := validateParams(win, api.CmdDefender, json.RawMessage(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	if _, err := validateParams(lin, api.CmdDefender, json.RawMessage(`{"action":"status"}`)); err == nil {
		t.Error("Defender action accepted for a Linux host")
	}
}
