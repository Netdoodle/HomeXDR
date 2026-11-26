package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestValidateHostCommands(t *testing.T) {
	h := &store.Host{Kind: store.HostEndpoint, OS: event.OS{Platform: "linux"}}
	for _, typ := range []string{api.CmdHostReboot, api.CmdHostShutdown} {
		ok := map[string]string{
			``:                                  `{"delay_sec":60}`,
			`{}`:                                `{"delay_sec":60}`,
			`{"delay_sec":0}`:                   `{"delay_sec":0}`,
			`{"delay_sec":3600,"message":"hi"}`: `{"delay_sec":3600,"message":"hi"}`,
		}
		for in, want := range ok {
			got, err := validateParams(h, typ, json.RawMessage(in))
			if err != nil || string(got) != want {
				t.Errorf("%s %q: got %s, %v; want %s", typ, in, got, err, want)
			}
		}
		for _, in := range []string{
			`{"delay_sec":-1}`, `{"delay_sec":3601}`, `{"message":"a\nb"}`,
			`{"message":"` + strings.Repeat("x", 201) + `"}`, `{"cmd":"x"}`, `{"delay_sec":"5"}`,
		} {
			if _, err := validateParams(h, typ, json.RawMessage(in)); err == nil {
				t.Errorf("%s %s accepted", typ, in)
			}
		}
	}
	for _, typ := range []string{api.CmdAgentRestart, api.CmdAgentLogs, api.CmdAgentFlushQueue} {
		if got, err := validateParams(h, typ, nil); err != nil || string(got) != `{}` {
			t.Errorf("%s: got %s, %v", typ, got, err)
		}
		if _, err := validateParams(h, typ, json.RawMessage(`{"x":1}`)); err == nil {
			t.Errorf("%s accepted params", typ)
		}
	}
}
