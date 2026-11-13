package commands

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

type fakeFirewall struct{ got []api.FirewallParams }

func (f *fakeFirewall) ApplyFirewall(_ context.Context, p api.FirewallParams) (api.FirewallResult, error) {
	f.got = append(f.got, p)
	return api.FirewallResult{Version: p.Version, Rules: len(p.Rules)}, nil
}

func fwCmd(params string) *api.Command {
	return &api.Command{ID: "c1", Type: api.CmdFirewall, Params: json.RawMessage(params)}
}

func TestPrepareFirewall(t *testing.T) {
	fw := &fakeFirewall{}
	h := &Handler{Firewall: fw, Platform: "linux"}
	run, err := h.prepare(fwCmd(`{"version":"fw-1","rules":[{"cidr":"203.0.113.0/24"},{"cidr":"2001:db8::1","direction":"out"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(context.Background())
	if err != nil || out.(api.FirewallResult).Rules != 2 || len(fw.got) != 1 {
		t.Fatalf("run = %v, %v", out, err)
	}
	for params, want := range map[string]string{
		`{"version":"fw-1","rules":[{"cidr":"0.0.0.0/0"}]}`:                   "too broad",
		`{"version":"fw-1","rules":[{"cidr":"127.0.0.1"}]}`:                   "loopback",
		`{"version":"fw-1","rules":[{"cidr":"203.0.113.1","direction":"x"}]}`: "direction",
		`{"version":"a'b","rules":[]}`:                                        "version",
		`{"version":"fw-1","rules":[],"shell":"x"}`:                           "unknown field",
	} {
		if _, err := h.prepare(fwCmd(params)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", params, err, want)
		}
	}
	none := &Handler{Platform: "plan9"}
	if _, err := none.prepare(fwCmd(`{"version":"v","rules":[]}`)); err == nil || !strings.Contains(err.Error(), "not supported on plan9") {
		t.Errorf("no firewall: %v", err)
	}
}
