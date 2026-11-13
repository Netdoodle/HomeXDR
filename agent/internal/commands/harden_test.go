package commands

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

type fakeHardening struct{ got *api.DefenderHardenParams }

func (f *fakeHardening) DefenderHarden(_ context.Context, p api.DefenderHardenParams) (api.DefenderHardenResult, error) {
	f.got = &p
	return api.DefenderHardenResult{Mode: p.Mode, Version: p.Version, Message: "ok"}, nil
}

func TestPrepareHarden(t *testing.T) {
	cmd := func(params string) *api.Command {
		return &api.Command{ID: "c1", Type: api.CmdDefenderHarden, Params: json.RawMessage(params)}
	}
	// Not Windows: rejected.
	if _, err := (&Handler{}).prepare(cmd(`{"mode":"audit","version":"audit-p1"}`)); err == nil {
		t.Fatal("accepted without a Defender")
	}
	f := &fakeHardening{}
	h := &Handler{Hardening: f}
	for _, bad := range []string{`{"mode":"block","version":"x"}`, `{"mode":"audit","version":"a b"}`,
		`{"mode":"audit","version":"v","rules":["x"]}`, `{"mode":"audit","script":"Set-MpPreference"}`} {
		if _, err := h.prepare(cmd(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	run, err := h.prepare(cmd(`{"mode":"enforce","version":"enforce-p1"}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(context.Background())
	if err != nil || f.got == nil || f.got.Mode != "enforce" || out.(api.DefenderHardenResult).Version != "enforce-p1" {
		t.Fatalf("%v %+v %+v", err, f.got, out)
	}
	if timeout(api.CmdDefenderHarden) <= 0 {
		t.Fatal("no timeout")
	}
}
