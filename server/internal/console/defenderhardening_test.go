package console

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// The Defender hardening loop: the group's mode reaches Windows hosts as defender.harden,
// the agent's result marks the host applied or partial, off is only sent to hosts that
// were hardened, and old agents show not_allowed.
func TestDefenderHardeningReconcile(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin, viewer := signedIn(t, srv)

	win := api.HostInfo{Hostname: "desk", OS: event.OS{Platform: "windows"}}
	if _, err := c.State.CreateEndpoint(ctx, "w1", win, nil, "1"); err != nil {
		t.Fatal(err)
	}
	c.State.CreateEndpoint(ctx, "w2", api.HostInfo{Hostname: "old", OS: event.OS{Platform: "windows"}}, nil, "3")
	// w2's agent predates the command: its local policy lacks it.
	old := slices.DeleteFunc(slices.Clone(api.DefaultAllowedActions), func(s string) bool { return s == api.CmdDefenderHarden })
	if _, err := c.State.Heartbeat(ctx, "w2", api.HostInfo{Hostname: "old", OS: event.OS{Platform: "windows"}}, api.AgentStatus{AllowedActions: old}); err != nil {
		t.Fatal(err)
	}
	c.State.CreateEndpoint(ctx, "l1", api.HostInfo{Hostname: "srv", OS: event.OS{Platform: "linux"}}, nil, "2")
	g, _ := c.State.CreateGroup(ctx, "Office", "")
	c.State.SetHostsGroup(ctx, []string{"w1"}, g.ID)
	c.ReloadGroups(ctx)

	commands := func(host string) []*store.CommandRecord {
		cs, _ := c.State.ListHostCommands(ctx, host, 50)
		var out []*store.CommandRecord
		for _, x := range cs {
			if x.Type == api.CmdDefenderHarden {
				out = append(out, x)
			}
		}
		return out
	}
	finish := func(rec *store.CommandRecord, r api.DefenderHardenResult) {
		t.Helper()
		out, _ := json.Marshal(r)
		done, err := c.State.RecordResult(ctx, "w1", api.CommandResult{CommandID: rec.ID, Status: api.StatusCompleted, Output: out})
		if err != nil {
			t.Fatal(err)
		}
		h, _ := c.State.GetHost(ctx, "w1")
		c.CommandFinished(ctx, h, done)
	}

	// Off everywhere (the default): nothing is sent.
	c.ReconcileDefenderHardening(ctx)
	if n := len(commands("w1")) + len(commands("w2")) + len(commands("l1")); n != 0 {
		t.Fatalf("commands while off: %d", n)
	}
	if st := c.DefenderHardeningHostState(ctx, "w1"); st.Status != "off" {
		t.Fatalf("state while off: %+v", st)
	}

	// The group asks for audit; Global stays off.
	audit := "audit"
	if _, err := c.State.UpdateGroup(ctx, g.ID, store.GroupUpdate{Policy: &store.GroupPolicy{AV: store.AVGroupPolicy{DefenderHardening: &audit}}}); err != nil {
		t.Fatal(err)
	}
	c.ReloadGroups(ctx)
	if e := c.ResolveAV(g.ID).DefenderHardening; e.Value != "audit" || e.GroupName != "Office" {
		t.Fatalf("effective %+v", e)
	}
	c.ReconcileDefenderHardening(ctx)
	cs := commands("w1")
	if len(cs) != 1 || len(commands("w2")) != 0 {
		t.Fatalf("commands = %d / %d", len(cs), len(commands("w2")))
	}
	var p api.DefenderHardenParams
	if err := json.Unmarshal(cs[0].Params, &p); err != nil || p.Mode != "audit" || p.Version != "audit-p"+api.HardeningProfile {
		t.Fatalf("params = %s", cs[0].Params)
	}
	c.ReconcileDefenderHardening(ctx) // pending: not sent again
	if len(commands("w1")) != 1 {
		t.Fatal("sent twice while pending")
	}
	finish(cs[0], api.DefenderHardenResult{Mode: "audit", Version: p.Version, Message: "audit: 16 of 16 settings in effect"})
	c.ReconcileDefenderHardening(ctx)
	if st := c.DefenderHardeningHostState(ctx, "w1"); st.Status != "applied" || st.Applied != p.Version || len(commands("w1")) != 1 {
		t.Fatalf("after success: %+v, %d commands", st, len(commands("w1")))
	}

	// Global enforce: w2 (no group) cannot take it; w1 keeps its group's audit.
	set := c.AV.Settings()
	set.DefenderHardening = "enforce"
	if code, _ := admin.do("PUT", "/api/settings/antivirus", set, true); code != 200 {
		t.Fatalf("put settings = %d", code)
	}
	set.DefenderHardening = "block"
	if code, _ := admin.do("PUT", "/api/settings/antivirus", set, true); code != 400 {
		t.Fatalf("bad mode = %d", code)
	}
	c.ReconcileDefenderHardening(ctx)
	if st := c.DefenderHardeningHostState(ctx, "w2"); st.Status != "not_allowed" || !strings.Contains(st.Message, "defender.harden") {
		t.Fatalf("w2: %+v", st)
	}
	if len(commands("w1")) != 1 {
		t.Fatal("w1 got a command though its group sets audit")
	}

	// The group moves to enforce; the agent reports settings Defender kept.
	enforce := "enforce"
	c.State.UpdateGroup(ctx, g.ID, store.GroupUpdate{Policy: &store.GroupPolicy{AV: store.AVGroupPolicy{DefenderHardening: &enforce}}})
	c.ReloadGroups(ctx)
	c.ReconcileDefenderHardening(ctx)
	cs = commands("w1")
	if len(cs) != 2 {
		t.Fatalf("after enforce: %d commands", len(cs))
	}
	json.Unmarshal(cs[0].Params, &p)
	finish(cs[0], api.DefenderHardenResult{Mode: "enforce", Version: p.Version, Message: "enforce: 15 of 16", Failures: []string{"Network Protection: wanted Enabled, Defender reports Disabled"}})
	c.ReconcileDefenderHardening(ctx)
	st := c.DefenderHardeningHostState(ctx, "w1")
	if st.Status != "partial" || len(st.Failures) != 1 || len(commands("w1")) != 2 {
		t.Fatalf("partial: %+v", st)
	}

	// The status route, for viewers.
	code, view := viewer.do("GET", "/api/defender/hardening", nil, false)
	if code != 200 || view["mode"] != "enforce" || len(view["hosts"].([]any)) != 2 {
		t.Fatalf("view = %d %v", code, view)
	}
	for _, x := range view["hosts"].([]any) {
		hh := x.(map[string]any)
		if hh["host_id"] == "w1" && (hh["mode_from"] != "Office" || hh["status"] != "partial") {
			t.Errorf("w1 in view: %v", hh)
		}
		if hh["host_id"] == "w2" && hh["mode_from"] != nil {
			t.Errorf("w2 in view: %v", hh)
		}
	}
	// Groups list the global value and effective setting.
	_, gv := viewer.do("GET", "/api/groups", nil, false)
	if gv["global"].(map[string]any)["defender_hardening"] != "enforce" {
		t.Errorf("groups global = %v", gv["global"])
	}
	// A bad group value is refused.
	bad := map[string]any{"policy": map[string]any{"av": map[string]any{"defender_hardening": "block"}}}
	if code, _ := admin.do("PATCH", "/api/groups/"+g.ID, bad, true); code != 400 {
		t.Fatalf("bad group value = %d", code)
	}

	// Off for the group: hardened w1 gets an off command; the agent puts things back.
	off := "off"
	c.State.UpdateGroup(ctx, g.ID, store.GroupUpdate{Policy: &store.GroupPolicy{AV: store.AVGroupPolicy{DefenderHardening: &off}}})
	c.ReloadGroups(ctx)
	c.ReconcileDefenderHardening(ctx)
	cs = commands("w1")
	if len(cs) != 3 {
		t.Fatalf("after off: %d commands", len(cs))
	}
	json.Unmarshal(cs[0].Params, &p)
	if p.Mode != "off" || p.Version != "off" {
		t.Fatalf("off params %+v", p)
	}
	finish(cs[0], api.DefenderHardenResult{Mode: "off", Version: "off", Message: "removed"})
	c.ReconcileDefenderHardening(ctx)
	c.ReconcileDefenderHardening(ctx)
	if st := c.DefenderHardeningHostState(ctx, "w1"); st.Status != "off" || st.Message != "removed" || len(commands("w1")) != 3 {
		t.Fatalf("after off: %+v, %d commands", st, len(commands("w1")))
	}
}

// Validation on the server: Windows only, a known mode, nothing else.
func TestDefenderHardenParams(t *testing.T) {
	ctx := context.Background()
	c, _ := setup(t)
	w, _ := c.State.CreateEndpoint(ctx, "w1", api.HostInfo{Hostname: "desk", OS: event.OS{Platform: "windows"}}, nil, "1")
	l, _ := c.State.CreateEndpoint(ctx, "l1", api.HostInfo{Hostname: "srv", OS: event.OS{Platform: "linux"}}, nil, "2")
	issue := func(h *store.Host, params string) error {
		_, err := c.IssueCommand(ctx, h, api.CmdDefenderHarden, json.RawMessage(params), "test", "", time.Minute)
		return err
	}
	if err := issue(w, `{"mode":"audit","version":"audit-p1"}`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"mode":"block"}`, `{"mode":"audit","version":"a b"}`, `{"mode":"audit","rules":["x"]}`} {
		var ve *core.ValidationError
		if err := issue(w, bad); err == nil || !errorsAs(err, &ve) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := issue(l, `{"mode":"audit","version":"v"}`); err == nil {
		t.Error("accepted for a Linux host")
	}
}

func errorsAs(err error, ve **core.ValidationError) bool {
	v, ok := err.(*core.ValidationError)
	*ve = v
	return ok
}
