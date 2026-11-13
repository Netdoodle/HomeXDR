package console

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// The App Control loop: confirmed malware with Authenticode hashes reaches Windows hosts
// whose group enforces App Control; the agent's result marks the host applied; turning
// it off sends a removal; quarantines record Authenticode hashes.
func TestAppControlReconcile(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)
	admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true)

	win := api.HostInfo{Hostname: "desk", OS: event.OS{Platform: "windows"}}
	if _, err := c.State.CreateEndpoint(ctx, "w1", win, nil, "1"); err != nil {
		t.Fatal(err)
	}
	c.State.CreateEndpoint(ctx, "l1", api.HostInfo{Hostname: "srv", OS: event.OS{Platform: "linux"}}, nil, "2")
	g, _ := c.State.CreateGroup(ctx, "Office", "")
	c.State.SetHostsGroup(ctx, []string{"w1"}, g.ID)
	c.ReloadGroups(ctx)
	a256, a1 := strings.Repeat("a", 64), strings.Repeat("b", 40)
	c.State.PutAVVerdict(ctx, &store.AVVerdict{SHA256: strings.Repeat("1", 64), Verdict: store.AVMalicious, Source: "clamav",
		Signature: "Win.Trojan.X", Path: `C:\Users\a\evil.exe`, AuthSHA256: a256, AuthSHA1: a1})
	// A hacking tool and a clean file never join the block list.
	c.State.PutAVVerdict(ctx, &store.AVVerdict{SHA256: strings.Repeat("2", 64), Verdict: store.AVMalicious, Source: "yara:tool", AuthSHA256: strings.Repeat("c", 64)})
	c.State.PutAVVerdict(ctx, &store.AVVerdict{SHA256: strings.Repeat("3", 64), Verdict: store.AVClean, Source: "clamav", AuthSHA256: strings.Repeat("d", 64)})

	commands := func() []*store.CommandRecord {
		cs, _ := c.State.ListHostCommands(ctx, "w1", 50)
		var out []*store.CommandRecord
		for _, x := range cs {
			if x.Type == api.CmdAppControl {
				out = append(out, x)
			}
		}
		return out
	}
	// Off everywhere (the default): nothing is sent.
	c.ReconcileAppControl(ctx)
	if n := len(commands()); n != 0 {
		t.Fatalf("commands while off: %d", n)
	}
	enforce := "enforce"
	if _, err := c.State.UpdateGroup(ctx, g.ID, store.GroupUpdate{Policy: &store.GroupPolicy{AV: store.AVGroupPolicy{AppControl: &enforce}}}); err != nil {
		t.Fatal(err)
	}
	c.ReloadGroups(ctx)
	c.ReconcileAppControl(ctx)
	cs := commands()
	if len(cs) != 1 {
		t.Fatalf("commands = %d", len(cs))
	}
	var p api.AppControlParams
	json.Unmarshal(cs[0].Params, &p)
	if p.Mode != "enforce" || len(p.Rules) != 1 || p.Rules[0].SHA256 != a256 || p.Rules[0].SHA1 != a1 || !strings.Contains(p.Rules[0].Name, "evil.exe") {
		t.Fatalf("params = %+v", p)
	}
	c.ReconcileAppControl(ctx) // pending: not sent again
	if len(commands()) != 1 {
		t.Fatal("sent twice while pending")
	}
	// The agent reports success.
	out, _ := json.Marshal(api.AppControlResult{Mode: "enforce", Version: p.Version, Rules: 1, Message: "ok"})
	rec, err := c.State.RecordResult(ctx, "w1", api.CommandResult{CommandID: cs[0].ID, Status: api.StatusCompleted, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := c.State.GetHost(ctx, "w1")
	c.CommandFinished(ctx, h, rec)
	c.ReconcileAppControl(ctx)
	if st := c.AppControlHostState(ctx, "w1"); st.Status != "applied" || st.Applied != p.Version || len(commands()) != 1 {
		t.Fatalf("after success: %+v, %d commands", st, len(commands()))
	}
	code, view := admin.do("GET", "/api/appcontrol", nil, false)
	if code != 200 || len(view["rules"].([]any)) != 1 || len(view["hosts"].([]any)) != 1 {
		t.Fatalf("view = %d %v", code, view)
	}

	// A quarantined blocklisted file records its hashes and joins the block list.
	blocked := strings.Repeat("4", 64)
	set := c.AV.Settings()
	set.BlockedHashes = []string{blocked}
	c.AV.Save(ctx, set)
	qout, _ := json.Marshal(api.QuarantineResult{ID: "q", OriginalPath: `C:\x\bad.exe`, SHA256: blocked, AuthSHA256: strings.Repeat("e", 64), AuthSHA1: strings.Repeat("f", 40)})
	c.CommandFinished(ctx, h, &store.CommandRecord{Type: api.CmdFileQuarantine, Status: api.StatusCompleted, Output: qout})
	if v, err := c.State.GetAVVerdict(ctx, blocked); err != nil || v.AuthSHA256 != strings.Repeat("e", 64) {
		t.Fatalf("blocklisted verdict = %+v, %v", v, err)
	}
	// A file quarantined by hand without a verdict is not added.
	hand := strings.Repeat("5", 64)
	qout, _ = json.Marshal(api.QuarantineResult{ID: "q2", SHA256: hand, AuthSHA256: strings.Repeat("9", 64)})
	c.CommandFinished(ctx, h, &store.CommandRecord{Type: api.CmdFileQuarantine, Status: api.StatusCompleted, Output: qout})
	if _, err := c.State.GetAVVerdict(ctx, hand); err == nil {
		t.Fatal("a hand-quarantined file joined the block list")
	}
	// The list changed: a new version goes out.
	c.ReconcileAppControl(ctx)
	if cs := commands(); len(cs) != 2 {
		t.Fatalf("after the list grew: %d commands", len(cs))
	} else {
		var p2 api.AppControlParams
		json.Unmarshal(cs[0].Params, &p2)
		if len(p2.Rules) != 2 {
			t.Fatalf("second policy = %+v", p2)
		}
	}
}
