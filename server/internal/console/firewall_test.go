package console

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func firewallCommands(t *testing.T, c *core.Core, hostID string) []*store.CommandRecord {
	t.Helper()
	cs, err := c.State.ListHostCommands(context.Background(), hostID, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.CommandRecord
	for _, x := range cs {
		if x.Type == api.CmdFirewall {
			out = append(out, x)
		}
	}
	return out // newest first
}

func firewallParams(t *testing.T, rec *store.CommandRecord) api.FirewallParams {
	t.Helper()
	var p api.FirewallParams
	if err := json.Unmarshal(rec.Params, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func rulesString(p api.FirewallParams) string {
	var s []string
	for _, r := range p.Rules {
		s = append(s, r.CIDR+":"+r.Direction)
	}
	return strings.Join(s, " ")
}

// finish reports a firewall.apply as done by the agent.
func finish(t *testing.T, c *core.Core, hostID string, rec *store.CommandRecord) {
	t.Helper()
	ctx := context.Background()
	p := firewallParams(t, rec)
	out, _ := json.Marshal(api.FirewallResult{Version: p.Version, Rules: len(p.Rules), Backend: "nftables", Message: "ok"})
	done, err := c.State.RecordResult(ctx, hostID, api.CommandResult{CommandID: rec.ID, Status: api.StatusCompleted, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := c.State.GetHost(ctx, hostID)
	c.CommandFinished(ctx, h, done)
}

// Block policies reach each host according to its scope: Global blocks everywhere, a
// group's blocks in the group and its child groups, nothing where a group turns host
// firewall control off. Results mark hosts applied; removals send the smaller set.
func TestFirewallReconcile(t *testing.T) {
	ctx := context.Background()
	c, _ := setup(t)
	mkHost := func(id, name, platform string) {
		if _, err := c.State.CreateEndpoint(ctx, id, api.HostInfo{Hostname: name, OS: event.OS{Platform: platform}}, nil, id); err != nil {
			t.Fatal(err)
		}
	}
	mkHost("w1", "desk", "windows")
	mkHost("l1", "srv", "linux")
	mkHost("m1", "mac", "darwin")
	parent, _ := c.State.CreateGroup(ctx, "DTS Assets", "")
	office, _ := c.State.CreateGroup(ctx, "Office", parent.ID)
	lab, _ := c.State.CreateGroup(ctx, "Lab", "")
	off := false
	c.State.UpdateGroup(ctx, lab.ID, store.GroupUpdate{Policy: &store.GroupPolicy{Firewall: store.FirewallGroupPolicy{Enabled: &off}}})
	c.State.SetHostsGroup(ctx, []string{"w1"}, office.ID)
	c.State.SetHostsGroup(ctx, []string{"m1"}, lab.ID)
	c.ReloadGroups(ctx)

	for _, b := range []store.FirewallBlock{
		{CIDR: "203.0.113.0/24", Direction: "both"},                     // everywhere
		{CIDR: "198.51.100.7", Direction: "in", GroupID: parent.ID},     // DTS Assets and Office
		{CIDR: "2001:db8::/48", Direction: "both", GroupID: office.ID},  // Office
		{CIDR: "192.0.2.1", Direction: "both", GroupID: lab.ID},         // Lab, which is off
		{CIDR: "192.0.2.99", Direction: "both", GroupID: "deleted-grp"}, // nowhere
	} {
		b.CreatedBy = "admin"
		if err := c.State.CreateFirewallBlock(ctx, &b); err != nil {
			t.Fatal(err)
		}
	}
	c.ReconcileFirewall(ctx)
	w := firewallCommands(t, c, "w1")
	l := firewallCommands(t, c, "l1")
	if len(w) != 1 || len(l) != 1 || len(firewallCommands(t, c, "m1")) != 0 {
		t.Fatalf("commands: w1 %d, l1 %d, m1 %d", len(w), len(l), len(firewallCommands(t, c, "m1")))
	}
	if got := rulesString(firewallParams(t, w[0])); got != "198.51.100.7:in 2001:db8::/48:both 203.0.113.0/24:both" {
		t.Fatalf("w1 rules = %s", got)
	}
	if got := rulesString(firewallParams(t, l[0])); got != "203.0.113.0/24:both" {
		t.Fatalf("l1 rules = %s", got)
	}
	if st := c.FirewallHostState(ctx, "m1"); st.Status != "off" || st.Enabled || st.EnabledFrom != "Lab" {
		t.Fatalf("m1 = %+v", st)
	}
	c.ReconcileFirewall(ctx) // pending: nothing is sent twice
	if len(firewallCommands(t, c, "w1")) != 1 {
		t.Fatal("sent twice while pending")
	}

	finish(t, c, "w1", w[0])
	c.ReconcileFirewall(ctx)
	st := c.FirewallHostState(ctx, "w1")
	if st.Status != "applied" || st.Applied != firewallParams(t, w[0]).Version || st.AppliedRules != 3 || st.Backend != "nftables" {
		t.Fatalf("w1 after result = %+v", st)
	}
	if len(firewallCommands(t, c, "w1")) != 1 {
		t.Fatal("applied host got another command")
	}

	// Removing the global block sends both hosts their smaller sets: w1 at once, l1 once
	// its first command is done (here: an empty set, which removes everything).
	blocks, _ := c.State.ListFirewallBlocks(ctx)
	for _, b := range blocks {
		if b.CIDR == "203.0.113.0/24" {
			if err := c.RemoveFirewallBlock(ctx, "admin", b.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if w = firewallCommands(t, c, "w1"); len(w) != 2 || rulesString(firewallParams(t, w[0])) != "198.51.100.7:in 2001:db8::/48:both" {
		t.Fatalf("w1 after removal: %d commands", len(w))
	}
	finish(t, c, "l1", l[0])
	c.ReconcileFirewall(ctx)
	if l = firewallCommands(t, c, "l1"); len(l) != 2 || len(firewallParams(t, l[0]).Rules) != 0 || firewallParams(t, l[0]).Version != "none" {
		t.Fatalf("l1 after removal: %d commands", len(l))
	}
	finish(t, c, "l1", l[0])
	c.ReconcileFirewall(ctx)
	if st := c.FirewallHostState(ctx, "l1"); st.Status != "empty" || len(firewallCommands(t, c, "l1")) != 2 {
		t.Fatalf("l1 with nothing to block = %+v", st)
	}

	// A failed apply is retried later, but a new rule set goes out at once.
	failed, _ := c.State.RecordResult(ctx, "w1", api.CommandResult{CommandID: w[0].ID, Status: api.StatusFailed, Error: "nft: no such file"})
	hw, _ := c.State.GetHost(ctx, "w1")
	c.CommandFinished(ctx, hw, failed)
	c.ReconcileFirewall(ctx)
	if st := c.FirewallHostState(ctx, "w1"); st.Status != "failed" || !strings.Contains(st.Message, "nft") || len(firewallCommands(t, c, "w1")) != 2 {
		t.Fatalf("w1 after failure = %+v", st)
	}
	// Office turns host firewall control off: w1 gets the empty set.
	c.State.UpdateGroup(ctx, office.ID, store.GroupUpdate{Policy: &store.GroupPolicy{Firewall: store.FirewallGroupPolicy{Enabled: &off}}})
	c.ReloadGroups(ctx)
	c.ReconcileFirewall(ctx)
	if w = firewallCommands(t, c, "w1"); len(w) != 3 || firewallParams(t, w[0]).Version != "none" {
		t.Fatalf("w1 after turning off: %d commands", len(w))
	}

	// An agent whose local policy leaves firewall.apply out.
	mkHost("l2", "old", "linux")
	if _, err := c.State.Heartbeat(ctx, "l2", api.HostInfo{Hostname: "old", OS: event.OS{Platform: "linux"}},
		api.AgentStatus{AllowedActions: []string{api.CmdProcessKill}}); err != nil {
		t.Fatal(err)
	}
	b := store.FirewallBlock{CIDR: "203.0.113.50", Direction: "both", CreatedBy: "admin"}
	c.State.CreateFirewallBlock(ctx, &b)
	c.ReconcileFirewall(ctx)
	if st := c.FirewallHostState(ctx, "l2"); st.Status != "not_allowed" || len(firewallCommands(t, c, "l2")) != 0 {
		t.Fatalf("l2 = %+v", st)
	}
}

// The routes: viewers read, admins change; addresses are validated strictly and the
// server's own addresses are refused; changes are audited.
func TestFirewallRoutes(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	c.Cfg.ServerNames = []string{"198.51.100.20"} // before the first ServerAddrs call (cached)
	admin := newClient(t, srv)
	admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true)
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("login = %d", code)
	}
	if _, err := c.State.CreateEndpoint(ctx, "w1", api.HostInfo{Hostname: "desk", OS: event.OS{Platform: "windows"}}, nil, "1"); err != nil {
		t.Fatal(err)
	}
	g, _ := c.State.CreateGroup(ctx, "Office", "")
	c.ReloadGroups(ctx)

	code, v := viewer.do("GET", "/api/firewall", nil, false)
	if code != 200 || len(v["blocks"].([]any)) != 0 || v["settings"].(map[string]any)["enabled"] != true ||
		v["limits"].(map[string]any)["max_blocks"].(float64) != api.FirewallMaxRules {
		t.Fatalf("viewer GET = %d %v", code, v)
	}
	if code, _ := viewer.do("POST", "/api/firewall/blocks", map[string]string{"cidr": "203.0.113.9"}, true); code != 403 {
		t.Fatalf("viewer add = %d", code)
	}
	if code, _ := viewer.do("PUT", "/api/settings/firewall", map[string]bool{"enabled": false}, true); code != 403 {
		t.Fatalf("viewer settings = %d", code)
	}

	for cidr, want := range map[string]string{
		"0.0.0.0/0":       "too broad",
		"::/0":            "too broad",
		"10.0.0.0/7":      "too broad",
		"2001:db8::/31":   "too broad",
		"127.0.0.1":       "loopback",
		"fe80::1":         "link-local",
		"198.51.100.20":   "HomeXDR server",
		"198.51.100.0/24": "HomeXDR server",
		"not an address":  "not an IP",
	} {
		code, b := admin.do("POST", "/api/firewall/blocks", map[string]string{"cidr": cidr}, true)
		if code != 400 || !strings.Contains(b["error"].(string), want) {
			t.Errorf("%s = %d %v, want %q", cidr, code, b, want)
		}
	}
	if code, b := admin.do("POST", "/api/firewall/blocks", map[string]string{"cidr": "203.0.113.9", "group_id": "nope"}, true); code != 400 {
		t.Fatalf("unknown group = %d %v", code, b)
	}
	code, v = admin.do("POST", "/api/firewall/blocks", map[string]string{"cidr": "203.0.113.9", "note": "Alert: beacon", "alert_id": "a1"}, true)
	if code != 200 || len(v["blocks"].([]any)) != 1 {
		t.Fatalf("add = %d %v", code, v)
	}
	blk := v["blocks"].([]any)[0].(map[string]any)
	if blk["cidr"] != "203.0.113.9" || blk["direction"] != "both" || blk["created_by"] != "admin" || blk["scope"] != "Global" || blk["alert_id"] != "a1" {
		t.Fatalf("block = %v", blk)
	}
	// Adding sends the host its rules at once.
	if hosts := v["hosts"].([]any); len(hosts) != 1 || hosts[0].(map[string]any)["status"] != "pending" {
		t.Fatalf("hosts = %v", hosts)
	}
	if code, b := admin.do("POST", "/api/firewall/blocks", map[string]string{"cidr": "203.0.113.9/32"}, true); code != 400 || !strings.Contains(b["error"].(string), "already blocked") {
		t.Fatalf("duplicate = %d %v", code, b)
	}
	if code, _ := admin.do("POST", "/api/firewall/blocks", map[string]string{"cidr": "203.0.113.9", "group_id": g.ID, "direction": "out"}, true); code != 200 {
		t.Fatalf("same address in a group = %d", code)
	}
	if code, _ := admin.do("POST", "/api/firewall/blocks", map[string]string{"cidr": "203.0.113.10", "direction": "sideways"}, true); code != 400 {
		t.Fatalf("bad direction = %d", code)
	}
	// Hand-sent firewall.apply is refused: the reconcile loop owns the rule set.
	if code, _ := admin.do("POST", "/api/hosts/w1/actions", map[string]any{"type": api.CmdFirewall, "params": map[string]any{"version": "x", "rules": []any{}}}, true); code != 400 {
		t.Fatalf("hand-sent firewall.apply = %d", code)
	}

	if code, _ := viewer.do("DELETE", "/api/firewall/blocks/"+blk["id"].(string), nil, true); code != 403 {
		t.Fatalf("viewer delete = %d", code)
	}
	if code, v = admin.do("DELETE", "/api/firewall/blocks/"+blk["id"].(string), nil, true); code != 200 || len(v["blocks"].([]any)) != 1 {
		t.Fatalf("delete = %d %v", code, v)
	}
	if code, _ := admin.do("DELETE", "/api/firewall/blocks/"+blk["id"].(string), nil, true); code != 404 {
		t.Fatalf("delete again = %d", code)
	}
	if code, v = admin.do("PUT", "/api/settings/firewall", map[string]bool{"enabled": false}, true); code != 200 || v["settings"].(map[string]any)["enabled"] != false {
		t.Fatalf("settings = %d %v", code, v)
	}
	_, gv := admin.do("GET", "/api/groups", nil, false)
	if gv["global"].(map[string]any)["firewall"] != false {
		t.Fatalf("groups global = %v", gv["global"])
	}

	entries, _, _ := c.State.ListAudit(ctx, 50, 0)
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, a := range []string{"firewall.block.add", "firewall.block.remove", "settings.firewall"} {
		if !seen[a] {
			t.Errorf("no %s audit entry", a)
		}
	}
}
