package console

import (
	"context"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Netdoodle > DTS Assets > Marketing Dept, Netdoodle > Infrastructure Assets > Linux
// Servers: scanner switches inherit down the tree and the nearest setting wins.
func TestGroups(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)
	admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true)

	if code, b := admin.do("PUT", "/api/org", map[string]string{"name": "Netdoodle"}, true); code != 200 || b["org"].(map[string]any)["name"] != "Netdoodle" {
		t.Fatalf("org = %d %v", code, b)
	}
	ids := map[string]string{}
	mk := func(name, parent string) {
		t.Helper()
		code, b := admin.do("POST", "/api/groups", map[string]string{"name": name, "parent_id": ids[parent]}, true)
		if code != 200 {
			t.Fatalf("create %s = %d %v", name, code, b)
		}
		for _, g := range b["groups"].([]any) {
			g := g.(map[string]any)
			if g["name"] == name {
				ids[name] = g["id"].(string)
			}
		}
	}
	mk("DTS Assets", "")
	mk("Marketing Dept", "DTS Assets")
	mk("Infrastructure Assets", "")
	mk("Linux Servers", "Infrastructure Assets")
	if code, _ := admin.do("POST", "/api/groups", map[string]string{"name": "Too Deep", "parent_id": ids["Marketing Dept"]}, true); code != 400 {
		t.Fatalf("third level = %d", code)
	}
	if code, _ := admin.do("POST", "/api/groups", map[string]string{"name": "dts assets"}, true); code != 400 {
		t.Fatalf("duplicate name = %d", code)
	}

	// DTS Assets turns YARA off; Marketing Dept turns it back on and ClamAV off.
	off, on := false, true
	admin.do("PATCH", "/api/groups/"+ids["DTS Assets"], map[string]any{"policy": map[string]any{"av": map[string]any{"yara": off}}}, true)
	admin.do("PATCH", "/api/groups/"+ids["Marketing Dept"], map[string]any{"policy": map[string]any{"av": map[string]any{"yara": on, "clamav": off}}}, true)
	_, b := admin.do("GET", "/api/groups", nil, false)
	eff := map[string]map[string]any{}
	for _, g := range b["groups"].([]any) {
		g := g.(map[string]any)
		eff[g["name"].(string)] = g["effective"].(map[string]any)
	}
	val := func(group, scanner string) (bool, string) {
		s := eff[group][scanner].(map[string]any)
		from, _ := s["group_name"].(string)
		return s["value"].(bool), from
	}
	for _, c := range []struct {
		group, scanner string
		want           bool
		from           string
	}{
		{"DTS Assets", "yara", false, "DTS Assets"},
		{"DTS Assets", "clamav", true, ""},
		{"Marketing Dept", "yara", true, "Marketing Dept"},
		{"Marketing Dept", "clamav", false, "Marketing Dept"},
		{"Linux Servers", "yara", true, ""},
	} {
		if v, from := val(c.group, c.scanner); v != c.want || from != c.from {
			t.Errorf("%s %s = %v from %q, want %v from %q", c.group, c.scanner, v, from, c.want, c.from)
		}
	}
	// Global switches apply where no group decides.
	set := c.AV.Settings()
	set.UseYARA = false
	if _, err := c.AV.Save(ctx, set); err != nil {
		t.Fatal(err)
	}
	if got := c.ResolveAV(ids["Linux Servers"]); got.YARA.Value || got.YARA.GroupID != "" {
		t.Errorf("global off: %+v", got.YARA)
	}
	if got := c.ResolveAV(ids["Marketing Dept"]); !got.YARA.Value {
		t.Errorf("Marketing Dept keeps its own on: %+v", got.YARA)
	}

	// Hosts: move into a group, and back to the parent when the group is deleted.
	if _, err := c.State.CreateEndpoint(ctx, "h1", api.HostInfo{Hostname: "mkt-1", OS: event.OS{Platform: "windows"}}, nil, "1"); err != nil {
		t.Fatal(err)
	}
	if code, b := admin.do("PUT", "/api/hosts/group", map[string]any{"host_ids": []string{"h1"}, "group_id": ids["Marketing Dept"]}, true); code != 200 {
		t.Fatalf("move host = %d %v", code, b)
	}
	if h, _ := c.State.GetHost(ctx, "h1"); h.GroupID != ids["Marketing Dept"] {
		t.Fatalf("host group = %q", h.GroupID)
	}
	if code, _ := admin.do("DELETE", "/api/groups/"+ids["DTS Assets"], nil, true); code != 400 {
		t.Fatalf("delete a group with child groups = %d", code)
	}
	if code, _ := admin.do("DELETE", "/api/groups/"+ids["Marketing Dept"], nil, true); code != 200 {
		t.Fatalf("delete = %d", code)
	}
	if h, _ := c.State.GetHost(ctx, "h1"); h.GroupID != ids["DTS Assets"] {
		t.Fatalf("host after delete = %q", h.GroupID)
	}
	if got := c.ResolveAV(ids["DTS Assets"]); got.YARA.Value || got.YARA.GroupName != "DTS Assets" {
		t.Errorf("DTS Assets after delete: %+v", got)
	}
}

// Enrollment tokens with a group, ?group= filters on hosts and alerts, and the response
// and AI overrides.
func TestGroupsFiltersAndPolicies(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)
	admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true)
	parent, err := c.State.CreateGroup(ctx, "Infrastructure Assets", "")
	if err != nil {
		t.Fatal(err)
	}
	child, _ := c.State.CreateGroup(ctx, "Linux Servers", parent.ID)
	c.ReloadGroups(ctx)

	code, tok := admin.do("POST", "/api/enrollment-tokens", map[string]any{"name": "linux", "group_id": child.ID}, true)
	if code != 201 || tok["group_id"] != child.ID {
		t.Fatalf("token = %d %v", code, tok)
	}
	if code, _ := admin.do("POST", "/api/enrollment-tokens", map[string]any{"name": "bad", "group_id": "nope"}, true); code != 400 {
		t.Fatalf("token with a missing group = %d", code)
	}
	toks, _ := c.State.ListTokens(ctx)
	if len(toks) != 1 || toks[0].GroupID != child.ID {
		t.Fatalf("stored token = %+v", toks)
	}

	for _, h := range []struct{ id, name, group string }{{"h1", "web-1", child.ID}, {"h2", "infra-1", parent.ID}, {"h3", "loose", ""}} {
		if _, err := c.State.CreateEndpoint(ctx, h.id, api.HostInfo{Hostname: h.name, OS: event.OS{Platform: "linux"}}, nil, h.id); err != nil {
			t.Fatal(err)
		}
		c.State.SetHostsGroup(ctx, []string{h.id}, h.group)
		ev := &event.Event{ID: event.NewID(), Host: event.Host{ID: h.id, Name: h.name}}
		c.State.RecordAlert(ctx, store.AlertInput{Rule: store.AlertRule{ID: "r", Title: "r"}, Severity: store.SevLow, Event: ev})
	}
	count := func(path string) int {
		t.Helper()
		code, b := admin.do("GET", path, nil, false)
		if code != 200 {
			t.Fatalf("%s = %d", path, code)
		}
		return int(b["total"].(float64))
	}
	if n := count("/api/hosts?group=" + parent.ID); n != 2 {
		t.Errorf("hosts in the parent group and its child = %d", n)
	}
	if n := count("/api/hosts?group=" + child.ID); n != 1 {
		t.Errorf("hosts in the child group = %d", n)
	}
	if n := count("/api/hosts?group=none"); n != 1 {
		t.Errorf("hosts in no group = %d", n)
	}
	if n := count("/api/alerts?group=" + parent.ID); n != 2 {
		t.Errorf("alerts in the parent group = %d", n)
	}

	// Response and AI overrides inherit like the scanners.
	alert, off := "alert", false
	if code, b := admin.do("PATCH", "/api/groups/"+parent.ID, map[string]any{"policy": map[string]any{"av": map[string]any{"action": alert}, "ai": map[string]any{"auto": off}}}, true); code != 200 {
		t.Fatalf("policy = %d %v", code, b)
	}
	if code, _ := admin.do("PATCH", "/api/groups/"+parent.ID, map[string]any{"policy": map[string]any{"av": map[string]any{"action": "nuke"}}}, true); code != 400 {
		t.Fatalf("bad action = %d", code)
	}
	e := c.ResolveAV(child.ID)
	if e.Action.Value != "alert" || e.Action.GroupName != "Infrastructure Assets" || e.AIAuto.Value {
		t.Fatalf("child = %+v", e)
	}
	if e := c.ResolveAV(""); e.Action.Value != "quarantine" || !e.AIAuto.Value {
		t.Fatalf("global = %+v", e)
	}
}
