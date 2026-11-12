package console

import (
	"context"
	"testing"

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
