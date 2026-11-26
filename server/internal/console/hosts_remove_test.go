package console

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/totp"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestRemoveHost(t *testing.T) {
	ctx := context.Background()
	e := newMFAEnv(t)
	c := e.h.c
	host, err := c.State.CreateEndpoint(ctx, "h-remove", api.HostInfo{Hostname: "Doomed-PC", OS: event.OS{Platform: "linux"}}, []string{"lab"}, "ab12")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := c.State.CreateCommand(ctx, host.ID, api.CmdFileHash, []byte(`{}`), "admin", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	upload := filepath.Join(t.TempDir(), "up.bin")
	os.WriteFile(upload, []byte("x"), 0o600)
	if err := c.State.SetUpload(ctx, rec.ID, upload, "up.bin"); err != nil {
		t.Fatal(err)
	}

	path := "/api/hosts/" + host.ID + "/remove"
	good := func() string { return totp.Code(e.secret, at(0)) }

	// An analyst or viewer cannot.
	if code, _ := e.admin.do("POST", "/api/users", map[string]string{"username": "ana", "password": "another long password", "role": "analyst"}, true); code != 201 && code != 200 {
		t.Fatalf("create analyst = %d", code)
	}
	ana := newClient(t, e.srv)
	if code, _ := ana.do("POST", "/api/auth/login", map[string]string{"username": "ana", "password": "another long password"}, true); code != 200 {
		t.Fatalf("analyst login = %d", code)
	}
	if code, _ := ana.do("POST", path, map[string]string{"totp_code": good(), "confirm_hostname": "Doomed-PC"}, true); code != http.StatusForbidden {
		t.Fatalf("analyst remove = %d", code)
	}
	// Wrong hostname, and no code burned.
	if code, _ := e.admin.do("POST", path, map[string]string{"totp_code": good(), "confirm_hostname": "other"}, true); code != http.StatusBadRequest {
		t.Fatalf("wrong hostname = %d", code)
	}
	// Wrong code.
	if code, _ := e.admin.do("POST", path, map[string]string{"totp_code": "000000", "confirm_hostname": "Doomed-PC"}, true); code != http.StatusForbidden {
		t.Fatalf("wrong code = %d", code)
	}
	// A recovery code is not an authenticator code.
	if code, _ := e.admin.do("POST", path, map[string]string{"totp_code": e.codes[0], "confirm_hostname": "Doomed-PC"}, true); code != http.StatusForbidden {
		t.Fatalf("recovery code = %d", code)
	}
	if _, err := c.State.GetHost(ctx, host.ID); err != nil {
		t.Fatalf("host gone after refused requests: %v", err)
	}
	// Unknown host.
	if code, _ := e.admin.do("POST", "/api/hosts/nope/remove", map[string]string{"totp_code": good(), "confirm_hostname": "x"}, true); code != http.StatusNotFound {
		t.Fatalf("unknown host = %d", code)
	}

	code, body := e.admin.do("POST", path, map[string]string{"totp_code": good(), "confirm_hostname": "doomed-pc"}, true)
	if code != http.StatusNoContent {
		t.Fatalf("remove = %d %v", code, body)
	}
	if _, err := c.State.GetHost(ctx, host.ID); err != store.ErrNotFound {
		t.Fatalf("host still there: %v", err)
	}
	if cmds, _ := c.State.ListHostCommands(ctx, host.ID, 10); len(cmds) != 0 {
		t.Fatalf("commands kept: %v", cmds)
	}
	if _, err := os.Stat(upload); !os.IsNotExist(err) {
		t.Fatalf("uploaded file kept: %v", err)
	}
	audit, _, _ := c.State.ListAudit(ctx, 50, 0)
	found := false
	for _, a := range audit {
		if a.Action == "host.remove" && a.Target == host.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("no host.remove audit entry")
	}
	if code, _ := e.admin.do("GET", "/api/hosts/"+host.ID, nil, false); code != http.StatusNotFound {
		t.Fatalf("get removed = %d", code)
	}
}

func TestRemoveHostNeedsTOTPAndReplayIsRefused(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": adminPW}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if _, err := c.State.CreateEndpoint(ctx, "h1", api.HostInfo{Hostname: "pc", OS: event.OS{Platform: "linux"}}, nil, ""); err != nil {
		t.Fatal(err)
	}
	code, body := admin.do("POST", "/api/hosts/h1/remove", map[string]string{"totp_code": "123456", "confirm_hostname": "pc"}, true)
	if code != http.StatusForbidden || !strings.Contains(body["error"].(string), "two-factor") {
		t.Fatalf("without two-factor = %d %v", code, body)
	}
	if _, err := c.State.GetHost(ctx, "h1"); err != nil {
		t.Fatal("host removed without two-factor")
	}

	e := newMFAEnv(t)
	for _, id := range []string{"r1", "r2"} {
		if _, err := e.h.c.State.CreateEndpoint(ctx, id, api.HostInfo{Hostname: id, OS: event.OS{Platform: "linux"}}, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	codeNow := totp.Code(e.secret, at(0))
	if code, _ := e.admin.do("POST", "/api/hosts/r1/remove", map[string]string{"totp_code": codeNow, "confirm_hostname": "r1"}, true); code != http.StatusNoContent {
		t.Fatalf("first remove = %d", code)
	}
	if code, _ := e.admin.do("POST", "/api/hosts/r2/remove", map[string]string{"totp_code": codeNow, "confirm_hostname": "r2"}, true); code != http.StatusForbidden {
		t.Fatalf("a code used once must not work again: %d", code)
	}
	// Repeated wrong codes are rate limited.
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		code, _ := e.admin.do("POST", "/api/hosts/r2/remove", map[string]string{"totp_code": "000000", "confirm_hostname": "r2"}, true)
		limited = code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("wrong codes were never rate limited")
	}
}

func TestHostApplicationsAndRescan(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin, viewer := signedIn(t, srv)
	if _, err := c.State.CreateEndpoint(ctx, "h1", api.HostInfo{Hostname: "pc", OS: event.OS{Platform: "linux"}}, nil, ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var evs []*event.Event
	for _, p := range []event.Package{{Name: "zlib", Version: "1", Type: "deb", Architecture: "amd64"}, {Name: "Bash", Version: "5", Type: "deb"}, {Name: "Bash", Version: "5", Type: "deb"}} {
		p := p
		evs = append(evs, &event.Event{ID: event.NewID(), Timestamp: now, Host: event.Host{ID: "h1", Name: "pc"},
			Event:   event.Meta{Kind: event.KindState, Module: event.ModuleInventory, Dataset: "inventory.software.list"},
			Package: &p})
	}
	if err := c.Events.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	code, body := viewer.do("GET", "/api/hosts/h1/applications", nil, false)
	apps, _ := body["applications"].([]any)
	if code != 200 || len(apps) != 2 || apps[0].(map[string]any)["name"] != "Bash" || body["reported_at"] == nil {
		t.Fatalf("applications = %d %v", code, body)
	}
	if code, _ := viewer.do("GET", "/api/hosts/nope/applications", nil, false); code != 404 {
		t.Fatalf("unknown host = %d", code)
	}
	if code, _ := viewer.do("POST", "/api/hosts/h1/vuln-rescan", nil, true); code != http.StatusForbidden {
		t.Fatalf("viewer rescan = %d", code)
	}
	if code, body := admin.do("POST", "/api/hosts/h1/vuln-rescan", nil, true); code != http.StatusAccepted || body["scope"] != "all" {
		t.Fatalf("rescan = %d %v", code, body)
	}
}
