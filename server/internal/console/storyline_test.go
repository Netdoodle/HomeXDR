package console

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestStorylineEndpoint(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("GET", "/api/storyline?host_id=agent-s&entity_id=e-ps", nil, false); code != http.StatusUnauthorized {
		t.Fatalf("signed out = %d", code)
	}
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	host, err := c.State.CreateEndpoint(ctx, "agent-s", api.HostInfo{Hostname: "desk-s", OS: event.OS{Platform: "windows"}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mk := func(entity, parent, parentName, name string, at time.Time) *event.Event {
		return &event.Event{ID: event.NewID(), Timestamp: at,
			Event: event.Meta{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
			Process: &event.Process{EntityID: entity, PID: int64(len(name) * 100), Name: name, Executable: `C:\Windows\System32\` + name,
				Parent: &event.Process{EntityID: parent, Name: parentName}}}
	}
	access := &event.Event{ID: event.NewID(), Timestamp: now,
		Event: event.Meta{Kind: "event", Category: []string{"process"}, Type: []string{"access"}, Action: event.ActionProcessAccess,
			Code: "10", Provider: "Microsoft-Windows-Sysmon"},
		Process: &event.Process{EntityID: "e-ps", Name: "powershell.exe"},
		Target:  &event.Target{Process: &event.Process{EntityID: "e-lsass", Name: "lsass.exe"}, GrantedAccess: "0x1010"}}
	evs := []*event.Event{
		mk("e-explorer", "e-userinit", "userinit.exe", "explorer.exe", now.Add(-4*time.Minute)),
		mk("e-cmd", "e-explorer", "explorer.exe", "cmd.exe", now.Add(-3*time.Minute)),
		mk("e-ps", "e-cmd", "cmd.exe", "powershell.exe", now.Add(-2*time.Minute)),
		mk("e-who", "e-ps", "powershell.exe", "whoami.exe", now.Add(-time.Minute)),
		access,
	}
	if err := c.Ingest(ctx, host, evs); err != nil {
		t.Fatal(err)
	}
	alerts, _, err := c.State.ListAlerts(ctx, store.AlertFilter{HostID: "agent-s"})
	if err != nil || len(alerts) != 1 || alerts[0].ProcessEntityID != "e-who" {
		t.Fatalf("alerts = %+v, %v", alerts, err)
	}

	code, g := admin.do("GET", "/api/storyline?alert_id="+alerts[0].ID, nil, false)
	if code != 200 {
		t.Fatalf("storyline by alert = %d %v", code, g)
	}
	if g["host_id"] != "agent-s" || g["hostname"] != "desk-s" || g["focus_entity_id"] != "e-who" || g["root_entity_id"] != "e-cmd" {
		t.Fatalf("storyline header = %v", g)
	}
	kinds := map[string]bool{}
	for _, e := range g["edges"].([]any) {
		kinds[e.(map[string]any)["kind"].(string)] = true
	}
	if !kinds["parent"] || !kinds["process_access"] {
		t.Errorf("edge kinds = %v", kinds)
	}
	var who map[string]any
	for _, n := range g["nodes"].([]any) {
		if n := n.(map[string]any); n["entity_id"] == "e-who" {
			who = n
		}
	}
	if who == nil || who["focus"] != true || who["alert_count"].(float64) != 1 || who["max_severity"] != "low" ||
		len(who["tactics"].([]any)) != 1 || who["tactics"].([]any)[0] != "discovery" {
		t.Errorf("focus node = %v", who)
	}
	if len(g["alerts"].([]any)) != 1 {
		t.Errorf("alerts = %v", g["alerts"])
	}

	code, g = admin.do("GET", "/api/storyline?host_id=agent-s&entity_id=e-ps&depth=99", nil, false)
	if code != 200 || g["focus_entity_id"] != "e-ps" || g["truncated"] != false {
		t.Fatalf("storyline by process = %d %v", code, g)
	}
	for path, want := range map[string]int{
		"/api/storyline":                                      http.StatusBadRequest,
		"/api/storyline?host_id=agent-s":                      http.StatusBadRequest,
		"/api/storyline?alert_id=nope":                        http.StatusNotFound,
		"/api/storyline?host_id=agent-s&entity_id=e-missing":  http.StatusNotFound,
		"/api/storyline?host_id=agent-x&entity_id=e-ps":       http.StatusNotFound,
		"/api/storyline?host_id=agent-s&entity_id=e-ps&depth": http.StatusOK,
	} {
		if code, body := admin.do("GET", path, nil, false); code != want {
			t.Errorf("%s = %d %v, want %d", path, code, body, want)
		}
	}

	// An alert that is not about a process has no storyline.
	a, _, err := c.State.RecordAlert(ctx, store.AlertInput{Rule: store.AlertRule{ID: "sys", Title: "sys"}, Severity: store.SevLow,
		Event: &event.Event{ID: event.NewID(), Timestamp: now, Host: event.Host{ID: "agent-s"}}, DedupEntity: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := admin.do("GET", "/api/storyline?alert_id="+a.ID, nil, false); code != http.StatusNotFound {
		t.Errorf("alert without a process = %d", code)
	}

	// The process tree is unchanged by cross-process events of the same process.
	code, tree := admin.do("GET", "/api/process-tree?host_id=agent-s&entity_id=e-ps", nil, false)
	if code != 200 || tree["root"].(map[string]any)["entity_id"] != "e-userinit" {
		t.Fatalf("process tree = %d %v", code, tree)
	}
}
