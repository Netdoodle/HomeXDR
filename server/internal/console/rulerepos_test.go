package console

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuleRepoAPI(t *testing.T) {
	_, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true)

	// A release-style zip: rules/ at the top level.
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("rules/windows/whoami_repo.yml")
	w.Write([]byte(strings.Replace(rule, "6f1b1a52-0000-4000-8000-000000000002", "6f1b1a52-0000-4000-8000-0000000000aa", 1)))
	zw.Close()
	pkg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(zbuf.Bytes()) }))
	defer pkg.Close()

	if code, _ := viewer.do("POST", "/api/rule-repos", map[string]any{"url": pkg.URL + "/core.zip"}, true); code != http.StatusForbidden {
		t.Fatalf("viewer add = %d", code)
	}
	if code, body := admin.do("POST", "/api/rule-repos", map[string]any{"url": "ftp://x/y"}, true); code != 400 || body["error"] == nil {
		t.Fatalf("bad URL = %d %v", code, body)
	}
	code, body := admin.do("POST", "/api/rule-repos", map[string]any{"url": pkg.URL + "/core.zip", "auto_update": false}, true)
	if code != 201 || body["kind"] != "archive" || body["name"] != "core" || body["auto_update"] != false || body["enable_rules"] != true {
		t.Fatalf("add = %d %v", code, body)
	}
	id := body["id"].(string)
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body = viewer.do("GET", "/api/rule-repos/"+id, nil, false)
		if body["syncing"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("import did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.HasPrefix(body["version"].(string), "sha256:") || body["rules"].(float64) != 1 || body["error"] != nil {
		t.Fatalf("after import: %v", body)
	}
	if code, list := viewer.do("GET", "/api/rules?source=repo&repo="+id, nil, false); code != 200 || list["total"].(float64) != 1 {
		t.Fatalf("repo rules = %d %v", code, list)
	} else if repo := list["rules"].([]any)[0].(map[string]any)["repo"].(map[string]any); repo["path"] != "rules/windows/whoami_repo.yml" {
		t.Fatalf("rule repo ref = %v", repo)
	}
	if code, body = admin.do("PATCH", "/api/rule-repos/"+id, map[string]any{"min_level": "high", "interval_hours": 6}, true); code != 200 ||
		body["rules"].(float64) != 0 || body["filtered"].(float64) != 1 || body["auto_update"] != false || body["interval_hours"].(float64) != 6 {
		t.Fatalf("patch = %d %v", code, body)
	}
	if code, body = admin.do("POST", "/api/rule-repos/"+id+"/check", nil, true); code != 200 || body["update_available"] != false {
		t.Fatalf("check = %d %v", code, body)
	}
	if code, _ = admin.do("POST", "/api/rule-repos/"+id+"/update", nil, true); code != http.StatusAccepted {
		t.Fatalf("update = %d", code)
	}
	if code, list := viewer.do("GET", "/api/rule-repos", nil, false); code != 200 || len(list["repos"].([]any)) != 1 {
		t.Fatalf("list = %d %v", code, list)
	}
	for i := 0; ; i++ {
		code, _ = admin.do("DELETE", "/api/rule-repos/"+id, nil, true)
		if code != http.StatusConflict || i > 200 { // busy while the update runs
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if code, _ = admin.do("GET", "/api/rule-repos/"+id, nil, false); code != 404 {
		t.Fatalf("get after delete = %d", code)
	}
}
