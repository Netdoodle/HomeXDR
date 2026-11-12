package yarasvc

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const forgeHead = `/*
 * YARA-Forge YARA Rule Package
 * https://github.com/YARAHQ/yara-forge
 *
 * Rule Package Information
 * Name: core
 * Creation Date: 2026-11-08
 */
import "pe"

private rule Helper { condition: true }
rule A_Malware : FILE {
	strings: $a = "rule fake_in_string"
	condition: $a and Helper
}
  global private rule G { condition: true }
rule B_Other { condition: false }
`

func TestParsers(t *testing.T) {
	if n := CountRules([]byte(forgeHead)); n != 2 {
		t.Errorf("CountRules = %d, want 2", n)
	}
	if p := PackageName([]byte(forgeHead)); p != "YARA Forge core 2026-11-08" {
		t.Errorf("PackageName = %q", p)
	}
	if p := PackageName([]byte("rule x { condition: true }")); p != "" {
		t.Errorf("PackageName of a plain file = %q", p)
	}
	path := "/var/lib/homexdr-yara/tmp/scan-1"
	out := "forge:A_Malware " + path + "\ncustom:Mine " + path + "\nforge:A_Malware " + path + "\n\n"
	ms := ParseOutput([]byte(out), path)
	if len(ms) != 2 || ms[0] != (Match{"forge", "A_Malware"}) || ms[1] != (Match{"custom", "Mine"}) {
		t.Errorf("ParseOutput = %+v", ms)
	}
	if ms := ParseOutput(nil, "/x"); ms == nil || len(ms) != 0 {
		t.Errorf("empty output = %#v", ms)
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		w, _ := zw.Create(name)
		io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRulesFromZip(t *testing.T) {
	got, err := RulesFromZip(zipOf(t, map[string]string{"packages/core/yara-rules-core.yar": forgeHead, "README.md": "x"}))
	if err != nil || string(got) != forgeHead {
		t.Fatalf("RulesFromZip: %v", err)
	}
	if _, err := RulesFromZip(zipOf(t, map[string]string{"a.txt": "x"})); err == nil {
		t.Error("a zip without rules was accepted")
	}
	if _, err := RulesFromZip([]byte("not a zip")); err == nil {
		t.Error("garbage was accepted")
	}
}

// TestService runs the whole service against the real yara tools when they are
// installed (CI installs them; so does the container image).
func TestService(t *testing.T) {
	if _, err := exec.LookPath("yarac"); err != nil {
		t.Skip("yara is not installed")
	}
	dir, custom := t.TempDir(), t.TempDir()
	pkg := zipOf(t, map[string]string{"packages/core/yara-rules-core.yar": forgeHead +
		"rule Forge_Marker { strings: $a = \"FORGE-MARKER-1\" condition: $a }\n"})
	var downloads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads++
		w.Write(pkg)
	}))
	defer srv.Close()
	os.WriteFile(filepath.Join(custom, "mine.yar"), []byte("rule Custom_Marker { strings: $a = \"CUSTOM-MARKER-1\" condition: $a }\n"), 0o644)

	s := New(Config{DataDir: dir, CustomDir: custom, ForgeURL: srv.URL}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if !st.OK || st.Rules != 4 || st.CustomFiles != 1 || st.Package != "YARA Forge core 2026-11-08" || downloads != 1 {
		t.Fatalf("status %+v, downloads %d", st, downloads)
	}
	h := httptest.NewServer(s.Handler())
	defer h.Close()
	scan := func(body string) map[string]bool {
		resp, err := http.Post(h.URL+"/scan", "application/octet-stream", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scan: HTTP %d %s", resp.StatusCode, b)
		}
		got := map[string]bool{}
		for _, m := range parseJSONMatches(t, b) {
			got[m.Namespace+":"+m.Rule] = true
		}
		return got
	}
	if got := scan("x FORGE-MARKER-1 CUSTOM-MARKER-1 x"); len(got) != 2 || !got["forge:Forge_Marker"] || !got["custom:Custom_Marker"] {
		t.Fatalf("scan = %v", got)
	}
	if got := scan("clean"); len(got) != 0 {
		t.Fatalf("clean scan = %v", got)
	}

	// A broken custom rule: the package still loads and the error is reported.
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(custom, "broken.yara"), []byte("rule Broken { condition: $nope }\n"), 0o644)
	s.refresh(ctx, false)
	st = s.Status()
	if !st.OK || st.CustomFiles != 0 || st.CustomError == "" || st.Rules != 3 {
		t.Fatalf("after broken rule: %+v", st)
	}
	if got := scan("CUSTOM-MARKER-1 FORGE-MARKER-1"); len(got) != 1 || !got["forge:Forge_Marker"] {
		t.Fatalf("scan after broken rule = %v", got)
	}
}

func parseJSONMatches(t *testing.T, b []byte) []Match {
	t.Helper()
	var r ScanResult
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("scan reply %s: %v", b, err)
	}
	return r.Matches
}
