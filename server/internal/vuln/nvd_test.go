package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const unraidKEV = `{"catalogVersion":"x","count":1,"vulnerabilities":[
 {"cveID":"CVE-2020-5847","vendorProject":"Unraid","product":"Unraid","vulnerabilityName":"Unraid Remote Code Execution","dateAdded":"2022-03-25","shortDescription":"Unraid contains a vulnerability due to the insecure use of the extract PHP function.","dueDate":"2022-04-15","knownRansomwareCampaignUse":"Unknown"}]}`

const nvdReply = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-9772",
 "descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"Unraid FileUpload.php command injection. More text."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`

func TestNVDSettlesUnraidByVersion(t *testing.T) {
	r := newRig(t, "Unraid OS", "7.2.8")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, kevFileName), []byte(unraidKEV), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := parseCatalog(filepath.Join(dir, kevFileName))
	if err != nil {
		t.Fatal(err)
	}
	r.s.kev.Store(c)
	var calls atomic.Int32
	var gotCPE string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		gotCPE = req.URL.Query().Get("cpeName")
		_, _ = w.Write([]byte(nvdReply))
	}))
	defer srv.Close()
	r.s.NVDURL = srv.URL
	r.snapshot(r.now, pkg{name: "sudo", version: "1.9", typ: "slackware"})

	// Off: the name match stands and nothing is sent.
	list := r.scan()
	if calls.Load() != 0 || find(list, "Unraid OS", "CVE-2020-5847") == nil {
		t.Fatalf("calls=%d %+v", calls.Load(), list)
	}

	// On: the 2020 flaw (through 6.8.0) is dropped, and the 2026 one NVD lists is added.
	if err := r.s.SaveSettings(context.Background(), Settings{OSV: true}); err != nil {
		t.Fatal(err)
	}
	list = r.scan()
	if gotCPE != "cpe:2.3:o:unraid:unraid:7.2.8:*:*:*:*:*:*:*" {
		t.Fatalf("cpe %q", gotCPE)
	}
	if f := find(list, "Unraid OS", "CVE-2020-5847"); f != nil && f.Status == "open" {
		t.Errorf("stale match still open: %+v", f)
	}
	f := find(list, "Unraid OS", "CVE-2026-9772")
	if f == nil || f.Confidence != Confirmed || f.CVSS == nil || *f.CVSS != 8.8 || f.AttackVector != "network" || f.SeveritySource != "nvd" {
		t.Fatalf("%+v", f)
	}
	if !strings.HasPrefix(f.Title, "Unraid FileUpload.php") {
		t.Errorf("title %q", f.Title)
	}

	// A second scan uses the cache.
	r.scan()
	if calls.Load() != 1 {
		t.Errorf("calls=%d", calls.Load())
	}

	// NVD down: nothing breaks.
	srv.Close()
	r.s.nvdCache = nil
	r.scan()
}
