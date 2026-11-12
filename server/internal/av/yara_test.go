package av

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeYara matches files containing "YARA-MAL", "YARA-TOOL" or "YARA-SUSP", and fails on
// "YARA-FAIL".
func fakeYara(t *testing.T) *Yara {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "yara_version": "4.5.4", "rules": 5128, "package": "YARA Forge core 2026-11-08"})
		case "/scan":
			b, _ := io.ReadAll(r.Body)
			if bytes.Contains(b, []byte("YARA-FAIL")) {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
				return
			}
			ms := []YaraMatch{}
			if bytes.Contains(b, []byte("YARA-SUSP")) {
				ms = append(ms, YaraMatch{"forge", "DITEKSHEN_INDICATOR_EXE_Packed_Themida"})
			}
			if bytes.Contains(b, []byte("YARA-TOOL")) {
				ms = append(ms, YaraMatch{"forge", "SIGNATURE_BASE_HKTL_Mimikatz"})
			}
			if bytes.Contains(b, []byte("YARA-MAL")) {
				ms = append(ms, YaraMatch{"forge", "MALPEDIA_Win_Agent_Tesla_Auto"})
			}
			json.NewEncoder(w).Encode(map[string]any{"matches": ms})
		}
	}))
	t.Cleanup(srv.Close)
	return NewYara(srv.Listener.Addr().String())
}

func TestYaraClass(t *testing.T) {
	for rule, want := range map[string]string{
		"MALPEDIA_Win_Emotet_Auto":                 SourceYara,
		"SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel": SourceYara,
		"SIGNATURE_BASE_HKTL_NET_GUID_Sharpexec":   SourceYaraTool,
		"FIREEYE_RT_Hacktool_MSIL_Wmisharp_1":      SourceYaraTool,
		"DITEKSHEN_INDICATOR_TOOL_Backstab":        SourceYaraTool,
		"SEKOIA_Tool_Safetykatz":                   SourceYaraTool,
		"DITEKSHEN_INDICATOR_RMM_Dwagent":          SourceYaraSuspicious,
		"SIGNATURE_BASE_SUSP_PS1_JAB_Pattern":      SourceYaraSuspicious,
		"Custom_Marker":                            SourceYara,
	} {
		if got := YaraClass(rule); got != want {
			t.Errorf("YaraClass(%s) = %s, want %s", rule, got, want)
		}
	}
	src, sig := yaraVerdict([]YaraMatch{{"forge", "SIGNATURE_BASE_SUSP_X"}, {"forge", "MALPEDIA_Win_Y_Auto"}, {"forge", "X_HKTL_Z"}})
	if src != SourceYara || sig != "MALPEDIA_Win_Y_Auto (+2 more)" {
		t.Errorf("yaraVerdict = %s %s", src, sig)
	}
	if !AlertOnly(SourceYaraTool) || !AlertOnly(SourceYaraSuspicious) || AlertOnly(SourceYara) || AlertOnly("clamav") {
		t.Error("AlertOnly")
	}
}

func TestYaraClient(t *testing.T) {
	y := fakeYara(t)
	ctx := context.Background()
	st, err := y.Status(ctx)
	if err != nil || !st.OK || !st.Configured || st.Rules != 5128 {
		t.Fatalf("status %+v, %v", st, err)
	}
	ms, err := y.Scan(ctx, bytes.NewReader([]byte("x YARA-MAL x")))
	if err != nil || len(ms) != 1 || ms[0].Rule != "MALPEDIA_Win_Agent_Tesla_Auto" {
		t.Fatalf("scan %+v, %v", ms, err)
	}
	if _, err := y.Scan(ctx, bytes.NewReader([]byte("YARA-FAIL"))); err == nil || err.Error() != "yara scanner: boom" {
		t.Fatalf("failing scan: %v", err)
	}
}

// ClamAV and YARA together: ClamAV decides first, YARA catches what it misses, hacking
// tools are alert-only, and a failing scanner leaves no verdict.
func TestJudgeWithYara(t *testing.T) {
	h := newHarness(t)
	h.s.d.Yara = fakeYara(t)
	ctx := context.Background()
	win := func(name string, c byte) Candidate {
		return Candidate{HostID: "h1", Hostname: "desk", Platform: "windows", Path: `C:\Users\a\` + name, SHA256: sha(c), PID: 10, EntityID: "e" + string(c)}
	}
	h.files[`C:\Users\a\both.exe`] = "EVIL YARA-MAL"
	h.files[`C:\Users\a\mal.exe`] = "YARA-MAL"
	h.files[`C:\Users\a\tool.exe`] = "YARA-TOOL YARA-SUSP"
	h.files[`C:\Users\a\packed.exe`] = "YARA-SUSP"
	h.files[`C:\Users\a\fine.exe`] = "fine"
	h.files[`C:\Users\a\fail.exe`] = "YARA-FAIL"
	h.run(t, win("both.exe", 'a'), win("mal.exe", 'b'), win("tool.exe", 'c'), win("packed.exe", 'd'), win("fine.exe", 'e'), win("fail.exe", 'f'))
	got := map[string]string{}
	for _, d := range h.detected {
		got[d.Path[len(`C:\Users\a\`):]] = d.Source + "/" + d.Signature
	}
	want := map[string]string{
		"both.exe":   "clamav/Win.Test.Evil-1",
		"mal.exe":    "yara/MALPEDIA_Win_Agent_Tesla_Auto",
		"tool.exe":   "yara:tool/SIGNATURE_BASE_HKTL_Mimikatz (+1 more)",
		"packed.exe": "yara:suspicious/DITEKSHEN_INDICATOR_EXE_Packed_Themida",
	}
	if len(got) != len(want) {
		t.Fatalf("detections = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	for _, d := range h.detected {
		if d.AlertOnly() != (d.Source == SourceYaraTool || d.Source == SourceYaraSuspicious) {
			t.Errorf("%s AlertOnly = %v", d.Path, d.AlertOnly())
		}
	}
	if v, err := h.st.GetAVVerdict(ctx, sha('e')); err != nil || v.Source != "clamav+yara" {
		t.Errorf("clean verdict = %+v, %v", v, err)
	}
	if _, err := h.st.GetAVVerdict(ctx, sha('f')); err == nil {
		t.Error("a failed scan stored a verdict")
	}
	if v := h.s.Status(ctx); !v.Yara.OK || v.Yara.Rules != 5128 {
		t.Errorf("status yara = %+v", v.Yara)
	}
}

// Per-group scanner switches: a host only hears about detections from its own scanners,
// and a clean verdict from fewer scanners than a host wants is scanned again.
func TestGroupScanners(t *testing.T) {
	h := newHarness(t)
	h.s.d.Yara = fakeYara(t)
	h.s.d.Scanners = func(group string) Scanners {
		switch group {
		case "clam-only":
			return Scanners{ClamAV: true}
		case "yara-only":
			return Scanners{YARA: true}
		case "none":
			return Scanners{}
		}
		return Scanners{ClamAV: true, YARA: true}
	}
	ctx := context.Background()
	cand := func(group, path string, c byte, pid int64) Candidate {
		return Candidate{HostID: "h-" + group, Hostname: group, Platform: "windows", Path: path, SHA256: sha(c), PID: pid,
			EntityID: group + string(c), GroupID: group}
	}
	h.files[`C:\a\mal.exe`] = "YARA-MAL"
	h.files[`C:\a\fine.exe`] = "fine"

	// Only a ClamAV-only host runs it: ClamAV finds nothing, YARA is not asked.
	h.run(t, cand("clam-only", `C:\a\mal.exe`, 'a', 1))
	if len(h.detected) != 0 {
		t.Fatalf("clam-only host: %+v", h.detected)
	}
	if v, err := h.st.GetAVVerdict(ctx, sha('a')); err != nil || v.Source != "clamav" {
		t.Fatalf("verdict %+v %v", v, err)
	}
	// A host that wants YARA too: the clean ClamAV-only verdict is not enough, so it is
	// scanned again and YARA finds it.
	h.fetched = nil
	h.run(t, cand("all", `C:\a\mal.exe`, 'a', 2))
	if len(h.fetched) != 1 || len(h.detected) != 1 || h.detected[0].Source != SourceYara {
		t.Fatalf("all host: fetched %v detected %+v", h.fetched, h.detected)
	}
	// Seen again on the ClamAV-only host: the YARA verdict does not count there.
	h.detected = nil
	h.run(t, cand("clam-only", `C:\a\mal.exe`, 'a', 3), cand("yara-only", `C:\a\mal.exe`, 'a', 4))
	if len(h.detected) != 1 || h.detected[0].GroupID != "yara-only" {
		t.Fatalf("mixed hosts: %+v", h.detected)
	}
	// Both scanners off for the group: nothing is fetched.
	h.fetched = nil
	h.run(t, cand("none", `C:\a\fine.exe`, 'b', 5))
	if len(h.fetched) != 0 {
		t.Fatalf("fetched with scanners off: %v", h.fetched)
	}
}

// The scanner resolver reads the antivirus settings (as the server's group resolver
// does); judging a file must not hold the service lock while calling it.
func TestScannersResolverReadsSettings(t *testing.T) {
	h := newHarness(t)
	h.s.d.Scanners = func(string) Scanners {
		set := h.s.Settings()
		return Scanners{ClamAV: set.UseClamAV, YARA: set.UseYARA}
	}
	h.files[`C:\a\evil.exe`] = "EVIL"
	h.run(t, Candidate{HostID: "h", Platform: "windows", Path: `C:\a\evil.exe`, SHA256: sha('a'), PID: 9})
	if len(h.detected) != 1 {
		t.Fatalf("detected %+v", h.detected)
	}
}
