package av

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// fakeClamd answers zVERSION, zPING and zINSTREAM; streams containing "EVIL" are found.
func fakeClamd(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				cmd, _ := r.ReadString(0)
				switch strings.TrimRight(cmd, "\x00") {
				case "zVERSION":
					conn.Write([]byte("ClamAV 1.4.6/27450/Fri Nov  6 08:21:00 2026\x00"))
				case "zPING":
					conn.Write([]byte("PONG\x00"))
				case "zINSTREAM":
					var data bytes.Buffer
					for {
						var size [4]byte
						if _, err := io.ReadFull(r, size[:]); err != nil {
							return
						}
						n := binary.BigEndian.Uint32(size[:])
						if n == 0 {
							break
						}
						if _, err := io.CopyN(&data, r, int64(n)); err != nil {
							return
						}
					}
					if bytes.Contains(data.Bytes(), []byte("EVIL")) {
						conn.Write([]byte("stream: Win.Test.Evil-1 FOUND\x00"))
					} else {
						conn.Write([]byte("stream: OK\x00"))
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestClamd(t *testing.T) {
	c := &Clamd{Addr: fakeClamd(t)}
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Version(ctx); err != nil || !strings.HasPrefix(v, "ClamAV 1.4.6/") {
		t.Fatalf("version %q, %v", v, err)
	}
	// Larger than one chunk, with the marker in the second.
	big := append(bytes.Repeat([]byte("a"), clamdChunk+10), []byte("EVIL")...)
	if sig, err := c.Scan(ctx, bytes.NewReader(big)); err != nil || sig != "Win.Test.Evil-1" {
		t.Fatalf("scan evil: %q, %v", sig, err)
	}
	if sig, err := c.Scan(ctx, strings.NewReader("hello")); err != nil || sig != "" {
		t.Fatalf("scan clean: %q, %v", sig, err)
	}
	if _, err := parseScanReply("stream: INSTREAM size limit exceeded. ERROR"); !errors.Is(err, ErrClamdFailed) {
		t.Fatalf("error reply: %v", err)
	}
}

func TestEligible(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Windows\System32\cmd.exe`:              false,
		`c:\windows\syswow64\x.exe`:                false,
		`C:\Program Files\WindowsApps\pkg\app.exe`: false,
		`C:\Windows\Temp\dropper.exe`:              true,
		`C:\Users\alice\Downloads\invoice.exe`:     true,
		`C:\Program Files\Some Vendor\tool.exe`:    true,
		"/usr/bin/curl":                            false,
		"/tmp/.x/miner":                            true,
		"/home/alice/.local/bin/thing":             true,
		"":                                         false,
	} {
		plat := "linux"
		if strings.Contains(path, `\`) {
			plat = "windows"
		}
		if got := Eligible(plat, path); got != want {
			t.Errorf("Eligible(%q) = %v, want %v", path, got, want)
		}
	}
}

type harness struct {
	s        *Service
	st       *store.Store
	mu       sync.Mutex
	fetched  []string
	detected []Detection
	files    map[string]string // path on the host → content
	rep      map[string]Reputation
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &harness{st: st, files: map[string]string{}, rep: map[string]Reputation{}}
	dir := t.TempDir()
	h.s = New(Deps{
		State: st,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clamd: &Clamd{Addr: fakeClamd(t)},
		Lookup: func(_ context.Context, sha string) (Reputation, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.rep[sha], nil
		},
		Fetch: func(_ context.Context, c Candidate, _ int64) (string, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.fetched = append(h.fetched, c.Path)
			body, ok := h.files[c.Path]
			if !ok {
				return "", ErrSkip
			}
			p := filepath.Join(dir, c.SHA256)
			return p, os.WriteFile(p, []byte(body), 0o600)
		},
		Detected: func(_ context.Context, d Detection, _ Settings) {
			h.mu.Lock()
			h.detected = append(h.detected, d)
			h.mu.Unlock()
		},
	})
	return h
}

func sha(c byte) string { return strings.Repeat(string(c), 64) }

// sum is the real SHA-256 of a file body: fetched files are checked against it.
func sum(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:])
}

func (h *harness) run(t *testing.T, cands ...Candidate) {
	t.Helper()
	for _, c := range cands {
		h.s.Observe(c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.s.mu.Lock()
		n := len(h.s.waiting)
		h.s.mu.Unlock()
		if n == 0 && len(h.s.queue) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue did not drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestJudge(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	win := func(path, hash string, pid int64) Candidate {
		return Candidate{HostID: "h1", Hostname: "desk", Platform: "windows", Path: path, SHA256: hash, PID: pid, EntityID: "e" + hash[:4]}
	}
	h.files[`C:\Users\a\Downloads\evil.exe`] = "MZ...EVIL..."
	h.files[`C:\Users\a\Downloads\fine.exe`] = "MZ...fine..."
	evil, fine := sum("MZ...EVIL..."), sum("MZ...fine...")
	h.rep[sha('c')] = Reputation{Malicious: true, Name: "AgentTesla", Source: "malwarebazaar"}
	h.rep[sha('d')] = Reputation{Known: true, Source: "circl"}

	h.run(t,
		win(`C:\Users\a\Downloads\evil.exe`, evil, 100), // ClamAV finds it
		win(`C:\Users\a\Downloads\fine.exe`, fine, 101), // clean
		win(`C:\Users\a\x.exe`, sha('c'), 102),          // intel says malware: not fetched
		win(`C:\Users\a\y.exe`, sha('d'), 103),          // known good: not fetched
		win(`C:\Windows\System32\z.exe`, sha('e'), 104), // system folder: ignored
		win(`C:\Users\a\gone.exe`, sha('f'), 105),       // cannot be fetched: skipped
	)
	got := map[string]string{}
	for _, d := range h.detected {
		got[d.SHA256] = d.Source + "/" + d.Signature
	}
	if got[evil] != "clamav/Win.Test.Evil-1" || got[sha('c')] != "intel:malwarebazaar/AgentTesla" || len(got) != 2 {
		t.Fatalf("detections = %v", got)
	}
	for _, p := range h.fetched {
		if strings.Contains(p, `x.exe`) || strings.Contains(p, `y.exe`) || strings.Contains(p, "System32") {
			t.Errorf("fetched %s", p)
		}
	}
	for hash, want := range map[string]string{evil: store.AVMalicious, fine: store.AVClean, sha('c'): store.AVMalicious, sha('d'): store.AVKnown, sha('f'): store.AVSkipped} {
		v, err := h.st.GetAVVerdict(ctx, hash)
		if err != nil || v.Verdict != want {
			t.Errorf("verdict %s = %+v, %v; want %s", hash[:8], v, err, want)
		}
	}
	if _, err := h.st.GetAVVerdict(ctx, sha('e')); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("system file got a verdict")
	}

	// The same malware on another host, seen later, is answered from the stored verdict
	// without fetching it again; the same process is not reported twice.
	h.fetched, h.detected = nil, nil
	other := win(`C:\Users\b\Desktop\evil.exe`, evil, 200)
	other.HostID, other.Hostname, other.EntityID = "h2", "laptop", "other"
	h.run(t, other, win(`C:\Users\a\Downloads\evil.exe`, evil, 100))
	if len(h.fetched) != 0 || len(h.detected) != 1 || h.detected[0].HostID != "h2" || h.detected[0].Path != `C:\Users\b\Desktop\evil.exe` {
		t.Fatalf("second round: fetched %v, detected %+v", h.fetched, h.detected)
	}

	// Blocklist and allowlist.
	if _, err := h.s.Save(ctx, Settings{Enabled: true, Action: ActionAlert, BlockedHashes: []string{strings.ToUpper(sha('9'))}, AllowedHashes: []string{sha('8')}}); err != nil {
		t.Fatal(err)
	}
	h.detected = nil
	h.files[`C:\Users\a\allowed.exe`] = "EVIL"
	h.run(t, win(`C:\Windows\System32\blocked.exe`, sha('9'), 300), win(`C:\Users\a\allowed.exe`, sha('8'), 301))
	if len(h.detected) != 1 || h.detected[0].Source != "blocklist" {
		t.Fatalf("lists: %+v", h.detected)
	}
	if _, err := h.s.Save(ctx, Settings{BlockedHashes: []string{"nothex"}}); err == nil {
		t.Error("bad hash accepted")
	}
	if _, err := h.s.Save(ctx, Settings{Action: "nuke"}); err == nil {
		t.Error("bad action accepted")
	}
	// Settings survive a reload.
	h2 := New(Deps{State: h.st, Log: h.s.d.Log})
	if err := h2.Load(ctx); err != nil || h2.Settings().Action != ActionAlert || len(h2.Settings().BlockedHashes) != 1 {
		t.Fatalf("reload: %+v, %v", h2.Settings(), err)
	}
}

// An agent that reports one program's hash and uploads another file gets no verdict
// stored under that hash, in either direction.
func TestUploadMustMatchReportedHash(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cand := func(path, hash string) Candidate {
		return Candidate{HostID: "rogue", Hostname: "rogue", Platform: "windows", Path: path, SHA256: hash, PID: 50, EntityID: path}
	}
	// Malware uploaded under a trusted program's hash: no detection, no verdict.
	h.files[`C:\Users\a\trusted.exe`] = "MZ...EVIL..."
	// A harmless file uploaded under malware's hash: not remembered as clean.
	h.files[`C:\Users\a\malware.exe`] = "MZ...fine..."
	h.run(t, cand(`C:\Users\a\trusted.exe`, sha('a')), cand(`C:\Users\a\malware.exe`, sha('b')))
	if len(h.fetched) != 2 || len(h.detected) != 0 {
		t.Fatalf("fetched %v, detected %+v", h.fetched, h.detected)
	}
	for _, hash := range []string{sha('a'), sha('b'), sum("MZ...EVIL..."), sum("MZ...fine...")} {
		if v, err := h.st.GetAVVerdict(ctx, hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("verdict stored for %s: %+v", hash[:8], v)
		}
	}
	if !strings.Contains(h.s.Status(ctx).LastError, "does not match the reported hash") {
		t.Errorf("last error = %q", h.s.Status(ctx).LastError)
	}
}

// A host that cannot (or will not) hand a file over does not keep it from being scanned
// when another host has it; the host itself is not asked again for a day.
func TestSkippedHoldsOnlyForItsHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	evil := sum("MZ...EVIL...")
	on := func(host, path string) Candidate {
		return Candidate{HostID: host, Hostname: host, Platform: "windows", Path: path, SHA256: evil, PID: 60, EntityID: host}
	}
	now := time.Now()
	h.s.now = func() time.Time { return now }
	h.run(t, on("rogue", `C:\Users\a\gone.exe`))
	h.run(t, on("rogue", `C:\Users\a\gone.exe`)) // not asked twice
	if v, err := h.st.GetAVVerdict(ctx, evil); err != nil || v.Verdict != store.AVSkipped || len(h.fetched) != 1 {
		t.Fatalf("after the skip: %+v, %v, fetched %v", v, err, h.fetched)
	}
	h.files[`C:\Users\b\evil.exe`] = "MZ...EVIL..."
	h.run(t, on("honest", `C:\Users\b\evil.exe`))
	if v, err := h.st.GetAVVerdict(ctx, evil); err != nil || v.Verdict != store.AVMalicious || len(h.detected) != 1 || h.detected[0].HostID != "honest" {
		t.Fatalf("another host: %+v, %v, detected %+v", v, err, h.detected)
	}

	// A day later the first host is asked again.
	h2 := newHarness(t)
	h2.s.now = func() time.Time { return now }
	h2.run(t, on("h1", `C:\Users\a\big.exe`))
	now = now.Add(retrySkippedAfter + time.Minute)
	h2.run(t, on("h1", `C:\Users\a\big.exe`))
	if len(h2.fetched) != 2 {
		t.Fatalf("retry after a day: fetched %v", h2.fetched)
	}
}

func TestDisabled(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.Save(context.Background(), Settings{Enabled: false, Action: ActionQuarantine}); err != nil {
		t.Fatal(err)
	}
	h.files[`C:\a\evil.exe`] = "EVIL"
	h.run(t, Candidate{HostID: "h", Platform: "windows", Path: `C:\a\evil.exe`, SHA256: sha('a'), PID: 9})
	if len(h.fetched) != 0 || len(h.detected) != 0 {
		t.Fatalf("disabled antivirus acted: %v %v", h.fetched, h.detected)
	}
}
