package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

type fakeServer map[string][]byte

func (f fakeServer) Fetch(_ context.Context, path string, w io.Writer, max int64) error {
	b, ok := f[path]
	if !ok {
		return fmt.Errorf("404 %s", path)
	}
	if int64(len(b)) > max {
		return fmt.Errorf("too large")
	}
	_, err := w.Write(b)
	return err
}

type fixture struct {
	srv     fakeServer
	priv    ed25519.PrivateKey
	updater *Updater
	exe     string
	data    string
}

const binName = "homexdr-agent-linux-amd64"

// release publishes a signed release whose binary is body.
func (f *fixture) release(version string, commitTime int64, body []byte) {
	sum := sha256.Sum256(body)
	m, _ := json.Marshal(api.AgentRelease{Version: version, CommitTime: commitTime,
		Files: map[string]api.ReleaseFile{binName: {SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}}})
	f.srv[api.PathAgentRelease] = m
	f.srv[api.PathAgentReleaseSig] = api.SignRelease(f.priv, m)
	f.srv["/v1/download/"+binName] = body
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin", "homexdr-agent")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("old binary"), 0o755)
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	f := &fixture{srv: fakeServer{}, priv: priv, exe: exe, data: data}
	f.updater = &Updater{
		Key: pub, Exe: exe, DataDir: data, Fetcher: f.srv, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		GOOS: "linux", GOARCH: "amd64", Version: "v1", CommitTime: 100,
		Check: func(context.Context, string, string) error { return nil },
	}
	return f
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallAndRollback(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.release("v2", 200, []byte("new binary"))

	rel, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v2"})
	if err != nil || rel == nil || rel.Version != "v2" {
		t.Fatalf("Install = %+v, %v", rel, err)
	}
	if read(t, f.exe) != "new binary" || read(t, f.exe+".prev") != "old binary" {
		t.Fatal("binary not swapped")
	}
	if m, ok := Pending(f.data); !ok || m.Version != "v2" || m.PreviousVersion != "v1" {
		t.Fatalf("marker %+v %v", m, ok)
	}

	// The new version starts three times without confirming; the fourth start rolls back.
	log := f.updater.Log
	for i := 1; i <= maxStartAttempts; i++ {
		if restore, err := CheckStartup(f.data, f.exe, "v2", log); restore || err != nil {
			t.Fatalf("start %d: restore %v, err %v", i, restore, err)
		}
	}
	restore, err := CheckStartup(f.data, f.exe, "v2", log)
	if !restore || err != nil {
		t.Fatalf("expected a rollback, got %v %v", restore, err)
	}
	if read(t, f.exe) != "old binary" {
		t.Fatal("previous binary not restored")
	}
	if _, ok := Pending(f.data); ok {
		t.Fatal("marker left after rollback")
	}
	// The rolled-back version is not installed again right away.
	f.updater.failed = nil
	if rel, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v2"}); rel != nil || err != nil {
		t.Fatalf("rolled-back version reinstalled: %+v %v", rel, err)
	}
	// A different version is.
	f.release("v3", 300, []byte("newer binary"))
	if rel, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v3"}); rel == nil || err != nil {
		t.Fatalf("v3: %+v %v", rel, err)
	}
	if m, ok := Confirm(f.data, "v3"); !ok || m.Version != "v3" {
		t.Fatal("Confirm did not clear the marker")
	}
	if restore, _ := CheckStartup(f.data, f.exe, "v3", log); restore {
		t.Fatal("confirmed version rolled back")
	}
}

func TestInstallRejects(t *testing.T) {
	ctx := context.Background()
	for name, setup := range map[string]func(f *fixture){
		"wrong key": func(f *fixture) {
			f.release("v2", 200, []byte("new"))
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.srv[api.PathAgentReleaseSig] = api.SignRelease(other, f.srv[api.PathAgentRelease])
		},
		"hash mismatch": func(f *fixture) {
			f.release("v2", 200, []byte("new"))
			f.srv["/v1/download/"+binName] = []byte("evil")
		},
		"older build": func(f *fixture) { f.release("v0", 50, []byte("old")) },
		"no binary for this platform": func(f *fixture) {
			f.release("v2", 200, []byte("new"))
			f.updater.GOARCH = "arm64"
		},
		"failed start check": func(f *fixture) {
			f.release("v2", 200, []byte("new"))
			f.updater.Check = func(context.Context, string, string) error { return errors.New("crashed") }
		},
		"no signature": func(f *fixture) {
			f.release("v2", 200, []byte("new"))
			delete(f.srv, api.PathAgentReleaseSig)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(f)
			rel, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v2"})
			if rel != nil || err == nil {
				t.Fatalf("installed: %+v, %v", rel, err)
			}
			if read(t, f.exe) != "old binary" {
				t.Fatal("binary changed")
			}
			if _, ok := Pending(f.data); ok {
				t.Fatal("marker written")
			}
			ents, _ := os.ReadDir(filepath.Dir(f.exe))
			if len(ents) != 1 {
				t.Fatalf("left files behind: %v", ents)
			}
		})
	}
}

func TestInstallNothingToDo(t *testing.T) {
	f := newFixture(t)
	if rel, err := f.updater.Install(context.Background(), api.AgentUpdate{Version: "v1"}); rel != nil || err != nil {
		t.Fatalf("same version: %+v %v", rel, err)
	}
}

// archived publishes a signed release under an archive path, as servers with release
// archives serve older versions.
func (f *fixture) archived(version string, commitTime int64, body []byte) string {
	dir := api.PathReleases + version + "/"
	sum := sha256.Sum256(body)
	m, _ := json.Marshal(api.AgentRelease{Version: version, CommitTime: commitTime,
		Files: map[string]api.ReleaseFile{binName: {SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}}})
	f.srv[dir+api.AgentReleaseName] = m
	f.srv[dir+api.AgentReleaseName+".sig"] = api.SignRelease(f.priv, m)
	f.srv[dir+binName] = body
	return dir
}

func TestInstallFromArchivePath(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.release("v9", 900, []byte("latest binary")) // the bundled release must not be used
	path := f.archived("v2", 200, []byte("archived binary"))
	rel, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v2", CommitTime: 200, Path: path})
	if err != nil || rel == nil || rel.Version != "v2" {
		t.Fatalf("install from archive: %v %v", rel, err)
	}
	if got := read(t, f.exe); got != "archived binary" {
		t.Fatalf("installed %q", got)
	}
}

func TestInstallRejectsBadArchivePaths(t *testing.T) {
	ctx := context.Background()
	for _, p := range []string{"/v1/download/", "/v1/releases/../x/", "/v1/releases/a/b/", "/v1/releases/v2", "https://evil.example/v1/releases/v2/"} {
		f := newFixture(t)
		f.archived("v2", 200, []byte("archived binary"))
		if _, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v2", Path: p}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	// A path that serves a different release than offered is refused.
	f := newFixture(t)
	path := f.archived("v3", 300, []byte("other"))
	if _, err := f.updater.Install(ctx, api.AgentUpdate{Version: "v2", Path: path}); err == nil {
		t.Error("mismatched release accepted")
	}
}
