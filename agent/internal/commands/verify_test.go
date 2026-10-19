package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/state"
	"github.com/Doodlebug12/homexdr/shared/api"
)

type fixture struct {
	priv ed25519.PrivateKey
	v    *Verifier
	now  time.Time
}

func newFixture(t *testing.T, allowed ...string) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(filepath.Join(t.TempDir(), state.FileName))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{priv: priv, now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	f.v = &Verifier{
		AgentID: "agent-1", Key: pub, Seen: st,
		Policy: func(t string) bool { return slices.Contains(allowed, t) },
		Now:    func() time.Time { return f.now },
	}
	return f
}

func (f *fixture) sign(t *testing.T, c api.Command) api.SignedCommand {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return api.SignedCommand{Payload: b, Signature: ed25519.Sign(f.priv, b)}
}

func (f *fixture) cmd(id, typ string) api.Command {
	return api.Command{ID: id, AgentID: "agent-1", Type: typ, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour), IssuedBy: "admin"}
}

func wantReject(t *testing.T, err error, id, contains string) {
	t.Helper()
	r, ok := err.(*Rejection)
	if !ok {
		t.Fatalf("want rejection containing %q, got %v", contains, err)
	}
	if r.ID != id || !strings.Contains(r.Reason, contains) {
		t.Fatalf("rejection %+v, want id %q reason containing %q", r, id, contains)
	}
}

func TestVerifyAccepts(t *testing.T) {
	f := newFixture(t, api.CmdProcessKill)
	c, err := f.v.Verify(f.sign(t, f.cmd("c1", api.CmdProcessKill)))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "c1" || c.Type != api.CmdProcessKill {
		t.Fatalf("got %+v", c)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	f := newFixture(t, api.CmdProcessKill)
	sc := f.sign(t, f.cmd("c1", api.CmdProcessKill))
	// Tamper with the payload after signing.
	sc.Payload = []byte(strings.Replace(string(sc.Payload), "process.kill", "host.isolat", 1))
	_, err := f.v.Verify(sc)
	wantReject(t, err, "c1", "signature")

	// Signed by a different key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := json.Marshal(f.cmd("c2", api.CmdProcessKill))
	_, err = f.v.Verify(api.SignedCommand{Payload: b, Signature: ed25519.Sign(other, b)})
	wantReject(t, err, "c2", "signature")

	// Truncated signature.
	_, err = f.v.Verify(api.SignedCommand{Payload: b, Signature: []byte{1, 2, 3}})
	wantReject(t, err, "c2", "signature")
}

func TestVerifyWrongAgent(t *testing.T) {
	f := newFixture(t, api.CmdProcessKill)
	c := f.cmd("c1", api.CmdProcessKill)
	c.AgentID = "agent-2"
	_, err := f.v.Verify(f.sign(t, c))
	wantReject(t, err, "c1", "addressed to agent")
}

func TestVerifyExpired(t *testing.T) {
	f := newFixture(t, api.CmdProcessKill)
	c := f.cmd("c1", api.CmdProcessKill)
	c.ExpiresAt = f.now.Add(-time.Second)
	_, err := f.v.Verify(f.sign(t, c))
	wantReject(t, err, "c1", "expired")

	c = f.cmd("c2", api.CmdProcessKill)
	c.ExpiresAt = f.now // now < ExpiresAt is required
	_, err = f.v.Verify(f.sign(t, c))
	wantReject(t, err, "c2", "expired")
}

func TestVerifyReplay(t *testing.T) {
	f := newFixture(t, api.CmdProcessKill)
	sc := f.sign(t, f.cmd("c1", api.CmdProcessKill))
	if _, err := f.v.Verify(sc); err != nil {
		t.Fatal(err)
	}
	_, err := f.v.Verify(sc)
	wantReject(t, err, "c1", "replay")
}

func TestReplayStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	c := api.Command{ID: "c1", AgentID: "a", Type: api.CmdFileHash, ExpiresAt: now.Add(time.Hour)}
	b, _ := json.Marshal(c)
	sc := api.SignedCommand{Payload: b, Signature: ed25519.Sign(priv, b)}
	mk := func() *Verifier {
		st, err := state.Open(filepath.Join(dir, state.FileName))
		if err != nil {
			t.Fatal(err)
		}
		return &Verifier{AgentID: "a", Key: pub, Seen: st, Policy: func(string) bool { return true }}
	}
	if _, err := mk().Verify(sc); err != nil {
		t.Fatal(err)
	}
	_, err := mk().Verify(sc) // a fresh process with the persisted state
	wantReject(t, err, "c1", "replay")
}

func TestVerifyPolicy(t *testing.T) {
	f := newFixture(t, api.CmdArtifact)
	_, err := f.v.Verify(f.sign(t, f.cmd("c1", api.CmdHostIsolate)))
	wantReject(t, err, "c1", "local policy")
	// A policy rejection still consumes the ID.
	_, err = f.v.Verify(f.sign(t, f.cmd("c1", api.CmdArtifact)))
	wantReject(t, err, "c1", "replay")
}

func TestSeenWindowIsBounded(t *testing.T) {
	st, _ := state.Open(filepath.Join(t.TempDir(), state.FileName))
	for i := range state.MaxSeen + 10 {
		if ok, err := st.MarkSeen(string(rune('a'+i%26)) + time.Duration(i).String()); err != nil || !ok {
			t.Fatalf("mark %d: %v %v", i, ok, err)
		}
	}
	if n := len(st.Snapshot().SeenCommands); n != state.MaxSeen {
		t.Fatalf("kept %d ids", n)
	}
}

func TestArtifactArgs(t *testing.T) {
	def, _ := api.FindArtifact("file.find")
	if _, err := ArtifactArgs(def, map[string]string{}); err == nil {
		t.Error("missing required root accepted")
	}
	got, err := ArtifactArgs(def, map[string]string{"root": "/etc", "max_depth": "2"})
	if err != nil {
		t.Fatal(err)
	}
	if got["glob"] != "*" || got["max_depth"] != "2" || got["hash"] != "false" {
		t.Fatalf("defaults not applied: %v", got)
	}
	if _, err := ArtifactArgs(def, map[string]string{"root": "/", "max_depth": "two"}); err == nil {
		t.Error("non-integer accepted")
	}
	if _, err := ArtifactArgs(def, map[string]string{"root": "/", "cmd": "id"}); err == nil {
		t.Error("unknown parameter accepted")
	}
}

func TestDecodeParamsStrict(t *testing.T) {
	var p api.KillParams
	if err := decodeParams(json.RawMessage(`{"pid":5,"extra":1}`), &p); err == nil {
		t.Error("unknown field accepted")
	}
	if err := decodeParams(nil, &struct{}{}); err != nil {
		t.Errorf("empty params: %v", err)
	}
}
