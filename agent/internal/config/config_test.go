package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

func TestParseDefaultsPolicy(t *testing.T) {
	c, err := Parse([]byte(`{"server_url":"https://x:8443"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.AllowedActions, api.DefaultAllowedActions) {
		t.Fatalf("missing allowed_actions should mean the default policy, got %v", c.AllowedActions)
	}
	if c.LogLevel != "info" {
		t.Fatalf("log level default: %q", c.LogLevel)
	}
}

func TestParseEmptyPolicyAllowsNothing(t *testing.T) {
	c, err := Parse([]byte(`{"server_url":"https://x:8443","allowed_actions":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AllowedActions) != 0 || c.Allowed(api.CmdProcessKill) {
		t.Fatalf("explicit empty list must allow nothing, got %v", c.AllowedActions)
	}
}

func TestParseRestrictedPolicy(t *testing.T) {
	c, err := Parse([]byte(`{"allowed_actions":["artifact.collect","file.hash"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Allowed(api.CmdArtifact) || c.Allowed(api.CmdHostIsolate) {
		t.Fatalf("policy check wrong: %v", c.AllowedActions)
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"unknown action": `{"allowed_actions":["shell.exec"]}`,
		"bad cidr":       `{"isolation_allow":["10.0.0.0/33"]}`,
		"unknown field":  `{"allowed_action":["process.kill"]}`,
		"bad pin":        `{"ca_pin":"md5:abc"}`,
		"bad level":      `{"log_level":"loud"}`,
		"bad update key": `{"update_key":"ed25519:AAAA"}`,
		"update no key":  `{"auto_update":true}`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseAutoUpdate(t *testing.T) {
	key := "ed25519:" + strings.Repeat("A", 43) + "="
	c, err := Parse([]byte(`{"auto_update":true,"update_key":"` + key + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.AutoUpdate || c.UpdateKey != key {
		t.Fatalf("auto update not parsed: %+v", c)
	}
	// A key without auto_update is kept but does nothing.
	if c, err := Parse([]byte(`{"update_key":"` + key + `"}`)); err != nil || c.AutoUpdate {
		t.Fatalf("key alone: %+v, %v", c, err)
	}
}

func TestIsolationPrefixes(t *testing.T) {
	c := Local{IsolationAllow: []string{"192.168.1.10", "10.0.0.0/8", "fd00::/8", " "}}
	ps, err := c.IsolationPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.10/32", "10.0.0.0/8", "fd00::/8"}
	if len(ps) != len(want) {
		t.Fatalf("got %v", ps)
	}
	for i, p := range ps {
		if p.String() != want[i] {
			t.Errorf("prefix %d: got %s want %s", i, p, want[i])
		}
	}
}

func TestValidPin(t *testing.T) {
	good := "sha256:" + string(make([]byte, 0))
	for i := 0; i < 64; i++ {
		good += "a"
	}
	if !ValidPin(good) {
		t.Error("valid pin rejected")
	}
	if ValidPin("sha256:xyz") || ValidPin(good[:len(good)-1]) {
		t.Error("invalid pin accepted")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "agent.json")
	if _, err := Load(p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file: got %v", err)
	}
	c := Default()
	c.ServerURL = "https://xdr.lan:8443"
	c.AllowedActions = []string{api.CmdFileHash}
	c.IsolationAllow = []string{"192.168.1.0/24"}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != c.ServerURL || !slices.Equal(got.AllowedActions, c.AllowedActions) || !slices.Equal(got.IsolationAllow, c.IsolationAllow) {
		t.Fatalf("round trip: %+v", got)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("config mode %o, want 0600", st.Mode().Perm())
		}
	}
	// An empty policy must survive a round trip as an empty list, not the default.
	c.AllowedActions = nil
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	if got, _ = Load(p); len(got.AllowedActions) != 0 {
		t.Fatalf("empty policy became %v", got.AllowedActions)
	}
}
