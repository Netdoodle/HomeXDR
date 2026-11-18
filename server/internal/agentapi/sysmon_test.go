package agentapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// TestHeartbeatSysmonEnabled checks the per-host Sysmon switch in heartbeat responses:
// Global (the agent config, on by default) unless the host's group or its parent group
// overrides it. It is independent of the decoy switch.
func TestHeartbeatSysmonEnabled(t *testing.T) {
	ctx := context.Background()
	c := newTestCore(t)
	srv := httptest.NewUnstartedServer(New(c))
	srv.TLS = c.PKI.TLSConfig()
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	id, cert := enrollForTest(t, c, srv.URL, roots)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}, DisableKeepAlives: true,
	}}
	hb, _ := json.Marshal(api.Heartbeat{Host: api.HostInfo{Hostname: "desktop", OS: event.OS{Platform: "windows"}},
		Status: api.AgentStatus{Version: "test", ConfigVersion: 1 << 40}})
	beat := func() api.HeartbeatResponse {
		t.Helper()
		resp, err := client.Post(srv.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var hbr api.HeartbeatResponse
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&hbr) != nil {
			t.Fatalf("heartbeat = %d", resp.StatusCode)
		}
		if hbr.SysmonEnabled == nil {
			t.Fatal("no sysmon_enabled in the heartbeat reply")
		}
		return hbr
	}
	want := func(v bool) {
		t.Helper()
		if got := beat(); *got.SysmonEnabled != v {
			t.Fatalf("sysmon_enabled = %v, want %v", *got.SysmonEnabled, v)
		}
	}
	setGlobal := func(on bool) {
		t.Helper()
		cfg := c.AgentConfig(ctx)
		cfg.Sysmon.Enabled = on
		if _, err := c.SetAgentConfig(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy := func(g string, v *bool) {
		t.Helper()
		if _, err := c.State.UpdateGroup(ctx, g, store.GroupUpdate{Policy: &store.GroupPolicy{Sysmon: store.SysmonGroupPolicy{Enabled: v}}}); err != nil {
			t.Fatal(err)
		}
		if err := c.ReloadGroups(ctx); err != nil {
			t.Fatal(err)
		}
	}
	on, off := true, false

	want(true) // default on, no group
	setGlobal(false)
	want(false)
	setGlobal(true)

	parent, err := c.State.CreateGroup(ctx, "Home", "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := c.State.CreateGroup(ctx, "Kids", parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.State.SetHostsGroup(ctx, []string{id}, child.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.ReloadGroups(ctx); err != nil {
		t.Fatal(err)
	}
	want(true)

	setPolicy(parent.ID, &off) // inherited from the parent
	want(false)
	if src := c.ResolveSysmon(child.ID, true); src.Value || src.GroupID != parent.ID {
		t.Errorf("child source %+v", src)
	}
	if got := beat(); got.DecoysEnabled == nil || !*got.DecoysEnabled {
		t.Errorf("the Sysmon switch changed decoys: %v", got.DecoysEnabled)
	}

	setPolicy(child.ID, &on) // the child's own value wins
	want(true)

	setPolicy(child.ID, nil)
	setPolicy(parent.ID, nil)
	want(true)
}
