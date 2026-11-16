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

// TestHeartbeatDecoysEnabled checks the per-host decoy switch in heartbeat responses:
// Global (the agent config) unless the host's group or its parent group overrides it.
func TestHeartbeatDecoysEnabled(t *testing.T) {
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
	hb, _ := json.Marshal(api.Heartbeat{Host: api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "windows"}},
		Status: api.AgentStatus{Version: "test", ConfigVersion: 1 << 40}})
	beat := func() *bool {
		t.Helper()
		resp, err := client.Post(srv.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var raw map[string]json.RawMessage
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&raw) != nil {
			t.Fatalf("heartbeat = %d", resp.StatusCode)
		}
		var hbr api.HeartbeatResponse
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &hbr)
		if _, ok := raw["decoys_enabled"]; !ok {
			t.Fatalf("no decoys_enabled in %s", b)
		}
		return hbr.DecoysEnabled
	}
	want := func(v bool) {
		t.Helper()
		if got := beat(); got == nil || *got != v {
			t.Fatalf("decoys_enabled = %v, want %v", got, v)
		}
	}
	setGlobal := func(on bool) {
		t.Helper()
		cfg := c.AgentConfig(ctx)
		cfg.Decoys.Enabled = on
		if _, err := c.SetAgentConfig(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy := func(g string, v *bool) {
		t.Helper()
		if _, err := c.State.UpdateGroup(ctx, g, store.GroupUpdate{Policy: &store.GroupPolicy{Decoys: store.DecoysGroupPolicy{Enabled: v}}}); err != nil {
			t.Fatal(err)
		}
		if err := c.ReloadGroups(ctx); err != nil {
			t.Fatal(err)
		}
	}
	on, off := true, false

	// No group: Global.
	want(true)
	setGlobal(false)
	want(false)

	parent, err := c.State.CreateGroup(ctx, "Infrastructure", "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := c.State.CreateGroup(ctx, "Servers", parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.State.SetHostsGroup(ctx, []string{id}, child.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.ReloadGroups(ctx); err != nil {
		t.Fatal(err)
	}
	want(false) // neither group sets it: Global

	setPolicy(parent.ID, &on) // the child inherits its parent's override over Global
	want(true)
	if src := c.ResolveDecoys(child.ID, false); !src.Value || src.GroupID != parent.ID {
		t.Errorf("child source %+v", src)
	}

	setGlobal(true)
	setPolicy(child.ID, &off) // the child's own value beats its parent's and Global
	want(false)

	setPolicy(child.ID, nil)
	setPolicy(parent.ID, nil)
	want(true)
}
