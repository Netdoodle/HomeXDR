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

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestNewExternalSetsFlag(t *testing.T) {
	c := newTestCore(t)
	if New(c).external {
		t.Error("local handler marked external")
	}
	if !NewExternal(c).external {
		t.Error("external handler not marked external")
	}
}

// TestHeartbeatRecordsAddress checks that a heartbeat stores where the agent connected
// from, writes only when that changes, and notes the internet listener.
func TestHeartbeatRecordsAddress(t *testing.T) {
	ctx := context.Background()
	c := newTestCore(t)
	localH, extH := New(c), NewExternal(c)
	local := httptest.NewUnstartedServer(localH)
	local.TLS = c.PKI.TLSConfig()
	local.StartTLS()
	defer local.Close()
	ext := httptest.NewUnstartedServer(extH)
	ext.TLS = c.PKI.TLSConfig()
	ext.StartTLS()
	defer ext.Close()

	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	id, cert := enrollForTest(t, c, local.URL, roots)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}, DisableKeepAlives: true,
	}}
	hb, _ := json.Marshal(api.Heartbeat{Host: api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "windows"}},
		Status: api.AgentStatus{Version: "test"}})
	beat := func(base string) {
		t.Helper()
		resp, err := client.Post(base+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("heartbeat = %d", resp.StatusCode)
		}
	}
	addr := func() (string, bool) {
		t.Helper()
		h, err := c.State.GetHost(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return h.LastIP, h.LastExternal
	}

	if ip, ext := addr(); ip != "" || ext {
		t.Fatalf("before any heartbeat: %q %v", ip, ext)
	}
	beat(local.URL)
	if ip, ext := addr(); ip != "127.0.0.1" || ext {
		t.Fatalf("after local heartbeat: %q %v", ip, ext)
	}

	// An unchanged address is not written again: a marker put in the database survives.
	if err := c.State.SetLastAddress(ctx, id, "marker", false); err != nil {
		t.Fatal(err)
	}
	beat(local.URL)
	beat(local.URL)
	if ip, _ := addr(); ip != "marker" {
		t.Fatalf("an unchanged address was written again: %q", ip)
	}

	// Through the internet listener's handler the address and the flag are updated.
	beat(ext.URL)
	if ip, ext := addr(); ip != "127.0.0.1" || !ext {
		t.Fatalf("after external heartbeat: %q %v", ip, ext)
	}
	// And back.
	beat(local.URL)
	if ip, ext := addr(); ip != "127.0.0.1" || ext {
		t.Fatalf("after returning to the local listener: %q %v", ip, ext)
	}
}
