package agentapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/pki"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const testRule = `title: Whoami executed
id: 6f1b1a52-0000-4000-8000-000000000001
level: medium
tags: [attack.discovery, attack.t1033]
logsource: {category: process_creation}
detection:
  sel:
    Image|endswith: ['\whoami.exe', '/whoami']
  condition: sel
`

func newTestCore(t *testing.T) *core.Core { return newTestCoreWith(t, nil) }

func newTestCoreWith(t *testing.T, edit func(*config.Config)) *core.Core {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	os.MkdirAll(rules, 0o755)
	os.WriteFile(filepath.Join(rules, "whoami.yml"), []byte(testRule), 0o644)
	cfg := config.Config{DataDir: dir, RulesDir: rules, RetentionDays: 30, AgentURL: "https://localhost:8443"}
	if edit != nil {
		edit(&cfg)
	}
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	p, err := pki.Load(filepath.Join(dir, "pki"), []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New(context.Background(), cfg, log, st, ev, p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAgentLifecycle(t *testing.T) {
	ctx := context.Background()
	c := newTestCore(t)
	srv := httptest.NewUnstartedServer(New(c))
	srv.TLS = c.PKI.TLSConfig()
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}

	tok, err := c.State.CreateToken(ctx, "test", "admin", nil, nil, []string{"lab"})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	req := api.EnrollRequest{
		Token:  tok.Token,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Host:   api.HostInfo{Hostname: "lab-1", OS: event.OS{Platform: "linux", Name: "Ubuntu"}, Arch: "amd64"},
	}
	body, _ := json.Marshal(req)
	resp, err := anon.Post(srv.URL+api.PathEnroll, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var enr api.EnrollResponse
	json.NewDecoder(resp.Body).Decode(&enr)
	resp.Body.Close()
	if resp.StatusCode != 200 || enr.AgentID == "" {
		t.Fatalf("enroll status %d %+v", resp.StatusCode, enr)
	}

	// Unauthenticated access to agent routes is refused.
	resp, _ = anon.Post(srv.URL+api.PathHeartbeat, "application/json", bytes.NewReader([]byte(`{}`)))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("heartbeat without cert = %d", resp.StatusCode)
	}
	resp.Body.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(enr.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	agent := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}}}

	hb, _ := json.Marshal(api.Heartbeat{
		Host:   req.Host,
		Status: api.AgentStatus{Version: "test", AllowedActions: api.DefaultAllowedActions},
	})
	resp, err = agent.Post(srv.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
	if err != nil {
		t.Fatal(err)
	}
	var hbr api.HeartbeatResponse
	json.NewDecoder(resp.Body).Decode(&hbr)
	resp.Body.Close()
	if resp.StatusCode != 200 || hbr.Config == nil {
		t.Fatalf("heartbeat = %d, config %v", resp.StatusCode, hbr.Config)
	}

	// Send events: one matches the rule.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	enc.Encode(event.Event{ID: event.NewID(), Timestamp: time.Now(), Event: event.Meta{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
		Process: &event.Process{EntityID: "p1", PID: 4242, Name: "whoami", Executable: "/usr/bin/whoami", CommandLine: "whoami"}})
	enc.Encode(event.Event{ID: event.NewID(), Timestamp: time.Now(), Event: event.Meta{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
		Network: &event.Network{Transport: "tcp"}, Source: &event.Endpoint{IP: "10.0.0.5", Port: 50000}, Destination: &event.Endpoint{IP: "1.1.1.1", Port: 443},
		Host: event.Host{ID: "spoofed"}})
	zw.Close()
	hreq, _ := http.NewRequest("POST", srv.URL+api.PathEvents, &buf)
	hreq.Header.Set("Content-Encoding", "gzip")
	resp, err = agent.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	var er api.EventsResponse
	json.NewDecoder(resp.Body).Decode(&er)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || er.Accepted != 2 {
		t.Fatalf("events = %d %+v", resp.StatusCode, er)
	}
	res, err := c.Events.Search(ctx, events.SearchQuery{Query: "event.category:network"})
	if err != nil || res.Total != 1 {
		t.Fatalf("stored network events = %v, %v", res, err)
	}
	if got := res.Events[0]; got.Host.ID != enr.AgentID || got.Network.CommunityID == "" || got.Host.Name != "lab-1" {
		t.Fatalf("event not normalized: host=%+v network=%+v", got.Host, got.Network)
	}
	alerts, _, err := c.State.ListAlerts(ctx, store.AlertFilter{})
	if err != nil || len(alerts) != 1 || alerts[0].Rule.Title != "Whoami executed" || alerts[0].HostID != enr.AgentID {
		t.Fatalf("alerts = %+v, %v", alerts, err)
	}
	if len(alerts[0].Mitre) != 2 || alerts[0].Mitre[1].TechniqueID != "T1033" {
		t.Fatalf("mitre = %+v", alerts[0].Mitre)
	}

	// Queue a kill while the agent long-polls; it must wake up.
	host, _ := c.State.GetHost(ctx, enr.AgentID)
	go func() {
		time.Sleep(300 * time.Millisecond)
		params, _ := json.Marshal(api.KillParams{PID: 4242, EntityID: "p1"})
		if _, err := c.IssueCommand(ctx, host, api.CmdProcessKill, params, "admin", "", 0); err != nil {
			t.Error(err)
		}
	}()
	start := time.Now()
	resp, err = agent.Get(srv.URL + api.PathCommands + "?wait=10")
	if err != nil {
		t.Fatal(err)
	}
	var cmds []api.SignedCommand
	json.NewDecoder(resp.Body).Decode(&cmds)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(cmds) != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("long poll = %d, %d cmds after %v", resp.StatusCode, len(cmds), time.Since(start))
	}
	pub, _ := base64.StdEncoding.DecodeString(enr.CommandKey)
	if !ed25519.Verify(pub, cmds[0].Payload, cmds[0].Signature) {
		t.Fatal("command signature does not verify with the enrolled key")
	}
	var cmd api.Command
	json.Unmarshal(cmds[0].Payload, &cmd)
	if cmd.AgentID != enr.AgentID || cmd.Type != api.CmdProcessKill {
		t.Fatalf("command = %+v", cmd)
	}

	out, _ := json.Marshal(api.KillResult{Killed: []int64{4242}})
	rb, _ := json.Marshal(api.CommandResult{Status: api.StatusCompleted, Output: out})
	resp, err = agent.Post(srv.URL+"/v1/commands/"+cmd.ID+"/result", "application/json", bytes.NewReader(rb))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("result = %d", resp.StatusCode)
	}
	rec, _ := c.State.GetCommand(ctx, cmd.ID)
	if rec.Status != api.StatusCompleted {
		t.Fatalf("command status = %s", rec.Status)
	}
	timeline, _ := c.Events.Search(ctx, events.SearchQuery{Query: "event.module:response"})
	if timeline.Total != 1 {
		t.Fatalf("response events = %d", timeline.Total)
	}

	// Empty long poll returns 204 quickly when wait=0.
	resp, _ = agent.Get(srv.URL + api.PathCommands + "?wait=0")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty poll = %d", resp.StatusCode)
	}

	// Revoked agents are refused.
	c.State.RevokeHost(ctx, enr.AgentID)
	resp, _ = agent.Post(srv.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked heartbeat = %d", resp.StatusCode)
	}
}
