package agentapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// A removed host's certificate is refused, on every agent route including renewal, and
// presenting it cannot bring the host back: only enrolling with a token makes a host, under
// a new ID.
func TestRemovedHostCertificateIsRefused(t *testing.T) {
	ctx := context.Background()
	c := newTestCore(t)
	srv := httptest.NewUnstartedServer(New(c))
	srv.TLS = c.PKI.TLSConfig()
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	tok, err := c.State.CreateToken(ctx, "test", "admin", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	info := api.HostInfo{Hostname: "gone-1", OS: event.OS{Platform: "linux", Name: "Ubuntu"}, Arch: "amd64"}
	body, _ := json.Marshal(api.EnrollRequest{Token: tok.Token, CSRPEM: csr, Host: info})
	resp, err := anon.Post(srv.URL+api.PathEnroll, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var enr api.EnrollResponse
	json.NewDecoder(resp.Body).Decode(&enr)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("enroll = %d", resp.StatusCode)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(enr.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	agent := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}}}
	hb, _ := json.Marshal(api.Heartbeat{Host: info, Status: api.AgentStatus{Version: "test"}})
	post := func(path string, b []byte) int {
		t.Helper()
		r, err := agent.Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if got := post(api.PathHeartbeat, hb); got != 200 {
		t.Fatalf("heartbeat before removal = %d", got)
	}

	if _, err := c.State.RemoveHost(ctx, enr.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.State.GetHost(ctx, enr.AgentID); err != store.ErrNotFound {
		t.Fatalf("host still there: %v", err)
	}
	renew, _ := json.Marshal(api.RenewRequest{CSRPEM: csr})
	for name, got := range map[string]int{
		"heartbeat": post(api.PathHeartbeat, hb),
		"events":    post(api.PathEvents, []byte(`{}`)),
		"renew":     post(api.PathRenew, renew),
	} {
		if got != http.StatusUnauthorized {
			t.Errorf("%s with a removed host's certificate = %d, want 401", name, got)
		}
	}
	if r, err := agent.Get(srv.URL + api.PathCommands + "?wait=0"); err != nil {
		t.Fatal(err)
	} else if r.Body.Close(); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("commands poll with a removed host's certificate = %d, want 401", r.StatusCode)
	}
	// Nothing above brought the host back.
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{IncludeDecommissioned: true})
	if err != nil || len(hosts) != 0 {
		t.Fatalf("hosts after refused requests = %d, %v", len(hosts), err)
	}
	// The same certificate cannot be used to enroll either: that needs a token, and
	// makes a new identity.
	body, _ = json.Marshal(api.EnrollRequest{Token: "not-a-token", CSRPEM: csr, Host: info})
	resp, _ = anon.Post(srv.URL+api.PathEnroll, "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enroll without a valid token = %d", resp.StatusCode)
	}
}
