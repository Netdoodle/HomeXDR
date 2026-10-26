package agentapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type lifecycle struct {
	t     *testing.T
	c     *core.Core
	srv   *httptest.Server
	roots *x509.CertPool
}

func newLifecycle(t *testing.T) *lifecycle {
	c := newTestCore(t)
	srv := httptest.NewUnstartedServer(New(c))
	srv.TLS = c.PKI.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	return &lifecycle{t: t, c: c, srv: srv, roots: roots}
}

func newCSR(t *testing.T) (*ecdsa.PrivateKey, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// client returns an HTTP client presenting certPEM with key.
func (l *lifecycle) client(certPEM string, key *ecdsa.PrivateKey) *http.Client {
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(certPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		l.t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: l.roots, Certificates: []tls.Certificate{cert}}}}
}

func (l *lifecycle) enroll() (string, string, *ecdsa.PrivateKey) {
	tok, err := l.c.State.CreateToken(context.Background(), "test", "admin", nil, nil, nil)
	if err != nil {
		l.t.Fatal(err)
	}
	key, csr := newCSR(l.t)
	body, _ := json.Marshal(api.EnrollRequest{Token: tok.Token, CSRPEM: csr,
		Host: api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "linux"}}})
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: l.roots}}}
	resp, err := anon.Post(l.srv.URL+api.PathEnroll, "application/json", bytes.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	var enr api.EnrollResponse
	json.NewDecoder(resp.Body).Decode(&enr)
	if resp.StatusCode != 200 {
		l.t.Fatalf("enroll: %d", resp.StatusCode)
	}
	return enr.AgentID, enr.CertPEM, key
}

func (l *lifecycle) post(c *http.Client, path string, v any) (int, string) {
	l.t.Helper()
	body, _ := json.Marshal(v)
	resp, err := c.Post(l.srv.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (l *lifecycle) heartbeat(c *http.Client) (int, string) {
	return l.post(c, api.PathHeartbeat, api.Heartbeat{
		Host:   api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "linux"}},
		Status: api.AgentStatus{Version: "test"},
	})
}

func (l *lifecycle) renew(c *http.Client) (string, *ecdsa.PrivateKey, int, string) {
	key, csr := newCSR(l.t)
	code, body := l.post(c, api.PathRenew, api.RenewRequest{CSRPEM: csr})
	var rr api.RenewResponse
	json.Unmarshal([]byte(body), &rr)
	return rr.CertPEM, key, code, body
}

func TestCertificateRenewal(t *testing.T) {
	ctx := context.Background()
	l := newLifecycle(t)
	id, certA, keyA := l.enroll()
	a := l.client(certA, keyA)
	if code, body := l.heartbeat(a); code != 200 {
		t.Fatalf("heartbeat A: %d %s", code, body)
	}
	if h, _ := l.c.State.GetHost(ctx, id); h.CertExpires == nil || time.Until(*h.CertExpires) < 300*24*time.Hour {
		t.Fatalf("cert expiry not recorded: %+v", h.CertExpires)
	}

	// Renew: the old certificate keeps working until the new one is used.
	certB, keyB, code, body := l.renew(a)
	if code != 200 || certB == "" {
		t.Fatalf("renew: %d %s", code, body)
	}
	if code, _ := l.heartbeat(a); code != 200 {
		t.Fatalf("old certificate refused before the new one was used: %d", code)
	}
	b := l.client(certB, keyB)
	if code, body := l.heartbeat(b); code != 200 {
		t.Fatalf("heartbeat B: %d %s", code, body)
	}
	if code, body := l.heartbeat(l.client(certA, keyA)); code != 403 || !strings.Contains(body, "superseded") {
		t.Fatalf("old certificate after switch: %d %s", code, body)
	}

	// An expired certificate is refused everywhere except renewal.
	key, csr := newCSR(t)
	expiredPEM, serial, err := l.c.PKI.SignAgentCSRValidity([]byte(csr), id, time.Now().Add(-4*time.Minute), time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(expiredPEM)
	expCert, _ := x509.ParseCertificate(blk.Bytes)
	if err := l.c.State.UseCert(ctx, id, serial, expCert.NotAfter); err != nil {
		t.Fatal(err)
	}
	expired := l.client(string(expiredPEM), key)
	if code, body := l.heartbeat(expired); code != 401 || !strings.Contains(body, "expired") {
		t.Fatalf("expired heartbeat: %d %s", code, body)
	}
	certC, keyC, code, body := l.renew(expired)
	if code != 200 {
		t.Fatalf("renew with expired certificate: %d %s", code, body)
	}
	if code, body := l.heartbeat(l.client(certC, keyC)); code != 200 {
		t.Fatalf("heartbeat after renewing an expired certificate: %d %s", code, body)
	}

	// A certificate from another CA is refused, renewal included.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &otherKey.PublicKey, otherKey)
	forged := l.client(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), otherKey)
	if _, _, code, _ := l.renew(forged); code != 401 {
		t.Fatalf("renew with a foreign certificate: %d", code)
	}

	// Revoked agents cannot renew.
	if err := l.c.State.RevokeHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, code, body := l.renew(l.client(certC, keyC)); code != 403 || !strings.Contains(body, "revoked") {
		t.Fatalf("renew when revoked: %d %s", code, body)
	}
}

func TestDecommissionedAgentIsRestored(t *testing.T) {
	ctx := context.Background()
	l := newLifecycle(t)
	id, cert, key := l.enroll()
	if err := l.c.State.DecommissionHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	if hosts, _ := l.c.State.ListHosts(ctx, store.HostFilter{}); len(hosts) != 0 {
		t.Fatalf("decommissioned host still listed: %d", len(hosts))
	}
	if hosts, _ := l.c.State.ListHosts(ctx, store.HostFilter{Status: "decommissioned"}); len(hosts) != 1 {
		t.Fatalf("decommissioned filter: %d", len(hosts))
	}
	if code, body := l.heartbeat(l.client(cert, key)); code != 200 {
		t.Fatalf("heartbeat: %d %s", code, body)
	}
	h, _ := l.c.State.GetHost(ctx, id)
	if h.DecommissionedAt != nil || h.Status != "online" {
		t.Fatalf("not restored: %+v", h)
	}
	entries, _, err := l.c.State.ListAudit(ctx, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		found = found || e.Action == "agent.recommission"
	}
	if !found {
		t.Fatal("no agent.recommission audit entry")
	}
}

func TestHeartbeatOffersArchivedRelease(t *testing.T) {
	dir := t.TempDir()
	downloads, sigs := filepath.Join(dir, "downloads"), filepath.Join(dir, "sigs")
	os.MkdirAll(downloads, 0o755)
	os.MkdirAll(sigs, 0o755)
	os.WriteFile(filepath.Join(downloads, "homexdr-agent-linux-amd64"), []byte("new agent"), 0o755)
	if _, err := core.WriteManifest(downloads, "0.0.0-20261101000000.new", "new", 2000000000); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m, _ := os.ReadFile(filepath.Join(downloads, api.AgentReleaseName))
	os.WriteFile(filepath.Join(sigs, core.UpdateKeyFile), []byte(api.FormatUpdateKey(pub)), 0o644)
	os.WriteFile(filepath.Join(sigs, core.SignatureFile(m)), api.SignRelease(priv, m), 0o644)

	c := newTestCoreWith(t, func(cfg *config.Config) {
		cfg.DownloadsDir, cfg.SignaturesDir, cfg.ReleasesDir, cfg.ReleasesKeep = downloads, sigs, filepath.Join(dir, "releases"), 5
	})
	srv := httptest.NewUnstartedServer(New(c))
	srv.TLS = c.PKI.TLSConfig()
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	l := &lifecycle{t: t, c: c, srv: srv, roots: roots}
	_, cert, key := l.enroll()

	code, body := l.post(l.client(cert, key), api.PathHeartbeat, api.Heartbeat{
		Host:   api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "linux"}},
		Status: api.AgentStatus{Version: "0.0.0-20261001000000.old"},
	})
	var hbr api.HeartbeatResponse
	json.Unmarshal([]byte(body), &hbr)
	want := api.PathReleases + "0.0.0-20261101000000.new/"
	if code != 200 || hbr.Update == nil || hbr.Update.Path != want {
		t.Fatalf("heartbeat offer: %d %s", code, body)
	}
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	for name, wantCode := range map[string]int{
		api.AgentReleaseName: 200, api.AgentReleaseName + ".sig": 200, "homexdr-agent-linux-amd64": 200, "secret.txt": 404,
	} {
		resp, err := anon.Get(srv.URL + want + name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != wantCode {
			t.Errorf("GET %s: %d", name, resp.StatusCode)
		}
		if name == "homexdr-agent-linux-amd64" && string(b) != "new agent" {
			t.Errorf("binary %q", b)
		}
	}
	// The offered release's signature verifies with the release key.
	resp, _ := anon.Get(srv.URL + want + api.AgentReleaseName)
	manifest, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp, _ = anon.Get(srv.URL + want + api.AgentReleaseName + ".sig")
	sig, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if _, err := api.VerifyRelease(pub, manifest, sig); err != nil {
		t.Fatalf("archived release does not verify: %v", err)
	}
}
