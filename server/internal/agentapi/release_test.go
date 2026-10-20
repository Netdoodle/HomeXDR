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
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// TestAgentUpdateOffer checks that a signed release is offered in heartbeats to agents
// on another version, and that the manifest and signature it serves verify.
func TestAgentUpdateOffer(t *testing.T) {
	downloads, sigs := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(downloads, "homexdr-agent-linux-amd64"), []byte("new agent"), 0o755)
	if _, err := core.WriteManifest(downloads, "v9", "abc", 900); err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile(filepath.Join(downloads, api.AgentReleaseName))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(filepath.Join(sigs, core.UpdateKeyFile), []byte(api.FormatUpdateKey(pub)), 0o644)
	os.WriteFile(filepath.Join(sigs, core.SignatureFile(manifest)), api.SignRelease(priv, manifest), 0o644)

	c := newTestCoreWith(t, func(cfg *config.Config) { cfg.DownloadsDir, cfg.SignaturesDir = downloads, sigs })
	srv := httptest.NewUnstartedServer(New(c))
	srv.TLS = c.PKI.TLSConfig()
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}

	get := func(path string) []byte {
		t.Helper()
		resp, err := anon.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s = %d %s", path, resp.StatusCode, b)
		}
		return b
	}
	if _, err := api.VerifyRelease(pub, get(api.PathAgentRelease), get(api.PathAgentReleaseSig)); err != nil {
		t.Fatalf("served release does not verify: %v", err)
	}

	tok, _ := c.State.CreateToken(context.Background(), "t", "admin", nil, nil, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	host := api.HostInfo{Hostname: "u1", OS: event.OS{Platform: "linux"}, Arch: "amd64"}
	body, _ := json.Marshal(api.EnrollRequest{Token: tok.Token, Host: host,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	resp, err := anon.Post(srv.URL+api.PathEnroll, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var enr api.EnrollResponse
	json.NewDecoder(resp.Body).Decode(&enr)
	resp.Body.Close()
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(enr.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	agent := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}}}

	heartbeat := func(version string) *api.AgentUpdate {
		t.Helper()
		hb, _ := json.Marshal(api.Heartbeat{Host: host, Status: api.AgentStatus{Version: version}})
		resp, err := agent.Post(srv.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var hbr api.HeartbeatResponse
		json.NewDecoder(resp.Body).Decode(&hbr)
		return hbr.Update
	}
	if u := heartbeat("v8"); u == nil || u.Version != "v9" || u.CommitTime != 900 {
		t.Fatalf("v8 agent offered %+v", u)
	}
	if u := heartbeat("v9"); u != nil {
		t.Fatalf("up-to-date agent offered %+v", u)
	}
}
