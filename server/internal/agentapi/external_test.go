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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// enrollForTest enrolls an agent on the local listener and returns its ID and a client
// certificate.
func enrollForTest(t *testing.T, c *core.Core, local string, roots *x509.CertPool) (string, tls.Certificate) {
	t.Helper()
	tok, err := c.State.CreateToken(context.Background(), "test", "admin", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	body, _ := json.Marshal(api.EnrollRequest{
		Token:  tok.Token,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Host:   api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "windows"}, Arch: "amd64"},
	})
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	resp, err := anon.Post(local+api.PathEnroll, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var enr api.EnrollResponse
	json.NewDecoder(resp.Body).Decode(&enr)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll = %d", resp.StatusCode)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(enr.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return enr.AgentID, cert
}

func TestExternalListener(t *testing.T) {
	ctx := context.Background()
	c := newTestCore(t)
	local := httptest.NewUnstartedServer(New(c))
	local.TLS = c.PKI.TLSConfig()
	local.StartTLS()
	defer local.Close()
	verify := func(cert *x509.Certificate) error {
		h, err := c.State.GetHost(context.Background(), cert.Subject.CommonName)
		if err != nil || h.Revoked {
			return errors.New("refused")
		}
		return nil
	}
	ext := httptest.NewUnstartedServer(NewExternal(c))
	ext.TLS = c.PKI.StrictTLSConfig(verify)
	ext.StartTLS()
	defer ext.Close()

	roots := x509.NewCertPool()
	roots.AddCert(c.PKI.CACert)
	id, cert := enrollForTest(t, c, local.URL, roots)
	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs}, DisableKeepAlives: true,
		}}
	}

	// Without a certificate, nothing is reachable: the handshake fails.
	for _, path := range []string{api.PathEnroll, "/v1/ca.crt", "/v1/install/linux.sh", "/v1/install/windows.ps1", api.PathAgentRelease} {
		if resp, err := client().Get(ext.URL + path); err == nil {
			resp.Body.Close()
			t.Errorf("%s without a certificate: got HTTP %d", path, resp.StatusCode)
		}
	}
	// A certificate from another CA is refused too.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: cert.Leaf.SerialNumber, Subject: cert.Leaf.Subject, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &otherKey.PublicKey, otherKey)
	forged := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: otherKey}
	if resp, err := client(forged).Get(ext.URL + api.PathAgentRelease); err == nil {
		resp.Body.Close()
		t.Errorf("self-signed certificate with the agent's name: got HTTP %d", resp.StatusCode)
	}

	// An enrolled agent can report; enrollment and installer routes do not exist here.
	hb, _ := json.Marshal(api.Heartbeat{Host: api.HostInfo{Hostname: "laptop", OS: event.OS{Platform: "windows"}},
		Status: api.AgentStatus{Version: "test", AllowedActions: api.DefaultAllowedActions}})
	resp, err := client(cert).Post(ext.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat over the external listener = %d", resp.StatusCode)
	}
	for _, path := range []string{"/v1/ca.crt", "/v1/install/linux.sh", "/v1/install/windows.ps1"} {
		resp, err := client(cert).Get(ext.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s on the external listener = %d, want 404", path, resp.StatusCode)
		}
	}
	resp, err = client(cert).Post(ext.URL+api.PathEnroll, "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("enroll on the external listener = %d", resp.StatusCode)
	}

	// Once revoked, the agent cannot even complete the handshake.
	if err := c.State.RevokeHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	if resp, err := client(cert).Post(ext.URL+api.PathHeartbeat, "application/json", bytes.NewReader(hb)); err == nil {
		resp.Body.Close()
		t.Errorf("revoked agent: got HTTP %d", resp.StatusCode)
	}
}
