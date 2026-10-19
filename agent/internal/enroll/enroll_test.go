package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/identity"
	"github.com/Doodlebug12/homexdr/agent/internal/transport"
	"github.com/Doodlebug12/homexdr/shared/api"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, pub any, cn string, eku x509.ExtKeyUsage) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
		// Deliberately not the address the client dials: hostnames are not checked.
		DNSNames: []string{"xdr.example.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// server starts an agent-API stand-in presenting [leaf, CA].
func server(t *testing.T, ca *testCA, bodyCA []byte) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	cmdPub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.issue(t, &key.PublicKey, "server", x509.ExtKeyUsageServerAuth)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req api.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}
		blk, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		der := ca.issue(t, csr.PublicKey, "agent-123", x509.ExtKeyUsageClientAuth)
		json.NewEncoder(w).Encode(api.EnrollResponse{
			AgentID: "agent-123", CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CAPEM: string(bodyCA), CommandKey: base64.StdEncoding.EncodeToString(cmdPub), Config: api.DefaultAgentConfig(),
		})
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf, ca.cert.Raw}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, cmdPub
}

func host() api.HostInfo { return api.HostInfo{Hostname: "h1"} }

func TestEnrollWithPin(t *testing.T) {
	ca := newCA(t)
	srv, cmdPub := server(t, ca, ca.pem)
	res, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "good", CAPin: identity.Pin(ca.cert), Host: host()})
	if err != nil {
		t.Fatal(err)
	}
	id := res.Identity
	if id.AgentID != "agent-123" || !id.CommandKey.Equal(cmdPub) || identity.Pin(id.CA) != identity.Pin(ca.cert) {
		t.Fatalf("identity %+v", id)
	}
	// The saved identity loads back and its TLS config trusts only the pinned CA.
	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Load(dir); err != nil {
		t.Fatal(err)
	}
	cfg := transport.TLSConfig(id)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), cfg)
	if err != nil {
		t.Fatalf("post-enrollment TLS to the pinned server: %v", err)
	}
	conn.Close()
}

func TestEnrollPinMismatch(t *testing.T) {
	ca := newCA(t)
	srv, _ := server(t, ca, ca.pem)
	other := newCA(t)
	_, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "good", CAPin: identity.Pin(other.cert), Host: host()})
	if err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("want pin mismatch, got %v", err)
	}
}

func TestEnrollNeedsPinOrTOFU(t *testing.T) {
	ca := newCA(t)
	srv, _ := server(t, ca, ca.pem)
	_, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "good", Host: host()})
	if !errors.Is(err, ErrNoPin) {
		t.Fatalf("want ErrNoPin, got %v", err)
	}
	res, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "good", InsecureTOFU: true, Host: host()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pin != identity.Pin(ca.cert) {
		t.Fatalf("TOFU pin %s", res.Pin)
	}
}

func TestEnrollRejectsSwappedCA(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	srv, _ := server(t, ca, other.pem) // body claims a different CA than the handshake
	_, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "good", CAPin: identity.Pin(ca.cert), Host: host()})
	if err == nil || !strings.Contains(err.Error(), "differs from the pinned CA") {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollBadToken(t *testing.T) {
	ca := newCA(t)
	srv, _ := server(t, ca, ca.pem)
	_, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "bad", CAPin: identity.Pin(ca.cert), Host: host()})
	if err == nil || !strings.Contains(err.Error(), "invalid or expired") {
		t.Fatalf("got %v", err)
	}
}

func TestServerWithClientCertRejected(t *testing.T) {
	// A certificate with only ClientAuth (like an agent's) must not pass as a server.
	ca := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.issue(t, &key.PublicKey, "agent-x", x509.ExtKeyUsageClientAuth)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf, ca.cert.Raw}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	_, err = Enroll(context.Background(), Options{ServerURL: "https://" + ln.Addr().(*net.TCPAddr).String(), Token: "good", CAPin: identity.Pin(ca.cert), Host: host()})
	if err == nil {
		t.Fatal("client-auth-only certificate accepted as server")
	}
}

func TestParseServerURL(t *testing.T) {
	for _, bad := range []string{"http://x:8443", "x:8443", "https://"} {
		if _, err := transport.ParseServerURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	u, err := transport.ParseServerURL("https://xdr.lan:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if h, p := transport.ServerHostPort(u); h != "xdr.lan" || p != 8443 {
		t.Fatalf("%s %d", h, p)
	}
}
