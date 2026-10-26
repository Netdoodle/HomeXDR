package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/identity"
	"github.com/Netdoodle/homexdr/agent/internal/transport"
	"github.com/Netdoodle/homexdr/shared/api"
)

// renewServer signs renewal CSRs; it requests client certificates without verifying
// them in the handshake, like the real server, so expired ones still reach it.
func renewServer(t *testing.T, agentLife, agentLeft time.Duration) (*identity.Identity, string, *atomic.Int32) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := cert(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour)},
		nil, &caKey.PublicKey, caKey)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := cert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "srv"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)},
		ca, &srvKey.PublicKey, caKey)
	agKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notAfter := time.Now().Add(agentLeft)
	ag := cert(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "agent-1"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: notAfter.Add(-agentLife), NotAfter: notAfter},
		ca, &agKey.PublicKey, caKey)

	var calls atomic.Int32
	serial := int64(10)
	h := http.NewServeMux()
	h.HandleFunc("POST "+api.PathRenew, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "agent-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req api.RenewRequest
		json.NewDecoder(r.Body).Decode(&req)
		blk, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		serial++
		der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{CommonName: "agent-1"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour)}, ca, csr.PublicKey, caKey)
		json.NewEncoder(w).Encode(api.RenewResponse{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	})
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srv.Raw, ca.Raw}, PrivateKey: srvKey}},
		ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return &identity.Identity{AgentID: "agent-1", Key: agKey, Cert: ag, CA: ca,
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})}, ts.URL, &calls
}

func renewAgent(t *testing.T, life, left time.Duration) (*Agent, *atomic.Int32) {
	t.Helper()
	id, url, calls := renewServer(t, life, left)
	client, err := transport.New(url, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return &Agent{client: client, log: quiet, id: id, dataDir: t.TempDir()}, calls
}

func TestRenewsNearExpiry(t *testing.T) {
	ctx := context.Background()
	// A third of the lifetime left: renew.
	a, calls := renewAgent(t, 300*24*time.Hour, 90*24*time.Hour)
	old := a.id.Certificate().SerialNumber
	a.maybeRenew(ctx)
	if calls.Load() != 1 || a.id.Certificate().SerialNumber.Cmp(old) == 0 {
		t.Fatalf("not renewed: %d calls", calls.Load())
	}
	if time.Until(a.id.Certificate().NotAfter) < 300*24*time.Hour {
		t.Fatal("renewed certificate has the old expiry")
	}
	saved, err := identity.ParseCertPEM(mustRead(t, a.dataDir, identity.CertFile))
	if err != nil || saved.SerialNumber.Cmp(a.id.Certificate().SerialNumber) != 0 {
		t.Fatalf("renewed certificate not saved: %v", err)
	}
	// Now well inside its lifetime: no further renewal.
	a.lastRenew = time.Time{}
	a.maybeRenew(ctx)
	if calls.Load() != 1 {
		t.Fatalf("renewed again: %d calls", calls.Load())
	}
}

func TestRenewsAfterExpiryButNotEarly(t *testing.T) {
	ctx := context.Background()
	fresh, calls := renewAgent(t, 365*24*time.Hour, 200*24*time.Hour)
	fresh.maybeRenew(ctx)
	if calls.Load() != 0 {
		t.Fatal("renewed a certificate with most of its life left")
	}
	expired, calls := renewAgent(t, 365*24*time.Hour, -24*time.Hour)
	expired.maybeRenew(ctx)
	if calls.Load() != 1 || time.Until(expired.id.Certificate().NotAfter) <= 0 {
		t.Fatalf("expired certificate not renewed: %d calls", calls.Load())
	}
}

func mustRead(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
