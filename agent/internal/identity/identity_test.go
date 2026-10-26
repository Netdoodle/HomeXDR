package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serial int64 = 10

func (ca *testCA) issue(t *testing.T, cn string, key *ecdsa.PrivateKey, days int) []byte {
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(0, 0, days),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func enrolled(t *testing.T) (string, *Identity, *testCA) {
	dir := t.TempDir()
	ca := newTestCA(t)
	key, _ := NewKey()
	certPEM := ca.issue(t, "agent-1", key, 365)
	cert, _ := ParseCertPEM(certPEM)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id := &Identity{AgentID: "agent-1", Key: key, CertPEM: certPEM, Cert: cert, CAPEM: ca.pem, CA: ca.cert, CommandKey: pub}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, loaded, ca
}

func TestRenewSwapsCertificate(t *testing.T) {
	dir, id, ca := enrolled(t)
	old := id.Certificate()
	key, _ := NewKey()
	certPEM := ca.issue(t, "agent-1", key, 730)
	if err := id.Renew(dir, key, certPEM); err != nil {
		t.Fatal(err)
	}
	if id.Certificate().SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Fatal("in-memory certificate not replaced")
	}
	c, _ := id.ClientCertificate(nil)
	if c.Leaf.SerialNumber.Cmp(id.Certificate().SerialNumber) != 0 {
		t.Fatal("TLS still presents the old certificate")
	}
	again, err := Load(dir)
	if err != nil || again.Certificate().SerialNumber.Cmp(id.Certificate().SerialNumber) != 0 {
		t.Fatalf("renewed identity not saved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, RenewFile)); !os.IsNotExist(err) {
		t.Fatal("renewal file left behind")
	}
	// A certificate for another agent or another key is refused.
	other, _ := NewKey()
	if err := id.Renew(dir, other, ca.issue(t, "agent-2", other, 365)); err == nil {
		t.Fatal("certificate for another agent accepted")
	}
	if err := id.Renew(dir, other, certPEM); err == nil {
		t.Fatal("certificate for another key accepted")
	}
}

// A crash after agent.renew and agent.key were written, but before agent.crt, leaves a
// mismatched pair; Load repairs it from agent.renew.
func TestLoadFinishesInterruptedRenewal(t *testing.T) {
	dir, _, ca := enrolled(t)
	key, _ := NewKey()
	certPEM := ca.issue(t, "agent-1", key, 730)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, RenewFile), append(append([]byte{}, keyPEM...), certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, KeyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := Load(dir)
	if err != nil {
		t.Fatalf("load after interrupted renewal: %v", err)
	}
	want, _ := ParseCertPEM(certPEM)
	if id.Certificate().SerialNumber.Cmp(want.SerialNumber) != 0 {
		t.Fatal("renewed certificate not installed")
	}
	if _, err := os.Stat(filepath.Join(dir, RenewFile)); !os.IsNotExist(err) {
		t.Fatal("renewal file left behind")
	}
}

func TestLoadDiscardsInvalidRenewal(t *testing.T) {
	dir, id, ca := enrolled(t)
	other, _ := NewKey()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(other)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), ca.issue(t, "someone-else", other, 365)...)
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, RenewFile), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Certificate().SerialNumber.Cmp(id.Certificate().SerialNumber) != 0 {
		t.Fatal("invalid renewal was installed")
	}
	if _, err := os.Stat(filepath.Join(dir, RenewFile)); !os.IsNotExist(err) {
		t.Fatal("invalid renewal file kept")
	}
}
