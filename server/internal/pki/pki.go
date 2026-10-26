// Package pki manages the server's private CA, its agent-listener certificate, client
// certificates for enrolled agents, and the Ed25519 key that signs agent commands.
//
// Everything lives in <data>/pki and is created on first start:
//
//	ca.crt / ca.key           ECDSA P-256 root, 10 years
//	server.crt / server.key   agent listener cert, re-issued when the SAN list changes
//	command.key               Ed25519 seed (32 bytes, raw)
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// AgentCertValidity is how long enrolled agent certificates are valid.
const AgentCertValidity = 365 * 24 * time.Hour

// PKI holds the loaded key material.
type PKI struct {
	dir        string
	CACert     *x509.Certificate
	caKey      crypto.Signer
	CAPEM      []byte
	serverCert tls.Certificate
	commandKey ed25519.PrivateKey
}

// Load opens or creates the PKI in dir, issuing a server certificate for names.
func Load(dir string, names []string) (*PKI, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &PKI{dir: dir}
	if err := p.loadOrCreateCA(); err != nil {
		return nil, fmt.Errorf("pki: CA: %w", err)
	}
	if err := p.loadOrCreateServerCert(names); err != nil {
		return nil, fmt.Errorf("pki: server cert: %w", err)
	}
	if err := p.loadOrCreateCommandKey(); err != nil {
		return nil, fmt.Errorf("pki: command key: %w", err)
	}
	return p, nil
}

// CAPin returns "sha256:<hex>" of the CA certificate's DER, the value agents pass to
// --ca-pin.
func (p *PKI) CAPin() string {
	sum := sha256.Sum256(p.CACert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CommandPublicKey returns the Ed25519 public key agents pin.
func (p *PKI) CommandPublicKey() ed25519.PublicKey {
	return p.commandKey.Public().(ed25519.PublicKey)
}

// SignCommand signs a command payload.
func (p *PKI) SignCommand(payload []byte) []byte {
	return ed25519.Sign(p.commandKey, payload)
}

// TLSConfig returns the agent-listener TLS config. Client certificates are verified when
// presented; handlers decide which routes require one.
func (p *PKI) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(p.CACert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{p.serverCert},
		// Client certificates are requested but checked by VerifyAgentCert, not by the
		// handshake, so that an agent whose certificate expired can still renew it. The
		// handshake still proves the client holds the certificate's private key.
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  pool,
	}
}

// VerifyAgentCert checks that the client certificate chain from a TLS handshake was
// issued by the CA for client authentication. allowExpired accepts a certificate past
// its NotAfter (for renewal); everything else about it must still be valid.
func (p *PKI) VerifyAgentCert(chain []*x509.Certificate, allowExpired bool) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("client certificate required")
	}
	leaf := chain[0]
	roots := x509.NewCertPool()
	roots.AddCert(p.CACert)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if allowExpired && time.Now().After(leaf.NotAfter) {
		opts.CurrentTime = leaf.NotAfter.Add(-time.Second)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, err
	}
	return leaf, nil
}

// SignAgentCSR verifies a PEM CSR and issues a client certificate with CN=agentID.
// It returns the certificate PEM and its serial number (hex).
func (p *PKI) SignAgentCSR(csrPEM []byte, agentID string) ([]byte, string, error) {
	now := time.Now()
	return p.SignAgentCSRValidity(csrPEM, agentID, now.Add(-5*time.Minute), now.Add(AgentCertValidity))
}

// SignAgentCSRValidity is SignAgentCSR with an explicit validity period (tests use it
// to issue already-expired certificates).
func (p *PKI) SignAgentCSRValidity(csrPEM []byte, agentID string, notBefore, notAfter time.Time) ([]byte, string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", errors.New("csr: not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("csr: bad signature: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, "", errors.New("csr: ECDSA key must be P-256 or P-384")
		}
	case ed25519.PublicKey:
	default:
		return nil, "", errors.New("csr: key must be ECDSA or Ed25519")
	}
	serial, err := randSerial()
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"HomeXDR agent"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CACert, csr.PublicKey, p.caKey)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial.Text(16), nil
}

func (p *PKI) loadOrCreateCA() error {
	certPath, keyPath := filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key")
	if fileExists(certPath) && fileExists(keyPath) {
		cert, key, err := loadPair(certPath, keyPath)
		if err != nil {
			return err
		}
		p.CACert, p.caKey = cert, key
		p.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "HomeXDR CA", Organization: []string{"HomeXDR"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := writePair(certPath, keyPath, der, key); err != nil {
		return err
	}
	p.CACert, p.caKey = cert, key
	p.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return nil
}

func (p *PKI) loadOrCreateServerCert(names []string) error {
	certPath, keyPath := filepath.Join(p.dir, "server.crt"), filepath.Join(p.dir, "server.key")
	want := normalizeNames(names)
	if fileExists(certPath) && fileExists(keyPath) {
		cert, key, err := loadPair(certPath, keyPath)
		if err == nil && slices.Equal(certNames(cert), want) &&
			time.Until(cert.NotAfter) > 30*24*time.Hour && cert.CheckSignatureFrom(p.CACert) == nil {
			p.serverCert = tls.Certificate{Certificate: [][]byte{cert.Raw, p.CACert.Raw}, PrivateKey: key, Leaf: cert}
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: want[0], Organization: []string{"HomeXDR server"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range want {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CACert, &key.PublicKey, p.caKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := writePair(certPath, keyPath, der, key); err != nil {
		return err
	}
	// Present the CA too, so agents can check it against their --ca-pin during enrollment.
	p.serverCert = tls.Certificate{Certificate: [][]byte{der, p.CACert.Raw}, PrivateKey: key, Leaf: cert}
	return nil
}

func (p *PKI) loadOrCreateCommandKey() error {
	path := filepath.Join(p.dir, "command.key")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != ed25519.SeedSize {
			return fmt.Errorf("%s: want %d bytes, got %d", path, ed25519.SeedSize, len(b))
		}
		p.commandKey = ed25519.NewKeyFromSeed(b)
		return nil
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return err
	}
	p.commandKey = ed25519.NewKeyFromSeed(seed)
	return nil
}

func normalizeNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = []string{"localhost"}
	}
	first := out[0]
	rest := out[1:]
	sort.Strings(rest)
	return append([]string{first}, rest...)
}

func certNames(c *x509.Certificate) []string {
	var names []string
	names = append(names, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	// Put the CN first to mirror normalizeNames.
	out := []string{c.Subject.CommonName}
	var rest []string
	for _, n := range names {
		if n != c.Subject.CommonName {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func loadPair(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cblock, _ := pem.Decode(cb)
	if cblock == nil {
		return nil, nil, fmt.Errorf("%s: no PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kblock, _ := pem.Decode(kb)
	if kblock == nil {
		return nil, nil, fmt.Errorf("%s: no PEM block", keyPath)
	}
	k, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("%s: not a signing key", keyPath)
	}
	return cert, signer, nil
}

func writePair(certPath, keyPath string, der []byte, key crypto.Signer) error {
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
