package consoletls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// writePair writes a self-signed certificate and key; the CN identifies it.
func writePair(t *testing.T, dir, cn string, mod time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	return
}

func cnOf(t *testing.T, f *FileCert) string {
	t.Helper()
	c, err := f.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestFileCertReloadsAndKeepsOldOnBadFile(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	cp, kp := writePair(t, dir, "one", base)
	f, err := NewFileCert(cp, kp, quiet)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	f.now = func() time.Time { return clock }
	f.lastTest = clock

	if got := cnOf(t, f); got != "one" {
		t.Fatalf("initial = %q", got)
	}

	// Replaced, but within the minute: not looked at yet.
	writePair(t, dir, "two", base.Add(time.Minute))
	if got := cnOf(t, f); got != "one" {
		t.Fatalf("before recheck = %q", got)
	}
	clock = clock.Add(61 * time.Second)
	if got := cnOf(t, f); got != "two" {
		t.Fatalf("after replacement = %q", got)
	}

	// An invalid replacement keeps the previous certificate.
	if err := os.WriteFile(cp, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := base.Add(2 * time.Minute)
	if err := os.Chtimes(cp, later, later); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(61 * time.Second)
	if got := cnOf(t, f); got != "two" {
		t.Fatalf("after bad file = %q", got)
	}

	// A good file after the bad one is picked up again.
	writePair(t, dir, "three", base.Add(3*time.Minute))
	clock = clock.Add(61 * time.Second)
	if got := cnOf(t, f); got != "three" {
		t.Fatalf("after recovery = %q", got)
	}
}

func TestNewFileCertRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writePair(t, dir, "one", time.Now())
	if err := os.WriteFile(kp, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileCert(cp, kp, quiet); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := NewFileCert(filepath.Join(dir, "missing"), kp, quiet); err == nil {
		t.Fatal("missing certificate accepted")
	}
}

func TestRedirect(t *testing.T) {
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain:"+r.URL.Path) })
	h := Redirect(":8448", plain)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://nas.lan:8080/alerts?x=1", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("code = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://nas.lan:8448/alerts?x=1" {
		t.Fatalf("Location = %q", loc)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://nas.lan:8080/healthz", nil))
	if rec.Code != 200 || rec.Body.String() != "plain:/healthz" {
		t.Fatalf("/healthz = %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://[::1]:8080/", nil))
	if loc := rec.Header().Get("Location"); loc != "https://[::1]:8448/" {
		t.Fatalf("IPv6 Location = %q", loc)
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	h := HSTS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	plain := httptest.NewRecorder()
	h.ServeHTTP(plain, httptest.NewRequest("GET", "http://x/", nil))
	if plain.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS on plain HTTP")
	}
	secure := httptest.NewRecorder()
	h.ServeHTTP(secure, httptest.NewRequest("GET", "https://x/", nil))
	if got := secure.Header().Get("Strict-Transport-Security"); got != "max-age=15552000" {
		t.Fatalf("HSTS = %q", got)
	}
}
