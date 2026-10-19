package core

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/identity"
	"github.com/Doodlebug12/homexdr/agent/internal/spool"
	"github.com/Doodlebug12/homexdr/agent/internal/transport"
	"github.com/Doodlebug12/homexdr/shared/api"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func cert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, pub any, signer any) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// fakeServer is a TLS agent API that accepts events, with knobs for failures.
type fakeServer struct {
	mu       sync.Mutex
	got      []string
	maxLines int // more lines than this -> 413
	status   int // if set, every request gets this status
	calls    int
}

func newIdentityAndServer(t *testing.T, fs *fakeServer) (*identity.Identity, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := cert(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)},
		nil, &caKey.PublicKey, caKey)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := cert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "srv"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)},
		ca, &srvKey.PublicKey, caKey)
	agKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ag := cert(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "agent-1"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)},
		ca, &agKey.PublicKey, caKey)

	h := http.NewServeMux()
	h.HandleFunc("POST "+api.PathEvents, func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 || r.Header.Get(api.HeaderProtocol) != api.ProtocolVersion {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.calls++
		if fs.status != 0 {
			w.WriteHeader(fs.status)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var lines []string
		sc := bufio.NewScanner(zr)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		if fs.maxLines > 0 && len(lines) > fs.maxLines {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		fs.got = append(fs.got, lines...)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(api.EventsResponse{Accepted: len(lines)})
	})
	ts := httptest.NewUnstartedServer(h)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srv.Raw, ca.Raw}, PrivateKey: srvKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return &identity.Identity{AgentID: "agent-1", Key: agKey, Cert: ag, CA: ca}, ts.URL
}

func setup(t *testing.T, fs *fakeServer, n int) (*Agent, *spool.Spool, *spool.Batch) {
	t.Helper()
	id, url := newIdentityAndServer(t, fs)
	client, err := transport.New(url, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	sp, err := spool.Open(t.TempDir(), 64<<20, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sp.Close() })
	for i := range n {
		sp.Append([]byte(fmt.Sprintf(`{"id":"e%02d"}`, i)))
	}
	b, err := sp.Next(1000, maxBatchBytes)
	if err != nil || b == nil {
		t.Fatal(err)
	}
	return &Agent{client: client, log: quiet}, sp, b
}

func TestSendSplitsOn413(t *testing.T) {
	fs := &fakeServer{maxLines: 3}
	a, sp, b := setup(t, fs, 10)
	if err := a.sendRange(context.Background(), b, 0, len(b.Lines)); err != nil {
		t.Fatal(err)
	}
	if len(fs.got) != 10 || fs.got[0] != `{"id":"e00"}` || fs.got[9] != `{"id":"e09"}` {
		t.Fatalf("server got %v", fs.got)
	}
	if a.sent.Load() != 10 || sp.Stats().Events != 0 {
		t.Fatalf("sent %d, queued %d", a.sent.Load(), sp.Stats().Events)
	}
}

func TestSendDropsSingleOversizeEvent(t *testing.T) {
	fs := &fakeServer{maxLines: 0, status: http.StatusRequestEntityTooLarge}
	a, sp, b := setup(t, fs, 1)
	if err := a.sendRange(context.Background(), b, 0, 1); err != nil {
		t.Fatal(err)
	}
	if a.dropped.Load() != 1 || sp.Stats().Events != 0 {
		t.Fatalf("dropped %d queued %d", a.dropped.Load(), sp.Stats().Events)
	}
}

func TestSendDropsOn4xx(t *testing.T) {
	fs := &fakeServer{status: http.StatusBadRequest}
	a, sp, b := setup(t, fs, 4)
	if err := a.sendRange(context.Background(), b, 0, 4); err != nil {
		t.Fatal(err)
	}
	if a.dropped.Load() != 4 || sp.Stats().Events != 0 {
		t.Fatalf("dropped %d queued %d", a.dropped.Load(), sp.Stats().Events)
	}
}

func TestSendKeepsBatchOn5xxAnd429(t *testing.T) {
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusRequestTimeout} {
		fs := &fakeServer{status: code}
		a, sp, b := setup(t, fs, 4)
		err := a.sendRange(context.Background(), b, 0, 4)
		if err == nil || !transport.Retryable(err) {
			t.Fatalf("%d: want retryable error, got %v", code, err)
		}
		if sp.Stats().Events != 4 || a.dropped.Load() != 0 {
			t.Fatalf("%d: queued %d dropped %d", code, sp.Stats().Events, a.dropped.Load())
		}
	}
}

func TestSensorKindsAndConfig(t *testing.T) {
	cfg := api.DefaultAgentConfig()
	if _, on := kindConfig("library", cfg.Sensors); on {
		t.Error("library is off by default")
	}
	if !strings.Contains(strings.Join(sensorKinds("windows"), ","), "registry") || strings.Contains(strings.Join(sensorKinds("linux"), ","), "registry") {
		t.Error("platform sensor kinds")
	}
	a := fingerprint(cfg.Sensors.Process)
	cfg.Sensors.Process.HashExecutables = false
	if fingerprint(cfg.Sensors.Process) == a {
		t.Error("fingerprint did not change with the config")
	}
}
