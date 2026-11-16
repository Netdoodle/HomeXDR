package console

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/consoletls"
)

// The console served over TLS with the HomeXDR CA's certificate: /healthz and the public
// CA download work, and a client that trusts the CA connects without errors.
func TestConsoleOverHTTPSWithCA(t *testing.T) {
	c, _ := setup(t)
	mux := http.NewServeMux()
	mux.Handle("/api/", New(c))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = consoletls.Config(nil, c.PKI.ServerCertificate())
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(c.PKI.CACert)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}

	resp, err := hc.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/healthz = %d", resp.StatusCode)
	}

	resp, err = hc.Get(srv.URL + "/api/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("/api/ca.crt = %d %q", resp.StatusCode, body)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "homexdr-ca.crt") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent with the HomeXDR CA")
	}
}
