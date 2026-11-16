// Package consoletls holds the pieces of the console's optional HTTPS listener: a
// certificate loader that follows renewed files, the HSTS header and the HTTP redirect.
package consoletls

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// recheckEvery bounds how often the certificate files are examined.
const recheckEvery = time.Minute

// FileCert serves a certificate from PEM files and reloads it when either file changes.
type FileCert struct {
	certPath, keyPath string
	log               *slog.Logger
	now               func() time.Time

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastTest time.Time
}

// NewFileCert loads the files once and fails when they are not a valid pair.
func NewFileCert(certPath, keyPath string, log *slog.Logger) (*FileCert, error) {
	f := &FileCert{certPath: certPath, keyPath: keyPath, log: log, now: time.Now}
	cs, err := os.Stat(certPath)
	if err != nil {
		return nil, err
	}
	ks, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("console TLS certificate: %w", err)
	}
	f.cert, f.certMod, f.keyMod = &c, cs.ModTime(), ks.ModTime()
	f.lastTest = f.now()
	return f, nil
}

// GetCertificate is a tls.Config.GetCertificate. Files are re-examined at most once a minute;
// a bad replacement keeps the previous certificate and logs a warning.
func (f *FileCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now := f.now(); now.Sub(f.lastTest) >= recheckEvery {
		f.lastTest = now
		cs, cerr := os.Stat(f.certPath)
		ks, kerr := os.Stat(f.keyPath)
		switch {
		case cerr != nil || kerr != nil:
			f.log.Warn("console TLS certificate files cannot be read; keeping the previous certificate", "cert", f.certPath, "key", f.keyPath)
		case !cs.ModTime().Equal(f.certMod) || !ks.ModTime().Equal(f.keyMod):
			// Remember the new times either way, so a bad file is not retried until it changes again.
			f.certMod, f.keyMod = cs.ModTime(), ks.ModTime()
			c, err := tls.LoadX509KeyPair(f.certPath, f.keyPath)
			if err != nil {
				f.log.Warn("new console TLS certificate is invalid; keeping the previous one", "err", err)
			} else {
				f.cert = &c
				f.log.Info("console TLS certificate reloaded", "cert", f.certPath)
			}
		}
	}
	return f.cert, nil
}

// Config returns a TLS config for the console: TLS 1.2 minimum. When fc is nil the fixed
// certificate is used instead (the HomeXDR CA's server certificate).
func Config(fc *FileCert, fixed *tls.Certificate) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if fc != nil {
		c.GetCertificate = fc.GetCertificate
	} else {
		c.Certificates = []tls.Certificate{*fixed}
	}
	return c
}

// HSTS adds Strict-Transport-Security to responses served over TLS.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		}
		next.ServeHTTP(w, r)
	})
}

// Redirect answers every request with a 308 to the same host on the HTTPS port, except
// /healthz, which the container health check calls over plain HTTP and which goes to plain.
func Redirect(httpsAddr string, plain http.Handler) http.Handler {
	_, port, err := net.SplitHostPort(httpsAddr)
	if err != nil || port == "" {
		port = "8448"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			plain.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
		target := "https://" + net.JoinHostPort(host, port) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}
