// Package adguard reads AdGuard Home's query log over its HTTP API and turns each lookup
// into a DNS event, so HomeXDR sees which device looked up which name even when AdGuard
// Home, not the firewall's own resolver, answers the network.
package adguard

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrAuth means AdGuard Home refused the username or password.
var ErrAuth = errors.New("AdGuard Home refused the username or password")

const (
	maxBody        = 32 << 20
	requestTimeout = 30 * time.Second
)

// Client talks to one AdGuard Home instance.
type Client struct {
	base       *url.URL
	user, pass string
	hc         *http.Client
}

// NewClient returns a client for the settings' address, credentials and certificate rules.
func NewClient(set Settings) (*Client, error) {
	u, err := ParseURL(set.URL)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: set.ServerName}
	if pin := normalizePin(set.PinSHA256); pin != "" {
		// Trust exactly one certificate, whatever its name or dates say.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the server sent no certificate")
			}
			if got := fingerprint(raw[0]); got != pin {
				return fmt.Errorf("the certificate changed: its fingerprint is now %s, not the one you trusted", colons(got))
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:     tc,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		base: u, user: set.Username, pass: set.Password,
		hc: &http.Client{
			Transport: tr,
			Timeout:   requestTimeout,
			// AdGuard Home's API never redirects; refusing keeps the password on this host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// ParseURL checks an AdGuard Home address: http or https, a host, and nothing else that
// could carry a secret or change the API path.
func ParseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("enter AdGuard Home's address, such as https://192.168.20.1:3001")
	}
	if u.User != nil {
		return nil, errors.New("put the username and password in their own fields, not in the address")
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("enter only the scheme, host and port, such as https://192.168.20.1:3001")
	}
	u.Path = ""
	return u, nil
}

func (c *Client) get(ctx context.Context, path string, q url.Values, v any) error {
	u := *c.base
	u.Path = path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return explain(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrAuth
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("AdGuard Home answered %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v); err != nil {
		return fmt.Errorf("AdGuard Home's answer was not what HomeXDR expected: %w", err)
	}
	return nil
}

// explain turns a transport error into a sentence. The request URL holds no secrets: the
// password travels in a header.
func explain(err error) error {
	var cv *tls.CertificateVerificationError
	var hn x509.HostnameError
	var inv x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return &CertError{Msg: "AdGuard Home's certificate has expired"}
	case errors.As(err, &hn):
		return &CertError{Msg: "AdGuard Home's certificate is not for this address. Set the certificate name, or trust the certificate"}
	case errors.As(err, &ua):
		return &CertError{Msg: "AdGuard Home's certificate is not signed by an authority HomeXDR knows"}
	case errors.As(err, &cv):
		return &CertError{Msg: "AdGuard Home's certificate failed the check: " + cv.Err.Error()}
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("AdGuard Home did not answer in time")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("could not reach AdGuard Home: %v", ue.Err)
	}
	return err
}

// CertError is a failed certificate check, which the console can offer to fix by trusting
// the certificate.
type CertError struct{ Msg string }

func (e *CertError) Error() string { return e.Msg }

// Status is the part of /control/status HomeXDR uses.
type Status struct {
	Version string `json:"version"`
	Running bool   `json:"running"`
}

// Status checks the connection and credentials.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	if err := c.get(ctx, "/control/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Page is one page of the query log, newest first.
type Page struct {
	Data   []Entry `json:"data"`
	Oldest string  `json:"oldest"`
}

// QueryLog returns up to limit entries older than olderThan (empty: the newest).
func (c *Client) QueryLog(ctx context.Context, olderThan string, limit int) (*Page, error) {
	q := url.Values{"limit": {fmt.Sprint(limit)}, "response_status": {"all"}}
	if olderThan != "" {
		q.Set("older_than", olderThan)
	}
	var p Page
	if err := c.get(ctx, "/control/querylog", q, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// CertInfo describes the certificate a server presented.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Names       []string  `json:"names,omitempty"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	Expired     bool      `json:"expired"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 of the certificate, with colons
}

// FetchCertificate connects without checking the certificate and describes it, so the
// owner can decide to trust it. Nothing is sent but the TLS handshake.
func FetchCertificate(ctx context.Context, set Settings) (*CertInfo, error) {
	u, err := ParseURL(set.URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errors.New("the address is not https")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: set.ServerName, MinVersion: tls.VersionTLS12},
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("could not reach AdGuard Home: %w", err)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the server sent no certificate")
	}
	leaf := certs[0]
	return &CertInfo{
		Subject: leaf.Subject.CommonName, Names: leaf.DNSNames, Issuer: leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter.UTC(), Expired: time.Now().After(leaf.NotAfter),
		Fingerprint: colons(fingerprint(leaf.Raw)),
	}, nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// normalizePin accepts a fingerprint with or without colons, in any case.
func normalizePin(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", " ", "", "sha256/", "").Replace(s)
	return s
}

func validPin(s string) bool {
	p := normalizePin(s)
	if len(p) != 64 {
		return false
	}
	_, err := hex.DecodeString(p)
	return err == nil
}

func colons(hexs string) string {
	var b strings.Builder
	for i := 0; i < len(hexs); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(hexs[i:min(i+2, len(hexs))]))
	}
	return b.String()
}
