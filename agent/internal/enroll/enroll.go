// Package enroll implements agent enrollment (docs/protocol.md, "Enrollment").
//
// The server presents [leaf, CA] in its TLS handshake. Before anything is sent, the agent
// checks that SHA-256 of one presented CA certificate's DER equals the --ca-pin value and
// that the leaf chains to that CA with the ServerAuth usage. The hostname is not checked.
// Without a pin the agent refuses, unless trust-on-first-use is explicitly requested.
package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/identity"
	"github.com/Doodlebug12/homexdr/agent/internal/transport"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/version"
)

// Options for Enroll.
type Options struct {
	ServerURL string
	Token     string
	// CAPin is "sha256:<hex>" of the server CA's DER. Required unless InsecureTOFU.
	CAPin        string
	InsecureTOFU bool
	Labels       []string
	Host         api.HostInfo
}

// Result is a successful enrollment.
type Result struct {
	Identity *identity.Identity
	Config   api.AgentConfig
	// Pin is the CA pin that was verified (or, with InsecureTOFU, accepted).
	Pin string
}

// ErrNoPin is returned when no pin is given and TOFU was not requested.
var ErrNoPin = errors.New("refusing to enroll without --ca-pin (copy it from the console's settings page, or pass --insecure-tofu to trust the server's CA on first use)")

// pinVerifier checks the handshake and remembers the accepted CA.
type pinVerifier struct {
	pin  string
	tofu bool
	mu   sync.Mutex
	ca   *x509.Certificate
}

func (v *pinVerifier) verify(cs tls.ConnectionState) error {
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		return errors.New("server presented no certificate")
	}
	raw := make([][]byte, len(certs))
	for i, c := range certs {
		raw[i] = c.Raw
	}
	var ca *x509.Certificate
	if v.pin != "" {
		var seen []string
		for _, c := range certs[1:] {
			p := identity.Pin(c)
			seen = append(seen, p)
			if strings.EqualFold(p, v.pin) {
				ca = c
				break
			}
		}
		if ca == nil {
			if len(seen) == 0 {
				return fmt.Errorf("CA pin mismatch: the server did not present its CA certificate")
			}
			return fmt.Errorf("CA pin mismatch: expected %s, server presented %s", v.pin, strings.Join(seen, ", "))
		}
	} else {
		if !v.tofu {
			return ErrNoPin
		}
		// Trust on first use: accept the last certificate of the chain if it is a CA.
		ca = certs[len(certs)-1]
		if len(certs) < 2 || !ca.IsCA {
			return errors.New("server did not present a CA certificate to trust")
		}
	}
	if !ca.IsCA {
		return errors.New("the pinned certificate is not a CA")
	}
	if err := identity.VerifyServerChain(raw, ca); err != nil {
		return err
	}
	v.mu.Lock()
	v.ca = ca
	v.mu.Unlock()
	return nil
}

func (v *pinVerifier) accepted() *x509.Certificate {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.ca
}

// Enroll generates a key, verifies the server against the pin, sends the CSR and returns
// the new identity. Nothing is written to disk.
func Enroll(ctx context.Context, o Options) (*Result, error) {
	u, err := transport.ParseServerURL(o.ServerURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, errors.New("an enrollment token is required (--token)")
	}
	pin := strings.ToLower(strings.TrimSpace(o.CAPin))
	if pin == "" && !o.InsecureTOFU {
		return nil, ErrNoPin
	}
	key, err := identity.NewKey()
	if err != nil {
		return nil, err
	}
	csr, err := identity.CSR(key, o.Host.Hostname)
	if err != nil {
		return nil, err
	}
	v := &pinVerifier{pin: pin, tofu: o.InsecureTOFU}
	tr := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Replaced by the pin check in VerifyConnection (no hostname matching).
			InsecureSkipVerify: true,
			VerifyConnection:   v.verify,
		},
		TLSHandshakeTimeout: 15 * time.Second,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: time.Minute}

	body, err := json.Marshal(api.EnrollRequest{
		Token:        strings.TrimSpace(o.Token),
		CSRPEM:       string(csr),
		AgentVersion: version.Version,
		Host:         o.Host,
		Labels:       o.Labels,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+api.PathEnroll, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.HeaderProtocol, api.ProtocolVersion)
	req.Header.Set("User-Agent", transport.UserAgent())
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("enroll: the enrollment token is invalid or expired (%s)", e.Error)
		case http.StatusConflict:
			return nil, fmt.Errorf("enroll: the enrollment token has no uses left (%s)", e.Error)
		}
		return nil, fmt.Errorf("enroll: server returned %d: %s", resp.StatusCode, e.Error)
	}
	var er api.EnrollResponse
	if err := json.Unmarshal(rb, &er); err != nil {
		return nil, fmt.Errorf("enroll: decode response: %w", err)
	}
	ca := v.accepted()
	if ca == nil {
		return nil, errors.New("enroll: TLS verification did not run")
	}
	return buildIdentity(key, er, ca)
}

// buildIdentity validates the enrollment response against the CA verified in the
// handshake. The stored CA is always the pinned one, never just what the body says.
func buildIdentity(ek *ecdsa.PrivateKey, er api.EnrollResponse, ca *x509.Certificate) (*Result, error) {
	if er.AgentID == "" {
		return nil, errors.New("enroll: response has no agent_id")
	}
	respCA, err := identity.ParseCertPEM([]byte(er.CAPEM))
	if err != nil {
		return nil, fmt.Errorf("enroll: ca_pem: %w", err)
	}
	if identity.Pin(respCA) != identity.Pin(ca) {
		return nil, errors.New("enroll: the CA in the response differs from the pinned CA")
	}
	cert, err := identity.ParseCertPEM([]byte(er.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("enroll: cert_pem: %w", err)
	}
	ck, err := identity.ParseCommandKey(er.CommandKey)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	id := &identity.Identity{
		AgentID:    er.AgentID,
		Key:        ek,
		CertPEM:    []byte(er.CertPEM),
		Cert:       cert,
		CAPEM:      []byte(er.CAPEM),
		CA:         ca,
		CommandKey: ck,
	}
	if err := id.Check(); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return &Result{Identity: id, Config: er.Config, Pin: identity.Pin(ca)}, nil
}
