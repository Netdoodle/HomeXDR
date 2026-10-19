// Package transport is the agent's mTLS HTTP client for the agent API
// (docs/protocol.md). It trusts only the CA pinned at enrollment.
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/identity"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/version"
)

// UserAgent is sent with every request.
func UserAgent() string { return "homexdr-agent/" + version.Version }

// StatusError is a non-success HTTP response.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("server returned %d: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("server returned %d", e.Code)
}

// Retryable reports whether a request that failed with err should be retried later:
// network errors, 5xx, 408 and 429. Other 4xx responses are final.
func Retryable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code >= 500 || se.Code == http.StatusRequestTimeout || se.Code == http.StatusTooManyRequests
	}
	return err != nil
}

// IsStatus reports whether err is a StatusError with the given code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Client talks to the agent API with the agent's client certificate.
type Client struct {
	base    *url.URL
	hc      *http.Client
	agentID string
}

// ParseServerURL validates an agent API URL (https only).
func ParseServerURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(s), "/"))
	if err != nil {
		return nil, fmt.Errorf("server url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("server url must look like https://host:8443, got %q", s)
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u, nil
}

// ServerHostPort returns the host and port of an agent API URL (port defaults to 443).
func ServerHostPort(u *url.URL) (string, int) {
	port := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return u.Hostname(), port
}

// TLSConfig returns the client TLS config: the client certificate, and server
// verification against the pinned CA only (see identity.VerifyServerChain).
func TLSConfig(id *identity.Identity) *tls.Config {
	ca := id.CA
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{id.TLSCertificate()},
		// The standard verifier would also require a hostname match. We skip it and run
		// our own chain check in VerifyConnection instead, which still requires the
		// pinned CA and the ServerAuth usage.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			return identity.VerifyServerChain(raw, ca)
		},
	}
}

// New returns a client for serverURL using the enrolled identity.
func New(serverURL string, id *identity.Identity) (*Client, error) {
	u, err := ParseServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       TLSConfig(id),
		TLSHandshakeTimeout:   15 * time.Second,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // long-poll requests set their own deadline
		ExpectContinueTimeout: time.Second,
	}
	return &Client{base: u, hc: &http.Client{Transport: tr}, agentID: id.AgentID}, nil
}

// Close releases idle connections.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

// URL returns the server base URL.
func (c *Client) URL() *url.URL { return c.base }

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, hdr http.Header) (*http.Response, error) {
	u := *c.base
	u.Path = path
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set(api.HeaderProtocol, api.ProtocolVersion)
	req.Header.Set(api.HeaderAgentID, c.agentID)
	req.Header.Set("User-Agent", UserAgent())
	return c.hc.Do(req)
}

// errorFrom builds a StatusError from a response, reading a bounded error body.
func errorFrom(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(b))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	return &StatusError{Code: resp.StatusCode, Msg: msg}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any, okCodes ...int) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, path, nil, bytes.NewReader(b), http.Header{"Content-Type": {"application/json"}})
	if err != nil {
		return err
	}
	defer drain(resp)
	ok := false
	for _, code := range okCodes {
		ok = ok || resp.StatusCode == code
	}
	if !ok {
		return errorFrom(resp)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

// Heartbeat posts agent status and returns the server's reply.
func (c *Client) Heartbeat(ctx context.Context, hb api.Heartbeat) (api.HeartbeatResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out api.HeartbeatResponse
	err := c.postJSON(ctx, api.PathHeartbeat, hb, &out, http.StatusOK)
	return out, err
}

// PostEvents sends one gzip NDJSON batch. It returns a *StatusError for any status
// other than 202, so the caller can split on 413, drop on other 4xx and retry otherwise.
func (c *Client) PostEvents(ctx context.Context, gz []byte) (api.EventsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, api.PathEvents, nil, bytes.NewReader(gz), http.Header{
		"Content-Type":     {"application/x-ndjson"},
		"Content-Encoding": {"gzip"},
	})
	if err != nil {
		return api.EventsResponse{}, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusAccepted {
		return api.EventsResponse{}, errorFrom(resp)
	}
	var out api.EventsResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	return out, nil
}

// PollCommands long-polls for commands. It returns nil, nil on 204.
func (c *Client) PollCommands(ctx context.Context, wait time.Duration) ([]api.SignedCommand, error) {
	ctx, cancel := context.WithTimeout(ctx, wait+30*time.Second)
	defer cancel()
	q := url.Values{"wait": {strconv.Itoa(int(wait / time.Second))}}
	resp, err := c.do(ctx, http.MethodGet, api.PathCommands, q, nil, nil)
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var out []api.SignedCommand
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out); err != nil {
			return nil, fmt.Errorf("decode commands: %w", err)
		}
		return out, nil
	}
	return nil, errorFrom(resp)
}

// PostResult reports a command status.
func (c *Client) PostResult(ctx context.Context, res api.CommandResult) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.postJSON(ctx, fmt.Sprintf(api.PathCommandResultFmt, url.PathEscape(res.CommandID)), res, nil,
		http.StatusNoContent, http.StatusOK, http.StatusAccepted)
}

// PostRows sends one gzip NDJSON batch of artifact rows.
func (c *Client) PostRows(ctx context.Context, commandID string, gz []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, fmt.Sprintf(api.PathCommandRowsFmt, url.PathEscape(commandID)), nil,
		bytes.NewReader(gz), http.Header{"Content-Type": {"application/x-ndjson"}, "Content-Encoding": {"gzip"}})
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return errorFrom(resp)
	}
	return nil
}

// Upload streams a file body for a file.get command.
func (c *Client) Upload(ctx context.Context, commandID, name string, body io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	q := url.Values{"name": {name}}
	u := *c.base
	u.Path = fmt.Sprintf(api.PathCommandUploadFmt, url.PathEscape(commandID))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(api.HeaderProtocol, api.ProtocolVersion)
	req.Header.Set(api.HeaderAgentID, c.agentID)
	req.Header.Set("User-Agent", UserAgent())
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return errorFrom(resp)
	}
	return nil
}

// GzipLines gzips NDJSON lines (each without its trailing newline).
func GzipLines(lines [][]byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	for _, l := range lines {
		zw.Write(l)
		zw.Write([]byte{'\n'})
	}
	zw.Close()
	return buf.Bytes()
}
