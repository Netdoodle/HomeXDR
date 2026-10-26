// Package agentapi serves the endpoint-agent protocol (docs/protocol.md) on the TLS
// agent listener.
package agentapi

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type ctxKey struct{}

// Handler serves the agent API.
type Handler struct {
	c   *core.Core
	mux *http.ServeMux
}

// New returns the agent API handler.
func New(c *core.Core) *Handler {
	h := &Handler{c: c, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST "+api.PathEnroll, h.enroll)
	h.mux.HandleFunc("POST "+api.PathRenew, h.renew)
	h.mux.HandleFunc("GET "+api.PathAgentRelease, h.releaseManifest)
	h.mux.HandleFunc("GET "+api.PathAgentReleaseSig, h.releaseSignature)
	h.mux.HandleFunc("GET /v1/download/{name}", h.download)
	h.mux.HandleFunc("GET "+api.PathReleases+"{version}/{name}", h.archivedRelease)
	h.mux.HandleFunc("GET /v1/install/linux.sh", h.installScript)
	h.mux.HandleFunc("GET /v1/ca.crt", h.caCert)
	h.mux.Handle("POST "+api.PathHeartbeat, h.agent(h.heartbeat))
	h.mux.Handle("POST "+api.PathEvents, h.agent(h.events))
	h.mux.Handle("GET "+api.PathCommands, h.agent(h.commands))
	h.mux.Handle("POST /v1/commands/{id}/result", h.agent(h.result))
	h.mux.Handle("POST /v1/commands/{id}/rows", h.agent(h.rows))
	h.mux.Handle("POST /v1/commands/{id}/upload", h.agent(h.upload))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(r *http.Request, limit int64, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(v)
}

// agent authenticates a request by its client certificate.
func (h *Handler) agent(next func(http.ResponseWriter, *http.Request, *store.Host)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, status, msg := h.authAgent(r, false)
		if host == nil {
			writeErr(w, status, msg)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, host.ID)), host)
	})
}

// authAgent identifies the agent behind a request by its client certificate, or returns
// the HTTP status and message to refuse it with. allowExpired is for renewal only.
//
// A host accepts its current certificate and, after a renewal, the pending new one; the
// first request with the new certificate makes it current and retires the old one. A
// decommissioned agent that authenticates is restored.
func (h *Handler) authAgent(r *http.Request, allowExpired bool) (*store.Host, int, string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, http.StatusUnauthorized, "client certificate required"
	}
	leaf, err := h.c.PKI.VerifyAgentCert(r.TLS.PeerCertificates, allowExpired)
	if err != nil {
		if !allowExpired && time.Now().After(r.TLS.PeerCertificates[0].NotAfter) {
			if _, err := h.c.PKI.VerifyAgentCert(r.TLS.PeerCertificates, true); err == nil {
				return nil, http.StatusUnauthorized, "certificate expired: renew it at " + api.PathRenew
			}
		}
		return nil, http.StatusUnauthorized, "invalid client certificate"
	}
	ctx := r.Context()
	host, err := h.c.State.GetHost(ctx, leaf.Subject.CommonName)
	if err != nil {
		return nil, http.StatusUnauthorized, "unknown agent"
	}
	if host.Revoked {
		return nil, http.StatusForbidden, "agent revoked"
	}
	serial := leaf.SerialNumber.Text(16)
	switch {
	case host.CertSerial == "" || serial == host.CertSerial:
		if host.CertExpires == nil || !host.CertExpires.Equal(leaf.NotAfter) {
			if err := h.c.State.UseCert(ctx, host.ID, serial, leaf.NotAfter); err != nil {
				h.c.Log.Warn("record agent certificate", "host", host.ID, "err", err)
			}
		}
	case serial == host.PendingCertSerial:
		if err := h.c.State.UseCert(ctx, host.ID, serial, leaf.NotAfter); err != nil {
			h.c.Log.Error("switch to renewed agent certificate", "host", host.ID, "err", err)
			return nil, http.StatusInternalServerError, "internal error"
		}
		h.c.Log.Info("agent switched to its renewed certificate", "host", host.ID, "expires", leaf.NotAfter)
	default:
		return nil, http.StatusForbidden, "certificate superseded"
	}
	if host.DecommissionedAt != nil {
		if was, err := h.c.State.RecommissionHost(ctx, host.ID); err == nil && was {
			days := int(time.Since(*host.DecommissionedAt).Hours() / 24)
			h.c.Audit(ctx, "agent", "agent.recommission", host.ID,
				fmt.Sprintf("%s reconnected %d days after it was decommissioned", host.Hostname, days))
			h.c.Log.Info("decommissioned agent reconnected; restored", "host", host.ID, "hostname", host.Hostname)
		}
	}
	return host, 0, ""
}

// renew issues a new client certificate to an agent, even one whose certificate expired.
func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	host, status, msg := h.authAgent(r, true)
	if host == nil {
		writeErr(w, status, msg)
		return
	}
	var req api.RenewRequest
	if err := decode(r, 64<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	certPEM, serial, err := h.c.PKI.SignAgentCSR([]byte(req.CSRPEM), host.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.c.State.SetPendingCert(r.Context(), host.ID, serial); err != nil {
		h.c.Log.Error("renew: store certificate", "host", host.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	old := "unknown"
	if host.CertExpires != nil {
		old = host.CertExpires.UTC().Format(time.DateOnly)
	}
	h.c.Audit(r.Context(), "agent", "agent.cert.renew", host.ID, fmt.Sprintf("%s: certificate expiring %s renewed", host.Hostname, old))
	h.c.Log.Info("agent certificate renewed", "host", host.ID, "hostname", host.Hostname, "previous_expiry", old)
	writeJSON(w, http.StatusOK, api.RenewResponse{CertPEM: string(certPEM)})
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := decode(r, 64<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.Host.Hostname) == "" {
		writeErr(w, http.StatusBadRequest, "host.hostname is required")
		return
	}
	switch req.Host.OS.Platform {
	case event.PlatformWindows, event.PlatformLinux, event.PlatformDarwin:
	default:
		writeErr(w, http.StatusBadRequest, "host.os.platform must be windows, linux or darwin")
		return
	}
	tok, err := h.c.State.UseToken(r.Context(), strings.TrimSpace(req.Token))
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, store.ErrTokenUsedUp):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		h.c.Log.Error("enroll: token", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	agentID := event.NewID()
	certPEM, serial, err := h.c.PKI.SignAgentCSR([]byte(req.CSRPEM), agentID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	labels := append(append([]string{}, tok.Labels...), req.Labels...)
	host, err := h.c.State.CreateEndpoint(r.Context(), agentID, req.Host, labels, serial)
	if err != nil {
		h.c.Log.Error("enroll: create host", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.c.Audit(r.Context(), "token:"+tok.Name, "agent.enroll", agentID, fmt.Sprintf("%s (%s) from %s", req.Host.Hostname, req.Host.OS.Platform, clientIP(r)))
	h.c.Log.Info("agent enrolled", "id", agentID, "hostname", host.Hostname, "platform", host.OS.Platform)
	writeJSON(w, http.StatusOK, api.EnrollResponse{
		AgentID:    agentID,
		CertPEM:    string(certPEM),
		CAPEM:      string(h.c.PKI.CAPEM),
		CommandKey: base64.StdEncoding.EncodeToString(h.c.PKI.CommandPublicKey()),
		Config:     h.c.AgentConfig(r.Context()),
	})
	go h.c.CatchUpHunts(context.WithoutCancel(r.Context()), host)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request, host *store.Host) {
	var hb api.Heartbeat
	if err := decode(r, 256<<10, &hb); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid heartbeat")
		return
	}
	if hb.Host.Hostname == "" {
		hb.Host.Hostname = host.Hostname
	}
	if hb.Host.OS.Platform == "" {
		hb.Host.OS = host.OS
	}
	wasOffline := host.Status == "offline" || host.Status == "decommissioned"
	updated, err := h.c.State.Heartbeat(r.Context(), host.ID, hb.Host, hb.Status)
	if err != nil {
		h.c.Log.Error("heartbeat", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if hb.Status.Isolated != host.Isolated {
		_ = h.c.State.SetIsolated(r.Context(), host.ID, hb.Status.Isolated)
	}
	resp := api.HeartbeatResponse{ServerTime: time.Now().UTC()}
	if cfg := h.c.AgentConfig(r.Context()); cfg.Version > hb.Status.ConfigVersion {
		resp.Config = &cfg
	}
	resp.CommandsPending, _ = h.c.State.HasPendingCommands(r.Context(), host.ID)
	resp.Update = h.c.UpdateOffer(r.Context(), updated)
	writeJSON(w, http.StatusOK, resp)
	if wasOffline {
		go h.c.CatchUpHunts(context.WithoutCancel(r.Context()), updated)
	}
}

// maxLine caps one NDJSON line.
const maxLine = 4 << 20

// readNDJSON decodes a gzip (or plain) NDJSON body, bounded by limit uncompressed bytes.
func readNDJSON(r *http.Request, limit int64, each func([]byte) error) (tooLarge bool, err error) {
	body := http.MaxBytesReader(nil, r.Body, limit)
	var src io.Reader = body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return false, err
		}
		defer zr.Close()
		src = zr
	}
	lr := &io.LimitedReader{R: src, N: limit + 1}
	br := bufio.NewReaderSize(lr, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Long line: accumulate.
			buf := append([]byte(nil), line...)
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = br.ReadSlice('\n')
				buf = append(buf, line...)
				if len(buf) > maxLine {
					return false, errors.New("line too long")
				}
			}
			line = buf
		}
		if len(bytes.TrimSpace(line)) > 0 {
			if cerr := each(bytes.TrimSpace(line)); cerr != nil {
				return false, cerr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return true, nil
			}
			return false, err
		}
	}
	return lr.N <= 0, nil
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request, host *store.Host) {
	var evs []*event.Event
	rejected := 0
	tooLarge, err := readNDJSON(r, api.MaxEventBatchBytes, func(line []byte) error {
		var e event.Event
		if json.Unmarshal(line, &e) != nil {
			rejected++
			return nil
		}
		evs = append(evs, &e)
		return nil
	})
	if tooLarge {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch too large")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := h.c.Ingest(r.Context(), host, evs); err != nil {
		h.c.Log.Error("ingest", "err", err, "host", host.ID, "events", len(evs))
		writeErr(w, http.StatusServiceUnavailable, "event store unavailable")
		return
	}
	_ = h.c.State.TouchHost(r.Context(), host.ID)
	writeJSON(w, http.StatusAccepted, api.EventsResponse{Accepted: len(evs), Rejected: rejected})
}

func (h *Handler) commands(w http.ResponseWriter, r *http.Request, host *store.Host) {
	wait := api.DefaultLongPoll
	if s := r.URL.Query().Get("wait"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			wait = time.Duration(min(n, 55)) * time.Second
		}
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		// Register before checking so a command queued in between still wakes us.
		wake := h.c.Broker.Wait(host.ID)
		cmds, err := h.c.State.TakePendingCommands(r.Context(), host.ID, 20)
		if err != nil {
			h.c.Log.Error("take commands", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if len(cmds) > 0 {
			out := make([]api.SignedCommand, 0, len(cmds))
			for _, c := range cmds {
				payload, err := json.Marshal(c.Command())
				if err != nil {
					continue
				}
				out = append(out, api.SignedCommand{Payload: payload, Signature: h.c.PKI.SignCommand(payload)})
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		select {
		case <-wake:
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (h *Handler) ownCommand(w http.ResponseWriter, r *http.Request, host *store.Host) *store.CommandRecord {
	c, err := h.c.State.GetCommand(r.Context(), r.PathValue("id"))
	if err != nil || c.HostID != host.ID {
		writeErr(w, http.StatusNotFound, "unknown command")
		return nil
	}
	return c
}

func (h *Handler) result(w http.ResponseWriter, r *http.Request, host *store.Host) {
	var res api.CommandResult
	if err := decode(r, 2<<20, &res); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid result")
		return
	}
	res.CommandID = r.PathValue("id")
	rec, err := h.c.State.RecordResult(r.Context(), host.ID, res)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "unknown command")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "command already finished")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if rec.Status == api.StatusCompleted {
		switch rec.Type {
		case api.CmdHostIsolate:
			_ = h.c.State.SetIsolated(r.Context(), host.ID, true)
		case api.CmdHostRelease:
			_ = h.c.State.SetIsolated(r.Context(), host.ID, false)
		}
	}
	if store.FinalStatus(rec.Status) {
		h.recordResponseEvent(r.Context(), host, rec)
	}
	w.WriteHeader(http.StatusNoContent)
}

// recordResponseEvent puts finished actions into the host timeline.
func (h *Handler) recordResponseEvent(ctx context.Context, host *store.Host, rec *store.CommandRecord) {
	outcome := event.OutcomeSuccess
	if rec.Status != api.StatusCompleted {
		outcome = event.OutcomeFailure
	}
	msg := fmt.Sprintf("%s %s by %s", rec.Type, rec.Status, rec.IssuedBy)
	if rec.Error != "" {
		msg += ": " + rec.Error
	}
	ev := &event.Event{
		ID: event.NewID(), Timestamp: time.Now().UTC(),
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryHost}, Type: []string{event.TypeInfo},
			Action: rec.Type, Outcome: outcome, Module: event.ModuleResponse,
		},
		Message: msg,
		Data:    map[string]any{"command_id": rec.ID, "params": json.RawMessage(rec.Params)},
	}
	var kp api.KillParams
	if rec.Type == api.CmdProcessKill && json.Unmarshal(rec.Params, &kp) == nil {
		ev.Process = &event.Process{PID: kp.PID, EntityID: kp.EntityID}
	}
	if err := h.c.Ingest(ctx, host, []*event.Event{ev}); err != nil {
		h.c.Log.Warn("response event", "err", err)
	}
}

func (h *Handler) rows(w http.ResponseWriter, r *http.Request, host *store.Host) {
	c := h.ownCommand(w, r, host)
	if c == nil {
		return
	}
	if c.Type != api.CmdArtifact || store.FinalStatus(c.Status) {
		writeErr(w, http.StatusConflict, "command does not accept rows")
		return
	}
	var rows []json.RawMessage
	tooLarge, err := readNDJSON(r, api.MaxRowsBatchBytes, func(line []byte) error {
		rows = append(rows, append(json.RawMessage(nil), line...))
		return nil
	})
	if tooLarge {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch too large")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	n, err := h.c.State.AddRows(r.Context(), c, rows)
	if err != nil {
		h.c.Log.Error("store rows", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"stored": n})
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request, host *store.Host) {
	c := h.ownCommand(w, r, host)
	if c == nil {
		return
	}
	if c.Type != api.CmdFileGet || store.FinalStatus(c.Status) {
		writeErr(w, http.StatusConflict, "command does not accept uploads")
		return
	}
	var p api.FileGetParams
	_ = json.Unmarshal(c.Params, &p)
	limit := p.MaxBytes
	if limit <= 0 || limit > core.MaxUploadBytes {
		limit = core.MaxUploadBytes
	}
	dir := filepath.Join(h.c.Cfg.DataDir, "uploads")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	dst := filepath.Join(dir, c.ID)
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(r.Body, limit+1))
	cerr := f.Close()
	if err != nil || cerr != nil {
		os.Remove(dst)
		writeErr(w, http.StatusBadRequest, "upload failed")
		return
	}
	if n > limit {
		os.Remove(dst)
		writeErr(w, http.StatusRequestEntityTooLarge, "file exceeds max_bytes")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = p.Path
	}
	if err := h.c.State.SetUpload(r.Context(), c.ID, dst, name); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"size": n, "sha256": hex.EncodeToString(hash.Sum(nil))})
}

var downloadName = regexp.MustCompile(`^(homexdr-agent-(linux|windows|darwin)-(amd64|arm64)(\.exe)?|SHA256SUMS)$`)

// releaseManifest and releaseSignature serve the same snapshot the heartbeat offers.
func (h *Handler) releaseManifest(w http.ResponseWriter, r *http.Request) {
	m := h.c.Release.Manifest()
	if m == nil {
		writeErr(w, http.StatusNotFound, "no agent release manifest bundled with this server")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(m)
}

func (h *Handler) releaseSignature(w http.ResponseWriter, r *http.Request) {
	sig := h.c.Release.Signature()
	if sig == nil {
		writeErr(w, http.StatusNotFound, "this agent release is not signed: "+h.c.Release.Status().Problem)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(sig)
}

// archivedRelease serves a file of an archived release (manifest, signature or binary).
func (h *Handler) archivedRelease(w http.ResponseWriter, r *http.Request) {
	p, ok := h.c.Release.ArchiveFile(r.PathValue("version"), r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such archived release file")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such archived release file")
		return
	}
	defer f.Close()
	switch name := r.PathValue("name"); {
	case name == api.AgentReleaseName:
		w.Header().Set("Content-Type", "application/json")
	case strings.HasSuffix(name, ".sig"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !downloadName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(h.c.Cfg.DownloadsDir, name)
	if _, err := os.Stat(p); err != nil {
		writeErr(w, http.StatusNotFound, "agent binary not bundled with this server")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, p)
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
