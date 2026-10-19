package commands

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/backoff"
	"github.com/Doodlebug12/homexdr/agent/internal/fileops"
	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/agent/internal/transport"
	"github.com/Doodlebug12/homexdr/shared/api"
)

// API is the subset of the transport client used to report results.
type API interface {
	PostResult(ctx context.Context, res api.CommandResult) error
	PostRows(ctx context.Context, commandID string, gz []byte) error
	Upload(ctx context.Context, commandID, name string, body io.Reader, size int64) error
}

// Isolator applies and removes host isolation (the core builds the Isolation from the
// server address and the allow lists, and persists the state).
type Isolator interface {
	Isolate(ctx context.Context, p api.IsolateParams) (any, error)
	Release(ctx context.Context) error
}

// Handler verifies and executes commands.
type Handler struct {
	API        API
	Verifier   *Verifier
	Responder  platform.Responder
	Isolator   Isolator
	Collectors map[string]platform.Collector
	Files      *fileops.Store
	Log        *slog.Logger
	// Platform is the event.Platform* name, used to check the artifact catalog.
	Platform string

	slow chan struct{} // limits concurrent artifact collections and uploads
}

// Row batching limits for artifact results.
const (
	rowsPerBatch   = 1000
	rowBatchBytes  = 4 << 20
	maxRowBytes    = 1 << 20
	slowConcurrent = 2
)

// Handle verifies one command and, if it passes, executes it in the background.
func (h *Handler) Handle(ctx context.Context, sc api.SignedCommand) {
	if h.slow == nil {
		h.slow = make(chan struct{}, slowConcurrent)
	}
	cmd, err := h.Verifier.Verify(sc)
	if err != nil {
		var rj *Rejection
		errors.As(err, &rj)
		h.Log.Warn("command rejected", "id", rj.ID, "reason", rj.Reason)
		if rj.ID != "" {
			h.post(ctx, api.CommandResult{CommandID: rj.ID, Status: api.StatusRejected, Error: rj.Reason})
		}
		return
	}
	h.Log.Info("command received", "id", cmd.ID, "type", cmd.Type, "issued_by", cmd.IssuedBy, "params", string(cmd.Params))
	go h.execute(ctx, cmd)
}

func decodeParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	return nil
}

func timeout(typ string) time.Duration {
	switch typ {
	case api.CmdArtifact:
		return 30 * time.Minute
	case api.CmdFileGet:
		return time.Hour
	}
	return 5 * time.Minute
}

func (h *Handler) execute(parent context.Context, cmd *api.Command) {
	// Prepare (validate params) before reporting "running", so bad params are rejected.
	run, err := h.prepare(cmd)
	if err != nil {
		h.Log.Warn("command rejected", "id", cmd.ID, "type", cmd.Type, "reason", err)
		h.post(parent, api.CommandResult{CommandID: cmd.ID, Status: api.StatusRejected, Error: err.Error()})
		return
	}
	if cmd.Type == api.CmdArtifact || cmd.Type == api.CmdFileGet {
		select {
		case h.slow <- struct{}{}:
			defer func() { <-h.slow }()
		case <-parent.Done():
			return
		}
	}
	ctx, cancel := context.WithTimeout(parent, timeout(cmd.Type))
	defer cancel()
	started := time.Now().UTC()
	h.post(ctx, api.CommandResult{CommandID: cmd.ID, Status: api.StatusRunning, StartedAt: &started})

	out, rows, err := run(ctx)
	finished := time.Now().UTC()
	res := api.CommandResult{CommandID: cmd.ID, StartedAt: &started, FinishedAt: &finished, RowCount: rows}
	if out != nil {
		if b, merr := json.Marshal(out); merr == nil {
			res.Output = b
		}
	}
	if err != nil {
		res.Status, res.Error = api.StatusFailed, err.Error()
		h.Log.Error("command failed", "id", cmd.ID, "type", cmd.Type, "err", err, "duration", finished.Sub(started).Round(time.Millisecond))
	} else {
		res.Status = api.StatusCompleted
		h.Log.Info("command completed", "id", cmd.ID, "type", cmd.Type, "rows", rows, "duration", finished.Sub(started).Round(time.Millisecond))
	}
	// Report with a fresh context: the action already happened even if ctx timed out.
	h.post(context.WithoutCancel(parent), res)
}

type runFunc func(ctx context.Context) (output any, rows int, err error)

// prepare validates the parameters and returns the action to run.
func (h *Handler) prepare(cmd *api.Command) (runFunc, error) {
	switch cmd.Type {
	case api.CmdProcessKill:
		var p api.KillParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		if p.PID <= 0 {
			return nil, errors.New("pid must be positive")
		}
		return func(ctx context.Context) (any, int, error) {
			r, err := h.Responder.KillProcess(ctx, p)
			if err != nil {
				return nil, 0, err
			}
			return r, 0, nil
		}, nil

	case api.CmdHostIsolate:
		var p api.IsolateParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		return func(ctx context.Context) (any, int, error) {
			out, err := h.Isolator.Isolate(ctx, p)
			return out, 0, err
		}, nil

	case api.CmdHostRelease:
		var p struct{}
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		return func(ctx context.Context) (any, int, error) {
			return nil, 0, h.Isolator.Release(ctx)
		}, nil

	case api.CmdFileQuarantine:
		var p api.QuarantineParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		return func(context.Context) (any, int, error) {
			r, err := h.Files.Quarantine(p.Path)
			if err != nil {
				return nil, 0, err
			}
			return r, 0, nil
		}, nil

	case api.CmdFileRestore:
		var p api.RestoreParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		return func(context.Context) (any, int, error) {
			r, err := h.Files.Restore(p.ID)
			if err != nil {
				return nil, 0, err
			}
			return r, 0, nil
		}, nil

	case api.CmdFileHash:
		var p api.FileHashParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		return func(context.Context) (any, int, error) {
			r, err := fileops.Hash(p.Path)
			if err != nil {
				return nil, 0, err
			}
			return r, 0, nil
		}, nil

	case api.CmdFileGet:
		var p api.FileGetParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		return func(ctx context.Context) (any, int, error) {
			r, err := h.fileGet(ctx, cmd.ID, p)
			if err != nil {
				return nil, 0, err
			}
			return r, 0, nil
		}, nil

	case api.CmdArtifact:
		var p api.ArtifactParams
		if err := decodeParams(cmd.Params, &p); err != nil {
			return nil, err
		}
		def, ok := api.FindArtifact(p.Name)
		if !ok {
			return nil, fmt.Errorf("unknown artifact %q", p.Name)
		}
		coll, ok := h.Collectors[p.Name]
		if !ok {
			return nil, fmt.Errorf("artifact %q is not implemented on %s", p.Name, h.Platform)
		}
		params, err := ArtifactArgs(def, p.Params)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context) (any, int, error) {
			n, err := h.collect(ctx, cmd.ID, coll, params)
			return nil, n, err
		}, nil
	}
	return nil, fmt.Errorf("unknown command type %q", cmd.Type)
}

// ArtifactArgs validates artifact parameters against the catalog and fills defaults.
func ArtifactArgs(def api.ArtifactDef, in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	known := map[string]api.ArtifactArg{}
	for _, a := range def.Params {
		known[a.Name] = a
		if a.Default != "" {
			out[a.Name] = a.Default
		}
	}
	for k, v := range in {
		a, ok := known[k]
		if !ok {
			return nil, fmt.Errorf("artifact %s has no parameter %q", def.Name, k)
		}
		switch a.Type {
		case "int":
			if _, err := strconv.Atoi(strings.TrimSpace(v)); err != nil {
				return nil, fmt.Errorf("parameter %s must be an integer", k)
			}
		case "bool":
			if _, err := strconv.ParseBool(strings.TrimSpace(v)); err != nil {
				return nil, fmt.Errorf("parameter %s must be true or false", k)
			}
		}
		out[k] = v
	}
	for _, a := range def.Params {
		if a.Required && strings.TrimSpace(out[a.Name]) == "" {
			return nil, fmt.Errorf("parameter %s is required", a.Name)
		}
	}
	return out, nil
}

// collect runs a collector and streams its rows in gzip NDJSON batches.
func (h *Handler) collect(ctx context.Context, id string, coll platform.Collector, params map[string]string) (int, error) {
	var (
		lines [][]byte
		size  int
		total int
	)
	flush := func() error {
		if len(lines) == 0 {
			return nil
		}
		gz := transport.GzipLines(lines)
		if err := h.retry(ctx, func(ctx context.Context) error { return h.API.PostRows(ctx, id, gz) }); err != nil {
			return fmt.Errorf("upload rows: %w", err)
		}
		total += len(lines)
		lines, size = lines[:0], 0
		return nil
	}
	err := coll(ctx, params, func(r platform.Row) error {
		b, err := json.Marshal(r)
		if err != nil {
			return nil // skip unencodable rows
		}
		if len(b) > maxRowBytes {
			return nil
		}
		lines = append(lines, b)
		size += len(b) + 1
		if len(lines) >= rowsPerBatch || size >= rowBatchBytes {
			return flush()
		}
		return nil
	})
	if ferr := flush(); err == nil {
		err = ferr
	}
	return total, err
}

// fileGet streams the file to the upload endpoint, hashing it on the way.
func (h *Handler) fileGet(ctx context.Context, id string, p api.FileGetParams) (api.FileHashResult, error) {
	f, size, err := fileops.Get(p.Path, p.MaxBytes)
	if err != nil {
		return api.FileHashResult{}, err
	}
	defer f.Close()
	hm, h1, h256 := md5.New(), sha1.New(), sha256.New()
	body := io.TeeReader(io.LimitReader(f, size), io.MultiWriter(hm, h1, h256))
	if err := h.API.Upload(ctx, id, p.Path, body, size); err != nil {
		return api.FileHashResult{}, fmt.Errorf("upload: %w", err)
	}
	hexsum := func(x hash.Hash) string { return hex.EncodeToString(x.Sum(nil)) }
	return api.FileHashResult{Path: p.Path, Size: size, MD5: hexsum(hm), SHA1: hexsum(h1), SHA256: hexsum(h256)}, nil
}

// retry retries transient transport failures a few times. Actions themselves are never
// retried; this only re-sends results that the server did not receive.
func (h *Handler) retry(ctx context.Context, fn func(ctx context.Context) error) error {
	bo := backoff.Backoff{Min: time.Second, Max: 30 * time.Second}
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		if err = fn(ctx); err == nil || !transport.Retryable(err) {
			return err
		}
		if !bo.Sleep(ctx) {
			return err
		}
	}
	return err
}

func (h *Handler) post(ctx context.Context, res api.CommandResult) {
	err := h.retry(ctx, func(ctx context.Context) error { return h.API.PostResult(ctx, res) })
	if err != nil {
		h.Log.Warn("cannot report command result", "id", res.CommandID, "status", res.Status, "err", err)
	}
}
