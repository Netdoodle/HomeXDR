package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
)

// ErrNotAllowed is returned when a host's local policy does not permit an action.
var ErrNotAllowed = errors.New("action not allowed by the host's local policy")

// ValidationError is a bad request from the user.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(format, a...)} }

// AllowedActions returns the actions a host accepts.
func AllowedActions(h *store.Host) []string {
	if len(h.AllowedActions) > 0 {
		return h.AllowedActions
	}
	return api.DefaultAllowedActions
}

// IssueCommand validates and queues a command for a host and wakes the agent.
func (c *Core) IssueCommand(ctx context.Context, h *store.Host, typ string, params json.RawMessage, issuedBy, huntID string, ttl time.Duration) (*store.CommandRecord, error) {
	if h.Kind != store.HostEndpoint {
		return nil, invalid("actions are only available on endpoint hosts")
	}
	if h.Revoked {
		return nil, invalid("host is revoked")
	}
	if !slices.Contains(AllowedActions(h), typ) {
		return nil, ErrNotAllowed
	}
	clean, err := validateParams(h, typ, params)
	if err != nil {
		return nil, err
	}
	rec, err := c.State.CreateCommand(ctx, h.ID, typ, clean, issuedBy, huntID, ttl)
	if err != nil {
		return nil, err
	}
	c.Broker.Notify(h.ID)
	return rec, nil
}

func decodeStrict(params json.RawMessage, v any) error {
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(strings.NewReader(string(params)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("invalid params: %v", err)
	}
	return nil
}

func validateParams(h *store.Host, typ string, params json.RawMessage) (json.RawMessage, error) {
	var v any
	switch typ {
	case api.CmdProcessKill:
		var p api.KillParams
		if err := decodeStrict(params, &p); err != nil {
			return nil, err
		}
		if p.PID <= 4 {
			return nil, invalid("pid must be greater than 4")
		}
		v = p
	case api.CmdHostIsolate:
		var p api.IsolateParams
		if err := decodeStrict(params, &p); err != nil {
			return nil, err
		}
		for _, a := range p.Allow {
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err := netip.ParseAddr(a); err != nil {
					return nil, invalid("allow entry %q is not an IP or CIDR", a)
				}
			}
		}
		v = p
	case api.CmdHostRelease:
		v = struct{}{}
	case api.CmdFileQuarantine, api.CmdFileHash:
		var p api.FileHashParams
		if err := decodeStrict(params, &p); err != nil {
			return nil, err
		}
		if err := checkPath(h, p.Path); err != nil {
			return nil, err
		}
		v = p
	case api.CmdFileGet:
		var p api.FileGetParams
		if err := decodeStrict(params, &p); err != nil {
			return nil, err
		}
		if err := checkPath(h, p.Path); err != nil {
			return nil, err
		}
		if p.MaxBytes <= 0 || p.MaxBytes > MaxUploadBytes {
			p.MaxBytes = MaxUploadBytes
		}
		v = p
	case api.CmdFileRestore:
		var p api.RestoreParams
		if err := decodeStrict(params, &p); err != nil {
			return nil, err
		}
		if strings.TrimSpace(p.ID) == "" {
			return nil, invalid("quarantine id is required")
		}
		v = p
	case api.CmdArtifact:
		var p api.ArtifactParams
		if err := decodeStrict(params, &p); err != nil {
			return nil, err
		}
		def, ok := api.FindArtifact(p.Name)
		if !ok {
			return nil, invalid("unknown artifact %q", p.Name)
		}
		if h.OS.Platform != "" && !slices.Contains(def.Platforms, h.OS.Platform) {
			return nil, invalid("artifact %s does not support %s", p.Name, h.OS.Platform)
		}
		if p.Params == nil {
			p.Params = map[string]string{}
		}
		if err := checkArtifactParams(def, p.Params); err != nil {
			return nil, err
		}
		v = p
	default:
		return nil, invalid("unknown action type %q", typ)
	}
	return json.Marshal(v)
}

// MaxUploadBytes caps file.get uploads.
const MaxUploadBytes = 100 << 20

func checkPath(h *store.Host, p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return invalid("path is required")
	}
	if len(p) > 4096 {
		return invalid("path is too long")
	}
	abs := strings.HasPrefix(p, "/")
	if h.OS.Platform == "windows" {
		abs = len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || strings.HasPrefix(p, `\\`)
	}
	if !abs {
		return invalid("path must be absolute")
	}
	return nil
}

func checkArtifactParams(def api.ArtifactDef, params map[string]string) error {
	known := map[string]api.ArtifactArg{}
	for _, a := range def.Params {
		known[a.Name] = a
	}
	for k, v := range params {
		a, ok := known[k]
		if !ok {
			return invalid("artifact %s has no parameter %q", def.Name, k)
		}
		switch a.Type {
		case "int":
			if _, err := strconv.Atoi(v); err != nil {
				return invalid("%s must be an integer", k)
			}
		case "bool":
			if _, err := strconv.ParseBool(v); err != nil {
				return invalid("%s must be true or false", k)
			}
		}
	}
	for _, a := range def.Params {
		if a.Required && strings.TrimSpace(params[a.Name]) == "" {
			return invalid("%s is required", a.Name)
		}
	}
	return nil
}

// CreateHunt stores a hunt and queues it on every matching host.
func (c *Core) CreateHunt(ctx context.Context, artifact string, params map[string]string, desc string, target store.HuntTarget, user string, ttl time.Duration) (*store.Hunt, error) {
	def, ok := api.FindArtifact(artifact)
	if !ok {
		return nil, invalid("unknown artifact %q", artifact)
	}
	if params == nil {
		params = map[string]string{}
	}
	if err := checkArtifactParams(def, params); err != nil {
		return nil, err
	}
	if !target.All && len(target.Labels) == 0 && len(target.HostIDs) == 0 && target.Platform == "" {
		return nil, invalid("choose a target: all hosts, labels, hosts or a platform")
	}
	if target.Platform != "" && !target.All && len(target.Labels) == 0 && len(target.HostIDs) == 0 {
		target.All = true
	}
	if ttl <= 0 || ttl > 30*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}
	hunt, err := c.State.CreateHunt(ctx, artifact, params, desc, target, user, ttl)
	if err != nil {
		return nil, err
	}
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		c.queueHunt(ctx, hunt, h)
	}
	c.Audit(ctx, user, "hunt.create", hunt.ID, artifact)
	return c.State.GetHunt(ctx, hunt.ID)
}

// queueHunt queues a hunt's command on a host if it matches and has none yet.
func (c *Core) queueHunt(ctx context.Context, hunt *store.Hunt, h *store.Host) {
	if !hunt.Target.Matches(h) {
		return
	}
	def, _ := api.FindArtifact(hunt.Artifact)
	if h.OS.Platform != "" && !slices.Contains(def.Platforms, h.OS.Platform) {
		return
	}
	if has, err := c.State.HuntHasHost(ctx, hunt.ID, h.ID); err != nil || has {
		return
	}
	params, _ := json.Marshal(api.ArtifactParams{Name: hunt.Artifact, Params: hunt.Params})
	ttl := time.Until(hunt.ExpiresAt)
	if ttl <= 0 {
		return
	}
	if _, err := c.IssueCommand(ctx, h, api.CmdArtifact, params, hunt.CreatedBy, hunt.ID, ttl); err != nil &&
		!errors.Is(err, ErrNotAllowed) {
		c.Log.Warn("queue hunt", "hunt", hunt.ID, "host", h.ID, "err", err)
	}
}

// CatchUpHunts queues running hunts on a host that enrolled or came back online.
func (c *Core) CatchUpHunts(ctx context.Context, h *store.Host) {
	hunts, err := c.State.ActiveHunts(ctx)
	if err != nil {
		c.Log.Warn("active hunts", "err", err)
		return
	}
	for _, hunt := range hunts {
		c.queueHunt(ctx, hunt, h)
	}
}
