// Package mcpserver serves HomeXDR's AI analyst tools over the Model Context Protocol
// (Streamable HTTP transport, stateless JSON responses), so MCP clients such as Claude
// Code or Claude Desktop can investigate alerts with the user's own Claude plan.
//
//	POST /mcp         JSON-RPC 2.0: initialize, ping, tools/list, tools/call
//	GET  /mcp/status  for the MCP runner: whether investigations are waiting
//
// Every request needs "Authorization: Bearer hxm_..." (an MCP token from Settings > AI
// analyst), and the endpoint answers only while MCP access is turned on.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
	"github.com/Netdoodle/homexdr/shared/version"
)

// Protocol versions this server speaks, newest first.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const maxBody = 1 << 20

// Handler serves /mcp and /mcp/status.
type Handler struct {
	st  *store.Store
	tr  *triage.Service
	log *slog.Logger
}

// New returns the MCP handler.
func New(st *store.Store, tr *triage.Service, log *slog.Logger) *Handler {
	return &Handler{st: st, tr: tr, log: log}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// DNS rebinding protection: browsers send Origin; MCP clients do not.
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			httpErr(w, http.StatusForbidden, "cross-origin requests are not allowed")
			return
		}
	}
	tok, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	set := h.tr.Settings(r.Context())
	if !set.MCPEnabled {
		httpErr(w, http.StatusForbidden, "MCP access is turned off in HomeXDR (Settings > AI analyst)")
		return
	}
	switch {
	case r.URL.Path == "/mcp/status" && r.Method == http.MethodGet:
		h.status(w, r, set)
	case r.URL.Path == "/mcp" && r.Method == http.MethodPost:
		h.rpc(w, r, tok)
	case r.URL.Path == "/mcp":
		// No server-initiated stream (GET) and no sessions to delete.
		w.Header().Set("Allow", "POST")
		httpErr(w, http.StatusMethodNotAllowed, "use POST")
	default:
		httpErr(w, http.StatusNotFound, "no such endpoint")
	}
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (*store.MCPToken, bool) {
	raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if found {
		if t, err := h.st.AuthenticateMCPToken(r.Context(), strings.TrimSpace(raw)); err == nil {
			return t, true
		} else if !errors.Is(err, store.ErrNotFound) {
			h.log.Warn("mcp: token lookup", "err", err)
			httpErr(w, http.StatusInternalServerError, "token lookup failed")
			return nil, false
		}
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="homexdr-mcp"`)
	httpErr(w, http.StatusUnauthorized, "an MCP token is required: Authorization: Bearer hxm_...")
	return nil, false
}

// status tells the MCP runner whether to start an investigation.
func (h *Handler) status(w http.ResponseWriter, r *http.Request, set triage.Settings) {
	name := strings.TrimSpace(r.Header.Get("X-HomeXDR-Runner"))
	if name != "" {
		if len(name) > 100 {
			name = name[:100]
		}
		h.tr.NoteRunner(name)
	}
	ready, why := h.tr.Ready(set)
	pending := h.tr.PendingMCP(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"engine": set.Engine, "auto_trigger": set.MCPAutoTrigger, "pending": pending,
		"run":   ready && set.Engine == store.EngineMCP && pending > 0,
		"ready": ready, "not_ready_reason": why,
	})
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (h *Handler) rpc(w http.ResponseWriter, r *http.Request, tok *store.MCPToken) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		httpErr(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	body = []byte(strings.TrimSpace(string(body)))
	client := triage.MCPClient{TokenID: tok.ID, TokenName: tok.Name}
	if len(body) > 0 && body[0] == '[' { // batches (2025-03-26 and older)
		var reqs []rpcRequest
		if err := json.Unmarshal(body, &reqs); err != nil {
			writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			return
		}
		var out []rpcResponse
		for _, req := range reqs {
			if resp, ok := h.handle(r.Context(), client, req); ok {
				out = append(out, resp)
			}
		}
		if len(out) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		return
	}
	resp, ok := h.handle(r.Context(), client, req)
	if !ok { // notification or response from the client
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handle answers one message; ok is false for notifications.
func (h *Handler) handle(ctx context.Context, c triage.MCPClient, req rpcRequest) (rpcResponse, bool) {
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return rpcResponse{}, false
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if req.JSONRPC != "2.0" || req.Method == "" {
		resp.Error = &rpcError{-32600, "invalid request"}
		return resp, true
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &p)
		pv := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				pv = v
			}
		}
		if p.ClientInfo.Name != "" {
			c.Software = strings.TrimSpace(clip(p.ClientInfo.Name, 60) + " " + clip(p.ClientInfo.Version, 30))
			h.tr.NoteMCPClient(c)
		}
		resp.Result = map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "homexdr", "title": "HomeXDR", "version": version.Version},
			"instructions":    triage.MCPInstructions,
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		var tools []map[string]any
		for _, t := range h.tr.MCPTools() {
			schema := map[string]any{"type": "object", "properties": t.Properties}
			if len(t.Required) > 0 {
				schema["required"] = t.Required
			}
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": schema})
		}
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			resp.Error = &rpcError{-32602, "invalid params: name is required"}
			return resp, true
		}
		known := false
		for _, t := range h.tr.MCPTools() {
			known = known || t.Name == p.Name
		}
		if !known {
			resp.Error = &rpcError{-32602, "unknown tool " + p.Name}
			return resp, true
		}
		if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
			p.Arguments = json.RawMessage(`{}`)
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		text, isErr := h.tr.MCPCall(cctx, c, p.Name, p.Arguments)
		cancel()
		resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	return resp, true
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
