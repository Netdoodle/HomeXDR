package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

func (h *Handler) listHosts(w http.ResponseWriter, r *http.Request, _ *store.User) {
	q := r.URL.Query()
	hosts, err := h.c.State.ListHosts(r.Context(), store.HostFilter{
		Q: q.Get("q"), Status: q.Get("status"), Label: q.Get("label"), Platform: q.Get("platform"), Kind: q.Get("kind"),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "total": len(hosts)})
}

func (h *Handler) getHost(w http.ResponseWriter, r *http.Request, _ *store.User) {
	host, err := h.c.State.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (h *Handler) patchHost(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Labels *[]string `json:"labels"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Labels == nil {
		writeErr(w, http.StatusBadRequest, "nothing to update")
		return
	}
	host, err := h.c.State.SetLabels(r.Context(), r.PathValue("id"), *req.Labels)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "host.labels", host.ID, strings.Join(host.Labels, ","))
	writeJSON(w, http.StatusOK, host)
}

func (h *Handler) deleteHost(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := h.c.State.RevokeHost(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "host.revoke", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) hostAction(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Type   string          `json:"type"`
		Params json.RawMessage `json:"params"`
	}
	if !decode(w, r, &req) {
		return
	}
	host, err := h.c.State.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	rec, err := h.c.IssueCommand(r.Context(), host, req.Type, req.Params, u.Username, "", 0)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "action."+rec.Type, host.ID, fmt.Sprintf("%s %s", host.Hostname, string(rec.Params)))
	writeJSON(w, http.StatusCreated, rec)
}

func (h *Handler) hostCommands(w http.ResponseWriter, r *http.Request, _ *store.User) {
	cmds, err := h.c.State.ListHostCommands(r.Context(), r.PathValue("id"), qInt(r, "limit", 100))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": cmds})
}

func (h *Handler) hostTimeline(w http.ResponseWriter, r *http.Request, _ *store.User) {
	q := events.SearchQuery{
		HostID:     r.PathValue("id"),
		Categories: qList(r, "category"),
		Limit:      qInt(r, "limit", 200),
		Offset:     qInt(r, "offset", 0),
	}
	q.From, _ = qTime(r, "from")
	q.To, _ = qTime(r, "to")
	if q.From.IsZero() {
		q.From = time.Now().Add(-24 * time.Hour)
	}
	res, err := h.c.Events.Search(r.Context(), q)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": res.Events, "total": res.Total})
}

func (h *Handler) getCommand(w http.ResponseWriter, r *http.Request, _ *store.User) {
	c, err := h.c.State.GetCommand(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *Handler) commandRows(w http.ResponseWriter, r *http.Request, _ *store.User) {
	rows, total, err := h.c.State.ListRows(r.Context(), r.PathValue("id"), qInt(r, "limit", 100), qInt(r, "offset", 0))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "total": total})
}

func (h *Handler) commandDownload(w http.ResponseWriter, r *http.Request, u *store.User) {
	c, err := h.c.State.GetCommand(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	if c.UploadPath == "" {
		writeErr(w, http.StatusNotFound, "no file was uploaded for this command")
		return
	}
	f, err := os.Open(c.UploadPath)
	if err != nil {
		writeErr(w, http.StatusNotFound, "uploaded file is missing")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	name := filepath.Base(strings.ReplaceAll(c.UploadName, `\`, "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == '"' || r == '\\' || r == '/' {
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." {
		name = c.ID + ".bin"
	}
	h.c.Audit(r.Context(), u.Username, "command.download", c.ID, c.UploadName)
	// Collected files may be malware: always force a download, never render.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.quarantine"`, name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

func (h *Handler) searchEvents(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var req struct {
		Query  string `json:"query"`
		From   string `json:"from"`
		To     string `json:"to"`
		HostID string `json:"host_id"`
		Limit  int    `json:"limit"`
		Offset int    `json:"offset"`
		Order  string `json:"order"`
	}
	if !decode(w, r, &req) {
		return
	}
	from, err1 := parseTime(req.From)
	to, err2 := parseTime(req.To)
	if err1 != nil || err2 != nil {
		writeErr(w, http.StatusBadRequest, "from/to must be RFC 3339 timestamps")
		return
	}
	if from.IsZero() && to.IsZero() {
		from = time.Now().Add(-24 * time.Hour)
	}
	res, err := h.c.Events.Search(r.Context(), events.SearchQuery{
		Query: req.Query, From: from, To: to, HostID: req.HostID,
		Limit: req.Limit, Offset: req.Offset, Asc: req.Order == "asc",
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) getEvent(w http.ResponseWriter, r *http.Request, _ *store.User) {
	ev, err := h.c.Events.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (h *Handler) processEvents(w http.ResponseWriter, r *http.Request, _ *store.User) {
	q := r.URL.Query()
	if q.Get("host_id") == "" || q.Get("entity_id") == "" {
		writeErr(w, http.StatusBadRequest, "host_id and entity_id are required")
		return
	}
	res, err := h.c.Events.Search(r.Context(), events.SearchQuery{
		HostID: q.Get("host_id"), EntityID: q.Get("entity_id"), Categories: qList(r, "category"),
		Limit: qInt(r, "limit", 500), Asc: true,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": res.Events, "total": res.Total})
}

// ProcessNode is one process in a tree.
type ProcessNode struct {
	EntityID       string           `json:"entity_id"`
	PID            int64            `json:"pid"`
	Name           string           `json:"name"`
	Executable     string           `json:"executable,omitempty"`
	CommandLine    string           `json:"command_line,omitempty"`
	User           string           `json:"user,omitempty"`
	Start          *time.Time       `json:"start,omitempty"`
	End            *time.Time       `json:"end,omitempty"`
	ExitCode       *int64           `json:"exit_code,omitempty"`
	ParentEntityID string           `json:"parent_entity_id,omitempty"`
	HashSHA256     string           `json:"hash_sha256,omitempty"`
	Signed         *bool            `json:"signed,omitempty"`
	AlertCount     int              `json:"alert_count"`
	EventCounts    map[string]int64 `json:"event_counts"`
	Children       []*ProcessNode   `json:"children"`
	IsTarget       bool             `json:"is_target,omitempty"`
	stub           bool
	parentInfo     *event.Process
}

func nodeFrom(p *event.Process, at time.Time) *ProcessNode {
	n := &ProcessNode{
		EntityID: p.EntityID, PID: p.PID, Name: p.Name, Executable: p.Executable, CommandLine: p.CommandLine,
		Start: p.Start, Children: []*ProcessNode{},
		EventCounts: map[string]int64{"network": 0, "file": 0, "registry": 0, "dns": 0, "library": 0},
	}
	if n.Start == nil && !at.IsZero() {
		t := at
		n.Start = &t
	}
	if n.Name == "" && p.Executable != "" {
		n.Name = filepath.Base(strings.ReplaceAll(p.Executable, `\`, "/"))
	}
	if p.User != nil {
		n.User = p.User.Name
	}
	if p.Parent != nil {
		n.ParentEntityID = p.Parent.EntityID
		n.parentInfo = p.Parent
	}
	if p.Hash != nil {
		n.HashSHA256 = p.Hash.SHA256
	}
	if cs := p.CodeSignature; cs != nil {
		signed := cs.Exists && (cs.Valid == nil || *cs.Valid)
		n.Signed = &signed
	}
	return n
}

const (
	maxAncestors     = 12
	maxTreeDepth     = 6
	maxChildrenLevel = 500
)

func (h *Handler) processTree(w http.ResponseWriter, r *http.Request, _ *store.User) {
	ctx := r.Context()
	q := r.URL.Query()
	hostID, target := q.Get("host_id"), q.Get("entity_id")
	if hostID == "" || target == "" {
		writeErr(w, http.StatusBadRequest, "host_id and entity_id are required")
		return
	}
	depth := qInt(r, "depth", 3)
	if depth < 0 {
		depth = 0
	}
	if depth > maxTreeDepth {
		depth = maxTreeDepth
	}
	nodes := map[string]*ProcessNode{}

	// lookup loads lifecycle events for the given entities into nodes.
	lookup := func(ids []string) error {
		evs, err := h.c.Events.ProcessEvents(ctx, hostID, ids)
		if err != nil {
			return err
		}
		for _, e := range evs {
			if e.Process == nil || e.Process.EntityID == "" {
				continue
			}
			n, ok := nodes[e.Process.EntityID]
			isStart := hasStr(e.Event.Type, event.TypeStart)
			if !ok || (n.stub && isStart) {
				prev := n
				n = nodeFrom(e.Process, e.Timestamp)
				if prev != nil {
					n.Children = prev.Children
					n.IsTarget = prev.IsTarget
				}
				nodes[n.EntityID] = n
			}
			if hasStr(e.Event.Type, event.TypeEnd) {
				t := e.Timestamp
				n.End = &t
				n.ExitCode = e.Process.ExitCode
			}
		}
		return nil
	}

	if err := lookup([]string{target}); err != nil {
		h.fail(w, err)
		return
	}
	if nodes[target] == nil {
		// No lifecycle event: build the node from any event of that process.
		res, err := h.c.Events.Search(ctx, events.SearchQuery{HostID: hostID, EntityID: target, Limit: 1})
		if err != nil {
			h.fail(w, err)
			return
		}
		if len(res.Events) == 0 || res.Events[0].Process == nil {
			writeErr(w, http.StatusNotFound, "process not found")
			return
		}
		n := nodeFrom(res.Events[0].Process, time.Time{})
		n.stub = true
		nodes[target] = n
	}
	nodes[target].IsTarget = true

	// Walk up.
	root := nodes[target]
	for i := 0; i < maxAncestors && root.ParentEntityID != ""; i++ {
		pid := root.ParentEntityID
		if _, ok := nodes[pid]; !ok {
			if err := lookup([]string{pid}); err != nil {
				h.fail(w, err)
				return
			}
		}
		parent, ok := nodes[pid]
		if !ok {
			// Parent never reported: make a stub from what the child knows.
			parent = parentStub(root)
			if parent == nil {
				break
			}
			nodes[pid] = parent
		}
		if !containsNode(parent.Children, root) {
			parent.Children = append(parent.Children, root)
		}
		root = parent
	}

	// Walk down from the target.
	frontier := []string{target}
	for level := 0; level < depth && len(frontier) > 0; level++ {
		kids, err := h.c.Events.Children(ctx, hostID, frontier, maxChildrenLevel)
		if err != nil {
			h.fail(w, err)
			return
		}
		var next []string
		for _, e := range kids {
			p := e.Process
			if p == nil || p.EntityID == "" || nodes[p.EntityID] != nil {
				continue
			}
			n := nodeFrom(p, e.Timestamp)
			nodes[n.EntityID] = n
			if parent := nodes[n.ParentEntityID]; parent != nil {
				parent.Children = append(parent.Children, n)
			}
			next = append(next, n.EntityID)
		}
		frontier = next
	}

	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	if err := lookup(ids); err != nil { // fills end times for descendants
		h.fail(w, err)
		return
	}
	counts, err := h.c.Events.EntityCounts(ctx, hostID, ids)
	if err != nil {
		h.fail(w, err)
		return
	}
	alerts, err := h.c.State.AlertCountsByEntity(ctx, ids)
	if err != nil {
		h.fail(w, err)
		return
	}
	for id, n := range nodes {
		for cat, c := range counts[id] {
			n.EventCounts[cat] = c
		}
		n.AlertCount = alerts[id]
	}
	writeJSON(w, http.StatusOK, map[string]any{"root": root})
}

// parentStub builds a parent node from the fields its child's event carried.
func parentStub(child *ProcessNode) *ProcessNode {
	if child.ParentEntityID == "" {
		return nil
	}
	info := child.parentInfo
	if info == nil {
		info = &event.Process{EntityID: child.ParentEntityID}
	}
	n := nodeFrom(&event.Process{
		EntityID: child.ParentEntityID, PID: info.PID, Name: info.Name,
		Executable: info.Executable, CommandLine: info.CommandLine, User: info.User,
	}, time.Time{})
	if n.Name == "" {
		n.Name = "(unknown parent)"
	}
	n.stub = true
	return n
}

func containsNode(list []*ProcessNode, n *ProcessNode) bool {
	for _, c := range list {
		if c == n {
			return true
		}
	}
	return false
}

func hasStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
