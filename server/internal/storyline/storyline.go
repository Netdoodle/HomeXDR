// Package storyline builds the attack-chain graph around a process: its lineage from a
// meaningful root, the root's descendants, the processes it acted on or that acted on it
// (cross-process events), processes it launched through the Task Scheduler, the Service
// Control Manager or WMI, and the alerts on all of them. docs/storyline.md describes it.
package storyline

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Limits.
const (
	DefaultDepth = 6   // descendant levels below the root
	MaxDepth     = 10  // most descendant levels a caller may ask for
	MaxNodes     = 500 // nodes in one graph; Graph.Truncated says when more were left out

	maxAncestors   = 12   // parents walked up from the focus
	maxCrossEvents = 2000 // cross-process events read
	maxAlerts      = 200  // alerts listed
	maxDetail      = 1000 // characters of an edge's detail
)

// ErrNotFound means no stored event describes the requested process.
var ErrNotFound = errors.New("process not found")

// Edge kinds.
const (
	EdgeParent           = "parent"
	EdgeRemoteThread     = "remote_thread"
	EdgeProcessAccess    = "process_access"
	EdgeProcessTampering = "process_tampering"
	EdgeScheduledTask    = "scheduled_task"
	EdgeService          = "service"
	EdgeWMI              = "wmi"
)

// Sources are the stores a storyline is read from.
type Sources struct {
	Events events.Store
	State  *store.Store
}

// Node is one process.
type Node struct {
	EntityID       string           `json:"entity_id"`
	PID            int64            `json:"pid"`
	Name           string           `json:"name"`
	Executable     string           `json:"executable"`
	CommandLine    string           `json:"command_line"`
	User           string           `json:"user"`
	Start          *time.Time       `json:"start"`
	End            *time.Time       `json:"end"`
	ExitCode       *int64           `json:"exit_code"`
	Signed         *bool            `json:"signed"`
	IntegrityLevel string           `json:"integrity_level"`
	ParentEntityID string           `json:"parent_entity_id"`
	Depth          int              `json:"depth"` // 0 is the root, -1 its context parent
	Focus          bool             `json:"focus"`
	Root           bool             `json:"root"`
	Context        bool             `json:"context"` // the system process above the root
	Outside        bool             `json:"outside"` // reached only through a cross-process event
	Stub           bool             `json:"stub"`    // no start or end event: built from what other events said
	AlertCount     int              `json:"alert_count"`
	MaxSeverity    string           `json:"max_severity"`
	Tactics        []string         `json:"tactics"`
	EventCounts    map[string]int64 `json:"event_counts"`

	parentInfo   *event.Process // what a child's event said about this node's parent
	startEventID string
}

// Edge links two nodes.
type Edge struct {
	From    string     `json:"from"`
	To      string     `json:"to"`
	Kind    string     `json:"kind"`
	At      *time.Time `json:"at"`
	EventID string     `json:"event_id"`
	Detail  string     `json:"detail"`
}

// Alert is an alert on one of the nodes.
type Alert struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	EntityID  string    `json:"entity_id"`
	Tactics   []string  `json:"tactics"`
}

// Graph is a storyline.
type Graph struct {
	HostID        string  `json:"host_id"`
	Hostname      string  `json:"hostname"`
	FocusEntityID string  `json:"focus_entity_id"`
	RootEntityID  string  `json:"root_entity_id"`
	Truncated     bool    `json:"truncated"`
	Nodes         []*Node `json:"nodes"`
	Edges         []Edge  `json:"edges"`
	Alerts        []Alert `json:"alerts"`
}

// eventCountKeys are the categories counted per node.
var eventCountKeys = []string{"network", "file", "registry", events.CategoryDNS, "library"}

type builder struct {
	ctx      context.Context
	src      Sources
	hostID   string
	depth    int
	g        *Graph
	nodes    map[string]*Node
	order    []*Node             // insertion order
	kids     map[string][]string // parent entity ID -> child entity IDs, in the graph
	expanded map[string]bool     // nodes whose children were read
	edges    []Edge
	edgeSeen map[string]bool
	hostname string
}

// Build returns the storyline around the process focus on a host. depth is how many
// levels of descendants to show below the root (and below the focus); it is clamped to
// 0..MaxDepth.
func Build(ctx context.Context, src Sources, hostID, focus string, depth int) (*Graph, error) {
	depth = max(0, min(depth, MaxDepth))
	b := &builder{
		ctx: ctx, src: src, hostID: hostID, depth: depth,
		g:     &Graph{HostID: hostID, FocusEntityID: focus, Nodes: []*Node{}, Edges: []Edge{}, Alerts: []Alert{}},
		nodes: map[string]*Node{}, kids: map[string][]string{}, expanded: map[string]bool{}, edgeSeen: map[string]bool{},
	}
	if err := b.loadFocus(focus); err != nil {
		return nil, err
	}
	root, err := b.walkUp(b.nodes[focus])
	if err != nil {
		return nil, err
	}
	b.g.RootEntityID = root.EntityID
	if err := b.walkDown(root.EntityID, depth); err != nil {
		return nil, err
	}
	if err := b.walkDown(focus, depth); err != nil {
		return nil, err
	}
	if err := b.launchedVia(); err != nil {
		return nil, err
	}
	if err := b.lifecycle(); err != nil {
		return nil, err
	}
	if err := b.crossProcess(); err != nil {
		return nil, err
	}
	if err := b.alerts(); err != nil {
		return nil, err
	}
	if err := b.counts(); err != nil {
		return nil, err
	}
	b.finish()
	return b.g, nil
}

func newNode(id string) *Node {
	n := &Node{EntityID: id, Stub: true, Tactics: []string{}, EventCounts: map[string]int64{}}
	for _, k := range eventCountKeys {
		n.EventCounts[k] = 0
	}
	return n
}

func setStr(dst *string, v string, overwrite bool) {
	if v != "" && (overwrite || *dst == "") {
		*dst = v
	}
}

// merge copies what p says into n. Values from a start event (authoritative) win; others
// only fill gaps.
func merge(n *Node, p *event.Process, authoritative bool) {
	if p == nil {
		return
	}
	if p.PID != 0 && (authoritative || n.PID == 0) {
		n.PID = p.PID
	}
	setStr(&n.Name, p.Name, authoritative)
	setStr(&n.Executable, p.Executable, authoritative)
	setStr(&n.CommandLine, p.CommandLine, authoritative)
	setStr(&n.IntegrityLevel, p.IntegrityLevel, authoritative)
	if p.User != nil {
		setStr(&n.User, p.User.Name, authoritative)
	}
	if p.Start != nil && (authoritative || n.Start == nil) {
		t := *p.Start
		n.Start = &t
	}
	if p.Parent != nil && p.Parent.EntityID != "" && (authoritative || n.ParentEntityID == "") {
		n.ParentEntityID = p.Parent.EntityID
		n.parentInfo = p.Parent
	}
	if cs := p.CodeSignature; cs != nil && (authoritative || n.Signed == nil) {
		signed := cs.Exists && (cs.Valid == nil || *cs.Valid)
		n.Signed = &signed
	}
	if n.Name == "" && n.Executable != "" {
		n.Name = filepath.Base(strings.ReplaceAll(n.Executable, `\`, "/"))
	}
}

func hasType(e *event.Event, t string) bool {
	for _, v := range e.Event.Type {
		if v == t {
			return true
		}
	}
	return false
}

// apply folds a process lifecycle event into n.
func apply(n *Node, e *event.Event) {
	start := hasType(e, event.TypeStart)
	merge(n, e.Process, start)
	if start {
		n.startEventID = e.ID
		if n.Start == nil {
			t := e.Timestamp
			n.Start = &t
		}
	}
	if hasType(e, event.TypeEnd) {
		t := e.Timestamp
		n.End = &t
		if e.Process.ExitCode != nil {
			n.ExitCode = e.Process.ExitCode
		}
	}
	n.Stub = false
}

func (b *builder) noteHost(e *event.Event) {
	if b.hostname == "" && e.Host.Name != "" {
		b.hostname = e.Host.Name
	}
}

// fromLifecycle builds nodes, not yet added, from the lifecycle events of ids.
func (b *builder) fromLifecycle(ids []string) (map[string]*Node, error) {
	out := map[string]*Node{}
	if len(ids) == 0 {
		return out, nil
	}
	evs, err := b.src.Events.ProcessEvents(b.ctx, b.hostID, ids)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		if e.Process == nil || e.Process.EntityID == "" {
			continue
		}
		b.noteHost(e)
		n := out[e.Process.EntityID]
		if n == nil {
			n = newNode(e.Process.EntityID)
			out[n.EntityID] = n
		}
		apply(n, e)
	}
	return out, nil
}

// add puts n in the graph unless the graph is full.
func (b *builder) add(n *Node) bool {
	if _, ok := b.nodes[n.EntityID]; ok {
		return true
	}
	if len(b.nodes) >= MaxNodes {
		b.g.Truncated = true
		return false
	}
	b.nodes[n.EntityID] = n
	b.order = append(b.order, n)
	if n.ParentEntityID != "" {
		b.kids[n.ParentEntityID] = append(b.kids[n.ParentEntityID], n.EntityID)
	}
	return true
}

func (b *builder) loadFocus(id string) error {
	found, err := b.fromLifecycle([]string{id})
	if err != nil {
		return err
	}
	n := found[id]
	if n == nil {
		// No lifecycle event: build the node from any event of that process.
		res, err := b.src.Events.Search(b.ctx, events.SearchQuery{HostID: b.hostID, EntityID: id, Limit: 1})
		if err != nil {
			return err
		}
		if len(res.Events) > 0 && res.Events[0].Process != nil {
			n = newNode(id)
			merge(n, res.Events[0].Process, false)
			b.noteHost(res.Events[0])
		}
	}
	if n == nil {
		// Or from a cross-process event that names it.
		evs, err := b.src.Events.CrossProcess(b.ctx, b.hostID, []string{id}, 1)
		if err != nil {
			return err
		}
		if len(evs) > 0 {
			n = newNode(id)
			merge(n, crossEnd(evs[0], id), false)
			b.noteHost(evs[0])
		}
	}
	if n == nil {
		return ErrNotFound
	}
	n.Focus = true
	b.add(n)
	return nil
}

// crossEnd returns the side of a cross-process event that is the process id.
func crossEnd(e *event.Event, id string) *event.Process {
	if e.Target != nil && e.Target.Process != nil && e.Target.Process.EntityID == id {
		return e.Target.Process
	}
	if e.Process != nil && e.Process.EntityID == id {
		return e.Process
	}
	return nil
}

// parentOf loads child's parent, from its lifecycle events or, failing that, from what
// the child's events said about it. It returns nil when the child names no parent.
func (b *builder) parentOf(child *Node) (*Node, error) {
	pid := child.ParentEntityID
	if pid == "" {
		return nil, nil
	}
	if n := b.nodes[pid]; n != nil {
		return n, nil
	}
	found, err := b.fromLifecycle([]string{pid})
	if err != nil {
		return nil, err
	}
	n := found[pid]
	if n == nil {
		n = newNode(pid)
		info := child.parentInfo
		if info != nil {
			merge(n, &event.Process{PID: info.PID, Name: info.Name, Executable: info.Executable,
				CommandLine: info.CommandLine, User: info.User}, false)
		}
		if n.Name == "" {
			n.Name = "(unknown parent)"
		}
	}
	return n, nil
}

// walkUp climbs from the focus to the root: the topmost ancestor below a system process
// (isBoundary), which becomes the context node. A focus that is itself a system process
// is its own root.
func (b *builder) walkUp(focus *Node) (*Node, error) {
	chain := []*Node{focus}
	var ctxNode *Node
	cur := focus
	if isBoundary(focus.Name) {
		p, err := b.parentOf(focus)
		if err != nil {
			return nil, err
		}
		ctxNode = p
	} else {
		for i := 0; ; i++ {
			p, err := b.parentOf(cur)
			if err != nil {
				return nil, err
			}
			if p == nil {
				break
			}
			if _, inGraph := b.nodes[p.EntityID]; inGraph {
				break // a loop (PID reuse or bad data)
			}
			if isBoundary(p.Name) {
				ctxNode = p
				break
			}
			if i == maxAncestors {
				b.g.Truncated = true // the lineage goes on
				break
			}
			chain = append(chain, p)
			b.add(p)
			cur = p
		}
	}
	for i, n := range chain {
		n.Depth = len(chain) - 1 - i
	}
	root := chain[len(chain)-1]
	root.Root = true
	if ctxNode != nil {
		if _, inGraph := b.nodes[ctxNode.EntityID]; !inGraph {
			ctxNode.Context = true
			ctxNode.Depth = -1
			b.add(ctxNode)
		}
	}
	return root, nil
}

// walkDown adds the descendants of id, levels deep.
func (b *builder) walkDown(id string, levels int) error {
	frontier := []string{id}
	for level := 0; level < levels && len(frontier) > 0; level++ {
		var query []string
		for _, f := range frontier {
			if !b.expanded[f] {
				b.expanded[f] = true
				query = append(query, f)
			}
		}
		if len(query) > 0 {
			kids, err := b.src.Events.Children(b.ctx, b.hostID, query, MaxNodes+1)
			if err != nil {
				return err
			}
			if len(kids) > MaxNodes {
				b.g.Truncated = true
			}
			for _, e := range kids {
				p := e.Process
				if p == nil || p.EntityID == "" || b.nodes[p.EntityID] != nil {
					continue
				}
				n := newNode(p.EntityID)
				apply(n, e)
				if parent := b.nodes[n.ParentEntityID]; parent != nil {
					n.Depth = parent.Depth + 1
				}
				if !b.add(n) {
					break
				}
			}
		}
		var next []string
		for _, f := range frontier {
			next = append(next, b.kids[f]...)
		}
		frontier = next
	}
	return nil
}

// lifecycle fills end times and replaces stubs for every node with a lifecycle event.
func (b *builder) lifecycle() error {
	ids := make([]string, 0, len(b.order))
	for _, n := range b.order {
		ids = append(ids, n.EntityID)
	}
	evs, err := b.src.Events.ProcessEvents(b.ctx, b.hostID, ids)
	if err != nil {
		return err
	}
	for _, e := range evs {
		if e.Process == nil {
			continue
		}
		if n := b.nodes[e.Process.EntityID]; n != nil {
			apply(n, e)
		}
	}
	return nil
}

func (b *builder) addEdge(e Edge) {
	key := e.From + "\x00" + e.To + "\x00" + e.Kind
	if b.edgeSeen[key] {
		return
	}
	b.edgeSeen[key] = true
	if len(e.Detail) > maxDetail {
		e.Detail = e.Detail[:maxDetail]
	}
	b.edges = append(b.edges, e)
}

// crossKind maps a cross-process event to its edge kind ("" for none).
func crossKind(e *event.Event) string {
	switch e.Event.Action {
	case event.ActionRemoteThread:
		return EdgeRemoteThread
	case event.ActionProcessAccess:
		return EdgeProcessAccess
	case event.ActionProcessTampering:
		return EdgeProcessTampering
	}
	if strings.EqualFold(e.Event.Provider, "Microsoft-Windows-Sysmon") {
		switch e.Event.Code {
		case "8":
			return EdgeRemoteThread
		case "10":
			return EdgeProcessAccess
		case "25":
			return EdgeProcessTampering
		}
	}
	return ""
}

func crossDetail(kind string, t *event.Target) string {
	if t == nil {
		return ""
	}
	switch kind {
	case EdgeProcessAccess:
		return t.GrantedAccess
	case EdgeProcessTampering:
		return t.Tampering
	case EdgeRemoteThread:
		start := t.StartModule
		if t.StartFunction != "" {
			start += "!" + t.StartFunction
		}
		if t.StartAddress != "" {
			start = strings.TrimSpace(start + " " + t.StartAddress)
		}
		return start
	}
	return ""
}

// crossProcess adds cross-process edges touching the graph's processes. The other process
// joins the graph as an outside node. The context node is left out of the lookup: system
// processes such as lsass.exe are opened by much of the system.
func (b *builder) crossProcess() error {
	var ids []string
	for _, n := range b.order {
		if !n.Context {
			ids = append(ids, n.EntityID)
		}
	}
	evs, err := b.src.Events.CrossProcess(b.ctx, b.hostID, ids, maxCrossEvents)
	if err != nil {
		return err
	}
	if len(evs) >= maxCrossEvents {
		b.g.Truncated = true
	}
	type link struct {
		e        *event.Event
		kind     string
		from, to string
	}
	var links []link
	missing := map[string]*event.Process{}
	var missingOrder []string
	need := func(id string, p *event.Process) {
		if _, ok := b.nodes[id]; ok {
			return
		}
		if _, ok := missing[id]; !ok {
			missing[id] = p
			missingOrder = append(missingOrder, id)
		}
	}
	for _, e := range evs {
		kind := crossKind(e)
		if kind == "" || e.Process == nil || e.Process.EntityID == "" {
			continue
		}
		from := e.Process.EntityID
		var to string
		if e.Target != nil && e.Target.Process != nil {
			to = e.Target.Process.EntityID
		}
		if to == "" {
			if kind != EdgeProcessTampering {
				continue // the acted-on process is unknown
			}
			to = from // tampering reported about the process itself
		}
		need(from, e.Process)
		if to != from {
			need(to, e.Target.Process)
		}
		links = append(links, link{e, kind, from, to})
	}
	found, err := b.fromLifecycle(missingOrder)
	if err != nil {
		return err
	}
	for _, l := range links {
		for _, id := range []string{l.from, l.to} {
			if _, ok := b.nodes[id]; ok {
				continue
			}
			n := found[id]
			if n == nil {
				n = newNode(id)
				merge(n, missing[id], false)
			}
			n.Outside = true
			peer := l.from
			if id == l.from {
				peer = l.to
			}
			if p := b.nodes[peer]; p != nil {
				n.Depth = p.Depth
			}
			b.add(n)
		}
		if b.nodes[l.from] == nil || b.nodes[l.to] == nil {
			continue // the graph is full
		}
		at := l.e.Timestamp
		b.addEdge(Edge{From: l.from, To: l.to, Kind: l.kind, At: &at, EventID: l.e.ID, Detail: crossDetail(l.kind, l.e.Target)})
	}
	return nil
}

func (b *builder) alerts() error {
	if b.src.State == nil {
		return nil
	}
	ids := make([]string, 0, len(b.order))
	for _, n := range b.order {
		ids = append(ids, n.EntityID)
	}
	list, err := b.src.State.AlertsForEntities(b.ctx, b.hostID, ids, maxAlerts)
	if err != nil {
		return err
	}
	counts, err := b.src.State.AlertCountsByEntity(b.ctx, ids)
	if err != nil {
		return err
	}
	for _, a := range list {
		tactics := tacticSlugs(a.Mitre)
		b.g.Alerts = append(b.g.Alerts, Alert{ID: a.ID, Title: a.Rule.Title, Severity: a.Severity, Status: a.Status,
			FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, EntityID: a.ProcessEntityID, Tactics: tactics})
		n := b.nodes[a.ProcessEntityID]
		if n == nil {
			continue
		}
		if severityRank[a.Severity] > severityRank[n.MaxSeverity] {
			n.MaxSeverity = a.Severity
		}
		n.Tactics = unionTactics(n.Tactics, tactics)
	}
	for id, c := range counts {
		if n := b.nodes[id]; n != nil {
			n.AlertCount = c
		}
	}
	return nil
}

func (b *builder) counts() error {
	ids := make([]string, 0, len(b.order))
	for _, n := range b.order {
		ids = append(ids, n.EntityID)
	}
	counts, err := b.src.Events.EntityCounts(b.ctx, b.hostID, ids)
	if err != nil {
		return err
	}
	for id, m := range counts {
		n := b.nodes[id]
		if n == nil {
			continue
		}
		for _, k := range eventCountKeys {
			n.EventCounts[k] = m[k]
		}
	}
	return nil
}

func (b *builder) finish() {
	if b.src.State != nil {
		if h, err := b.src.State.GetHost(b.ctx, b.hostID); err == nil && h.Hostname != "" {
			b.hostname = h.Hostname
		}
	}
	b.g.Hostname = b.hostname

	nodes := append([]*Node(nil), b.order...)
	sort.SliceStable(nodes, func(i, j int) bool {
		a, c := nodes[i], nodes[j]
		if a.Depth != c.Depth {
			return a.Depth < c.Depth
		}
		switch {
		case a.Start != nil && c.Start != nil && !a.Start.Equal(*c.Start):
			return a.Start.Before(*c.Start)
		case (a.Start == nil) != (c.Start == nil):
			return a.Start != nil
		}
		return a.EntityID < c.EntityID
	})
	b.g.Nodes = nodes

	edges := []Edge{}
	for _, n := range nodes {
		if p := b.nodes[n.ParentEntityID]; p != nil && p != n {
			edges = append(edges, Edge{From: p.EntityID, To: n.EntityID, Kind: EdgeParent, At: n.Start, EventID: n.startEventID})
		}
	}
	b.g.Edges = append(edges, b.edges...)
}

// severityRank orders alert severities.
var severityRank = map[string]int{
	store.SevInformational: 1, store.SevLow: 2, store.SevMedium: 3, store.SevHigh: 4, store.SevCritical: 5,
}

// tacticOrder is ATT&CK's tactic order, which tactics lists follow.
var tacticOrder = []string{
	"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
	"privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
	"collection", "command-and-control", "exfiltration", "impact",
}

var tacticRank = func() map[string]int {
	m := map[string]int{}
	for i, t := range tacticOrder {
		m[t] = i
	}
	return m
}()

// tacticSlug turns "Privilege Escalation" or "privilege_escalation" into
// "privilege-escalation".
func tacticSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("_", "-", " ", "-").Replace(s)
	return strings.Trim(s, "-")
}

func tacticSlugs(m []store.Mitre) []string {
	out := []string{}
	for _, x := range m {
		if x.Tactic != "" {
			out = unionTactics(out, []string{tacticSlug(x.Tactic)})
		}
	}
	return out
}

// unionTactics merges two tactic lists without repeats, in ATT&CK order (unknown
// tactics last, alphabetically).
func unionTactics(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, list := range [][]string{a, b} {
		for _, t := range list {
			if t != "" && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := tacticRank[out[i]]
		rj, jok := tacticRank[out[j]]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok
		}
		return out[i] < out[j]
	})
	return out
}
