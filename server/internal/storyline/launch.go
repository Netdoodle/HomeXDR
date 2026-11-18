package storyline

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/shared/event"
)

// boundaryNames are system processes a storyline does not climb past: session managers,
// service hosts, shells of the desktop and init systems. Their children start the
// interesting part. Names compare case-insensitively.
var boundaryNames = map[string]bool{
	// Windows
	"system": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "lsass.exe": true, "svchost.exe": true, "explorer.exe": true, "userinit.exe": true,
	"wmiprvse.exe": true, "taskhostw.exe": true, "taskeng.exe": true,
	// Linux and macOS
	"systemd": true, "init": true, "launchd": true, "cron": true, "crond": true, "sshd": true,
	"sshd-session": true, "login": true, "kthreadd": true,
}

// isBoundary reports whether a process name is a system process (see boundaryNames).
// containerd-shim* (the parent of a container's first process) counts too.
func isBoundary(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return boundaryNames[n] || strings.HasPrefix(n, "containerd-shim")
}

const (
	launchWindow     = 24 * time.Hour // how long after the creator a launch is linked
	maxCreators      = 10             // creating commands followed
	maxLaunchPages   = 3              // pages of candidate process starts read per creator
	launchPageEvents = 1000
)

// launchPatterns recognise commands that make the system start a program later. They
// run on the lowercased command line.
var launchPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{EdgeScheduledTask, regexp.MustCompile(`\bschtasks(\.exe)?["']?\s.*[/-]create\b`)},
	{EdgeScheduledTask, regexp.MustCompile(`\bregister-scheduledtask\b`)},
	{EdgeScheduledTask, regexp.MustCompile(`(^|[\\/\s"'])at(\.exe)?["']?\s+(\\\\\S+\s+)?\d{1,2}:\d{2}`)},
	{EdgeService, regexp.MustCompile(`\bsc(\.exe)?["']?\s+(\\\\\S+\s+)?(create|config)\b`)},
	{EdgeService, regexp.MustCompile(`\bnew-service\b`)},
	{EdgeWMI, regexp.MustCompile(`\bwmic(\.exe)?["']?\s.*\bprocess\s+call\s+create\b`)},
	{EdgeWMI, regexp.MustCompile(`\b(invoke-wmimethod|invoke-cimmethod)\b.*\bwin32_process\b.*\bcreate\b`)},
	{EdgeWMI, regexp.MustCompile(`\b(invoke-wmimethod|invoke-cimmethod)\b.*\bcreate\b.*\bwin32_process\b`)},
	{EdgeWMI, regexp.MustCompile(`\bcommandlineeventconsumer\b`)},
}

// launchKind returns the edge kind of a command line that schedules, installs or
// remotely creates a process, or "".
func launchKind(cmd string) string {
	lc := strings.ToLower(cmd)
	for _, p := range launchPatterns {
		if p.re.MatchString(lc) {
			return p.kind
		}
	}
	return ""
}

// launchParents are the processes that start what each kind of creator set up.
var launchParents = map[string][]string{
	EdgeScheduledTask: {"svchost.exe", "taskeng.exe", "taskhostw.exe"},
	EdgeService:       {"services.exe"},
	EdgeWMI:           {"wmiprvse.exe"},
}

// normCmd lowercases a command line and drops quotes and repeated spaces, so the
// quoting a creator used and the quoting the launched process shows compare equal.
func normCmd(s string) string {
	s = strings.NewReplacer(`"`, " ", `'`, " ").Replace(strings.ToLower(s))
	return strings.Join(strings.Fields(s), " ")
}

// cmdArgs returns a command line without its first token (the program).
func cmdArgs(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.Index(cmd[1:], `"`); i >= 0 {
			return strings.TrimSpace(cmd[i+2:])
		}
		return ""
	}
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		return strings.TrimSpace(cmd[i:])
	}
	return ""
}

// payloadMatch reports whether the process n is what the creating command line set up:
// its whole command line appears in it, or its executable path does (with its arguments,
// for programs under the Windows directory, which tasks and services run all the time),
// or its file name and arguments do.
func payloadMatch(creatorCmd string, n *Node) bool {
	c := normCmd(creatorCmd)
	if c == "" {
		return false
	}
	args := normCmd(cmdArgs(n.CommandLine))
	if cl := normCmd(n.CommandLine); len(cl) >= 8 && strings.Contains(c, cl) {
		return true
	}
	if exe := normCmd(n.Executable); len(exe) >= 4 && strings.Contains(c, exe) {
		if args == "" || strings.Contains(c, args) || !strings.HasPrefix(exe, `c:\windows\`) {
			return true
		}
	}
	base := strings.ToLower(n.Name)
	if base == "" && n.Executable != "" {
		base = strings.ToLower(filepath.Base(strings.ReplaceAll(n.Executable, `\`, "/")))
	}
	return base != "" && len(args) >= 6 && strings.Contains(c, base) && strings.Contains(c, args)
}

// launchedVia links processes the Task Scheduler, the Service Control Manager or WMI
// started within launchWindow of a graph process whose command line set them up. It is
// a heuristic: see docs/storyline.md. One hop only: launched processes are not followed
// as creators.
func (b *builder) launchedVia() error {
	type creator struct {
		n    *Node
		kind string
	}
	var creators []creator
	for _, n := range b.order {
		if n.Outside || n.Context || n.Start == nil || n.CommandLine == "" {
			continue
		}
		if kind := launchKind(n.CommandLine); kind != "" {
			creators = append(creators, creator{n, kind})
			if len(creators) == maxCreators {
				break
			}
		}
	}
	for _, c := range creators {
		parents := launchParents[c.kind]
		terms := make([]string, len(parents))
		for i, p := range parents {
			terms[i] = "process.parent.name:" + p
		}
		q := events.SearchQuery{
			Query:  "event.type:start AND (" + strings.Join(terms, " OR ") + ")",
			HostID: b.hostID, Categories: []string{event.CategoryProcess},
			From: *c.n.Start, To: c.n.Start.Add(launchWindow), Limit: launchPageEvents, Asc: true,
		}
		for page := 0; page < maxLaunchPages; page++ {
			q.Offset = page * launchPageEvents
			res, err := b.src.Events.Search(b.ctx, q)
			if err != nil {
				return err
			}
			for _, e := range res.Events {
				if full, err := b.linkLaunch(c.n, c.kind, e); full || err != nil {
					return err
				}
			}
			if len(res.Events) < launchPageEvents {
				break
			}
		}
	}
	return nil
}

// linkLaunch links e's process to creator when it matches. It reports whether the graph
// is full.
func (b *builder) linkLaunch(creator *Node, kind string, e *event.Event) (bool, error) {
	p := e.Process
	if p == nil || p.EntityID == "" || p.EntityID == creator.EntityID {
		return false, nil
	}
	// The Task Scheduler runs in a svchost.exe of its own ("-s Schedule"); when the
	// parent's command line says it is another service's, it is not a task.
	if kind == EdgeScheduledTask && p.Parent != nil && strings.EqualFold(p.Parent.Name, "svchost.exe") {
		pc := strings.ToLower(p.Parent.CommandLine)
		if strings.Contains(pc, "-s ") && !strings.Contains(pc, "schedule") {
			return false, nil
		}
	}
	n := b.nodes[p.EntityID]
	if n == nil {
		cand := newNode(p.EntityID)
		apply(cand, e)
		if !payloadMatch(creator.CommandLine, cand) {
			return false, nil
		}
		cand.Depth = creator.Depth + 1
		if !b.add(cand) {
			return true, nil
		}
		n = cand
		if err := b.walkDown(cand.EntityID, b.depth); err != nil {
			return false, err
		}
	} else if !payloadMatch(creator.CommandLine, n) {
		return false, nil
	}
	at := e.Timestamp
	b.addEdge(Edge{From: creator.EntityID, To: n.EntityID, Kind: kind, At: &at, EventID: e.ID, Detail: creator.CommandLine})
	return false, nil
}
