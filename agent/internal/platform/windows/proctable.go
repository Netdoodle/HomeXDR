//go:build windows

package windows

import (
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	// procTableMax bounds the process table.
	procTableMax = 65536
	// exitLinger is how long an exited process stays in the table, so late events
	// (a child's start read after its parent's exit) still resolve.
	exitLinger = time.Minute
	// timeSlack absorbs the difference between a process's real creation time and the
	// event times that stand in for it (logging delay, millisecond rounding).
	timeSlack = time.Second
)

// procEntry is what the table remembers about a process.
type procEntry struct {
	PID, PPID int64
	// Key is the creation time as a FILETIME, the entity ID start key.
	Key            uint64
	EntityID       string
	Start          time.Time
	Name           string
	Executable     string
	CommandLine    string
	User           *event.User
	ParentEntityID string
	// SysmonGUID is Sysmon's ProcessGuid, when the process was reported by Sysmon.
	SysmonGUID string

	exited  time.Time // event time of the exit; zero while running
	expires time.Time // wall-clock time after which an exited entry is dropped
}

// procTable maps PIDs to the processes the sensor knows about.
type procTable struct {
	mu     sync.Mutex
	max    int
	byPID  map[int64]*procEntry
	byGUID map[string]*procEntry
	now    func() time.Time
}

func newProcTable(max int) *procTable {
	return &procTable{max: max, byPID: map[int64]*procEntry{}, byGUID: map[string]*procEntry{}, now: time.Now}
}

// put adds or replaces the entry for e.PID.
func (t *procTable) put(e *procEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.byPID[e.PID]; ok && old.SysmonGUID != "" && old != e {
		if t.byGUID[old.SysmonGUID] == old {
			delete(t.byGUID, old.SysmonGUID)
		}
	}
	t.byPID[e.PID] = e
	if e.SysmonGUID != "" {
		t.byGUID[e.SysmonGUID] = e
	}
	if len(t.byPID) > t.max {
		t.evictLocked()
	}
}

// get returns the process that had this PID at time at: one that started no later
// than at and had not exited before it. A newer process with a reused PID or an old
// one that exited earlier does not match.
func (t *procTable) get(pid int64, at time.Time) *procEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.byPID[pid]
	if e == nil {
		return nil
	}
	if !at.IsZero() {
		if e.Start.After(at.Add(timeSlack)) {
			return nil
		}
		if !e.exited.IsZero() && e.exited.Before(at.Add(-timeSlack)) {
			return nil
		}
	}
	return e
}

// getRunning returns the entry for pid if it has not exited, whatever its start time.
func (t *procTable) getRunning(pid int64) *procEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.byPID[pid]; e != nil && e.exited.IsZero() {
		return e
	}
	return nil
}

// getGUID returns the process with this Sysmon ProcessGuid.
func (t *procTable) getGUID(guid string) *procEntry {
	if guid == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byGUID[guid]
}

// exit marks a process as exited at time at; it is dropped exitLinger later.
func (t *procTable) exit(e *procEntry, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e.exited = at
	e.expires = t.now().Add(exitLinger)
}

// sweep drops exited entries whose linger time is over.
func (t *procTable) sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for pid, e := range t.byPID {
		if !e.exited.IsZero() && now.After(e.expires) {
			t.removeLocked(pid, e)
		}
	}
}

func (t *procTable) removeLocked(pid int64, e *procEntry) {
	delete(t.byPID, pid)
	if e.SysmonGUID != "" && t.byGUID[e.SysmonGUID] == e {
		delete(t.byGUID, e.SysmonGUID)
	}
}

// evictLocked makes room: exited entries go first, then the oldest running ones (the
// table is only this full if exits are being missed).
func (t *procTable) evictLocked() {
	for pid, e := range t.byPID {
		if !e.exited.IsZero() {
			t.removeLocked(pid, e)
		}
	}
	for len(t.byPID) > t.max {
		var oldest *procEntry
		for _, e := range t.byPID {
			if oldest == nil || e.Start.Before(oldest.Start) {
				oldest = e
			}
		}
		t.removeLocked(oldest.PID, oldest)
	}
}

// running returns the entries that have not exited.
func (t *procTable) running() []*procEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*procEntry, 0, len(t.byPID))
	for _, e := range t.byPID {
		if e.exited.IsZero() {
			out = append(out, e)
		}
	}
	return out
}

func (t *procTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byPID)
}
