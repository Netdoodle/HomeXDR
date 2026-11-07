//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"golang.org/x/sys/windows"
)

// responder implements process termination on Windows. Isolation is not implemented yet
// (the embedded UnsupportedResponder rejects it).
type responder struct {
	platform.UnsupportedResponder
	env platform.Env
}

// criticalProcesses are never terminated: killing them crashes or locks up Windows.
var criticalProcesses = map[string]bool{
	"system": true, "registry": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "services.exe": true, "lsass.exe": true, "lsaiso.exe": true,
	"memcompression": true, "secure system": true, "fontdrvhost.exe": true, "dwm.exe": true,
}

type winProc struct {
	pid     int64
	created windows.Filetime
}

// KillProcess terminates a process, and with p.Tree its descendants. When p.EntityID is
// set, the PID must still belong to that process (same creation time), so a PID reused
// since the alert is never hit.
func (r responder) KillProcess(_ context.Context, p api.KillParams) (api.KillResult, error) {
	self := int64(os.Getpid())
	switch {
	case p.PID <= 4:
		return api.KillResult{}, fmt.Errorf("refusing to kill PID %d", p.PID)
	case p.PID == self:
		return api.KillResult{}, errors.New("refusing to kill the agent itself")
	}
	pairs, err := newWinProcs().list()
	if err != nil {
		return api.KillResult{}, fmt.Errorf("list processes: %w", err)
	}
	names := map[int64]string{}
	children := map[int64][]int64{}
	for _, pp := range pairs {
		names[pp.PID] = pp.Name
		children[pp.PPID] = append(children[pp.PPID], pp.PID)
	}
	name, ok := names[p.PID]
	if !ok {
		return api.KillResult{}, fmt.Errorf("process %d not found", p.PID)
	}
	if criticalProcesses[strings.ToLower(name)] {
		return api.KillResult{}, fmt.Errorf("refusing to kill %s (PID %d): Windows depends on it", name, p.PID)
	}
	root, err := processCreated(p.PID)
	if err != nil {
		return api.KillResult{}, fmt.Errorf("process %d not found", p.PID)
	}
	if p.EntityID != "" && r.env.EntityID(p.PID, filetimeKey(root)) != p.EntityID {
		return api.KillResult{}, fmt.Errorf("PID %d now belongs to a different process (entity ID mismatch); nothing was killed", p.PID)
	}
	targets := []winProc{{p.PID, root}}
	if p.Tree {
		// A child is only one if it was created after its parent; an older process with a
		// stale parent PID is not.
		queue := []winProc{{p.PID, root}}
		seen := map[int64]bool{p.PID: true}
		for len(queue) > 0 {
			parent := queue[0]
			queue = queue[1:]
			for _, c := range children[parent.pid] {
				if seen[c] || c == self || c <= 4 || criticalProcesses[strings.ToLower(names[c])] {
					continue
				}
				ct, err := processCreated(c)
				if err != nil || filetimeKey(ct) < filetimeKey(parent.created) {
					continue
				}
				seen[c] = true
				targets = append(targets, winProc{c, ct})
				queue = append(queue, winProc{c, ct})
			}
		}
	}
	var res api.KillResult
	var errs []error
	// Children first, so a parent cannot respawn them in between.
	for i := len(targets) - 1; i >= 0; i-- {
		t := targets[i]
		if err := terminateExact(t); err != nil {
			if !errors.Is(err, errProcessGone) {
				errs = append(errs, fmt.Errorf("pid %d: %w", t.pid, err))
			}
			continue
		}
		res.Killed = append(res.Killed, t.pid)
	}
	if len(res.Killed) == 0 {
		if len(errs) > 0 {
			return res, errors.Join(errs...)
		}
		return res, fmt.Errorf("process %d exited before it could be killed", p.PID)
	}
	return res, errors.Join(errs...)
}

var errProcessGone = errors.New("process is gone or the PID was reused")

func processCreated(pid int64) (windows.Filetime, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return windows.Filetime{}, err
	}
	defer windows.CloseHandle(h)
	var created, exit, kern, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exit, &kern, &user); err != nil {
		return windows.Filetime{}, err
	}
	return created, nil
}

// terminateExact opens the PID, checks it is still the same process and terminates it
// through that handle, so the check and the kill refer to one process object.
func terminateExact(t winProc) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(t.pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return errProcessGone
		}
		return err
	}
	defer windows.CloseHandle(h)
	var created, exit, kern, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exit, &kern, &user); err != nil || created != t.created {
		return errProcessGone
	}
	var code uint32
	if windows.GetExitCodeProcess(h, &code) == nil && code != 259 { // STILL_ACTIVE
		return errProcessGone
	}
	return windows.TerminateProcess(h, 1)
}
