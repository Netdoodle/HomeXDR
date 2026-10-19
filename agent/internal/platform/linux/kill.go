//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/api"
	"golang.org/x/sys/unix"
)

// errGone means the PID no longer refers to the expected process.
var errGone = errors.New("process is gone or the PID was reused")

// signalExact sends sig to pid only if the process still has start key want. With a
// pidfd (5.3+) the check and the signal refer to the same process even if the PID is
// recycled in between; on older kernels it falls back to kill(2).
func signalExact(pid int64, want uint64, sig unix.Signal) error {
	fd, err := unix.PidfdOpen(int(pid), 0)
	switch {
	case err == nil:
		defer unix.Close(fd)
		// The pidfd pins the process that had this PID at open time; if /proc still shows
		// the expected start key now, it is that process.
		if k, err := startKey(pid); err != nil || k != want {
			return errGone
		}
		return unix.PidfdSendSignal(fd, sig, nil, 0)
	case errors.Is(err, unix.ESRCH):
		return errGone
	case errors.Is(err, unix.ENOSYS):
		if k, err := startKey(pid); err != nil || k != want {
			return errGone
		}
		return unix.Kill(int(pid), sig)
	default:
		return err
	}
}

type procNode struct {
	pid   int64
	ppid  int64
	start uint64
}

// descendants returns the process tree below root (not including root), from /proc.
func descendants(root int64) []procNode {
	pids, _ := listPIDs()
	children := map[int64][]procNode{}
	for _, pid := range pids {
		st, err := readStat(pid)
		if err != nil {
			continue
		}
		children[st.PPID] = append(children[st.PPID], procNode{pid: pid, ppid: st.PPID, start: st.StartTick})
	}
	var out []procNode
	queue := []int64{root}
	seen := map[int64]bool{root: true}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if !seen[c.pid] {
				seen[c.pid] = true
				out = append(out, c)
				queue = append(queue, c.pid)
			}
		}
	}
	return out
}

// isKernelThread reports kthreadd (PID 2) and its children.
func isKernelThread(st procStat) bool { return st.PID == 2 || st.PPID == 2 }

func killProcess(env platform.Env, p api.KillParams) (api.KillResult, error) {
	self := int64(os.Getpid())
	switch {
	case p.PID <= 1:
		return api.KillResult{}, fmt.Errorf("refusing to kill PID %d", p.PID)
	case p.PID == self:
		return api.KillResult{}, errors.New("refusing to kill the agent itself")
	}
	st, err := readStat(p.PID)
	if err != nil {
		return api.KillResult{}, fmt.Errorf("process %d not found", p.PID)
	}
	if isKernelThread(st) {
		return api.KillResult{}, fmt.Errorf("refusing to kill kernel thread %d (%s)", p.PID, st.Comm)
	}
	if p.EntityID != "" && env.EntityID(p.PID, st.StartTick) != p.EntityID {
		return api.KillResult{}, fmt.Errorf("PID %d now belongs to a different process (entity ID mismatch); nothing was killed", p.PID)
	}
	targets := []procNode{{pid: p.PID, ppid: st.PPID, start: st.StartTick}}
	if p.Tree {
		// Stop the whole tree first so nothing can fork while we work through it, then
		// look again for children created before the stop took effect.
		_ = signalExact(p.PID, st.StartTick, unix.SIGSTOP)
		for range 2 {
			for _, d := range descendants(p.PID) {
				if d.pid != self && d.pid > 1 {
					_ = signalExact(d.pid, d.start, unix.SIGSTOP)
				}
			}
		}
		for _, d := range descendants(p.PID) {
			if d.pid != self && d.pid > 1 {
				targets = append(targets, d)
			}
		}
	}
	var res api.KillResult
	var errs []error
	// Kill the root first so its children cannot be restarted by it.
	for _, t := range targets {
		if err := signalExact(t.pid, t.start, unix.SIGKILL); err != nil {
			if !errors.Is(err, errGone) {
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
	if len(errs) > 0 {
		env.Log.Warn("kill: some processes in the tree could not be killed", "err", errors.Join(errs...))
	}
	return res, nil
}

// responder implements platform.Responder for Linux.
type responder struct {
	env platform.Env
	fw  firewall
}

func (r *responder) KillProcess(_ context.Context, p api.KillParams) (api.KillResult, error) {
	return killProcess(r.env, p)
}

func (r *responder) Isolate(ctx context.Context, iso platform.Isolation) error {
	fw, err := r.firewall()
	if err != nil {
		return err
	}
	return fw.apply(ctx, iso, resolvers())
}

func (r *responder) Release(ctx context.Context) error {
	var errs []error
	for _, fw := range availableFirewalls() {
		if err := fw.release(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *responder) Isolated() bool {
	for _, fw := range availableFirewalls() {
		if fw.active(context.Background()) {
			return true
		}
	}
	return false
}

func (r *responder) firewall() (firewall, error) {
	if r.fw != nil {
		return r.fw, nil
	}
	fws := availableFirewalls()
	if len(fws) == 0 {
		return nil, errors.New("neither nft nor iptables is installed; cannot isolate")
	}
	return fws[0], nil
}
