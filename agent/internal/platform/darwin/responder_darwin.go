//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"golang.org/x/sys/unix"
)

// errGone means the PID no longer refers to the expected process.
var errGone = errors.New("process is gone or the PID was reused")

// signalExact sends sig to pid only if it still has start key want. macOS has no
// pidfd, so a PID reused between the check and the signal cannot be ruled out entirely;
// the window is microseconds and PIDs are not reused quickly.
func signalExact(pid int64, want uint64, sig unix.Signal) error {
	k, err := procByPID(pid)
	if err != nil || k.Start != want {
		return errGone
	}
	return unix.Kill(int(pid), sig)
}

type procNode struct {
	pid, ppid int64
	start     uint64
}

// descendants returns the process tree below root (not including root).
func descendants(root int64) []procNode {
	ps, _ := listProcs()
	children := map[int64][]procNode{}
	for _, p := range ps {
		children[p.PPID] = append(children[p.PPID], procNode{pid: p.PID, ppid: p.PPID, start: p.Start})
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

func killProcess(env platform.Env, p api.KillParams) (api.KillResult, error) {
	self := int64(os.Getpid())
	switch {
	case p.PID <= 1:
		return api.KillResult{}, fmt.Errorf("refusing to kill PID %d", p.PID)
	case p.PID == self:
		return api.KillResult{}, errors.New("refusing to kill the agent itself")
	}
	k, err := procByPID(p.PID)
	if err != nil {
		return api.KillResult{}, fmt.Errorf("process %d not found", p.PID)
	}
	if p.EntityID != "" && env.EntityID(p.PID, k.Start) != p.EntityID {
		return api.KillResult{}, fmt.Errorf("PID %d now belongs to a different process (entity ID mismatch); nothing was killed", p.PID)
	}
	targets := []procNode{{pid: p.PID, ppid: k.PPID, start: k.Start}}
	if p.Tree {
		// Stop the whole tree first so nothing can fork while we work through it.
		_ = signalExact(p.PID, k.Start, unix.SIGSTOP)
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

// responder implements platform.Responder for macOS: kill with the start time check,
// and isolation with pf rules in an anchor of the stock ruleset.
type responder struct {
	env platform.Env
}

func (r *responder) KillProcess(_ context.Context, p api.KillParams) (api.KillResult, error) {
	return killProcess(r.env, p)
}

const pfctl = "/sbin/pfctl"

func runPfctl(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pfctl, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (r *responder) tokenPath() string { return filepath.Join(r.env.DataDir, "pf.token") }

// Isolate loads the rules into the anchor, makes sure pf is enabled (holding a
// reference token, so Release does not turn off pf another program enabled), checks
// that the main ruleset consults the anchor, and drops existing connections.
func (r *responder) Isolate(ctx context.Context, iso platform.Isolation) error {
	rules := pfRules(iso, resolvers())
	if _, err := runPfctl(ctx, []byte(rules), "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	main, err := runPfctl(ctx, nil, "-s", "rules")
	if err == nil && !pfMainHasAppleAnchor(main) {
		// pf was never configured since boot: load the stock ruleset, which has it.
		if _, err := runPfctl(ctx, nil, "-f", "/etc/pf.conf"); err != nil {
			return err
		}
		main, err = runPfctl(ctx, nil, "-s", "rules")
	}
	if err != nil {
		return err
	}
	if !pfMainHasAppleAnchor(main) {
		_, _ = runPfctl(ctx, nil, "-a", pfAnchor, "-F", "rules")
		return errors.New(`the pf main ruleset has no anchor "com.apple/*" (custom /etc/pf.conf?), so isolation rules would not apply; nothing was changed`)
	}
	// Take a reference unless we hold one and pf is on (a reboot turns pf off and voids
	// the saved token).
	info, _ := runPfctl(ctx, nil, "-s", "info")
	enabled := bytes.Contains(info, []byte("Status: Enabled"))
	if b, err := os.ReadFile(r.tokenPath()); !enabled || err != nil || len(bytes.TrimSpace(b)) == 0 {
		out, err := runPfctl(ctx, nil, "-E")
		if err != nil {
			return err
		}
		if tok := pfToken(out); tok != "" {
			if err := os.WriteFile(r.tokenPath(), []byte(tok+"\n"), 0o600); err != nil {
				r.env.Log.Warn("isolation: cannot save the pf token", "err", err)
			}
		}
	}
	// Connections opened before isolation would otherwise keep flowing on their state.
	if _, err := runPfctl(ctx, nil, "-F", "states"); err != nil {
		r.env.Log.Warn("isolation: cannot flush pf states", "err", err)
	}
	return nil
}

// Release flushes the anchor and returns the pf reference taken by Isolate.
func (r *responder) Release(ctx context.Context) error {
	var errs []error
	if _, err := runPfctl(ctx, nil, "-a", pfAnchor, "-F", "all"); err != nil {
		errs = append(errs, err)
	}
	if b, err := os.ReadFile(r.tokenPath()); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			// After a reboot the token is stale; pfctl then fails harmlessly.
			if _, err := runPfctl(ctx, nil, "-X", tok); err != nil {
				r.env.Log.Info("isolation: pf token not released", "err", err)
			}
		}
		_ = os.Remove(r.tokenPath())
	}
	return errors.Join(errs...)
}

// Isolated reports whether the anchor holds rules.
func (r *responder) Isolated() bool {
	out, err := runPfctl(context.Background(), nil, "-a", pfAnchor, "-s", "rules")
	return err == nil && bytes.Contains(out, []byte("block drop"))
}

// resolvers returns the DNS servers from /etc/resolv.conf (kept current by macOS).
func resolvers() []netip.Addr {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(b)
}
