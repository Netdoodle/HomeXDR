//go:build linux

package linux

import (
	"context"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/event"
)

// runPoll is the last-resort process sensor: it compares /proc snapshots every second.
// Processes that live shorter than the interval are missed, and exit codes are unknown.
func (s *processSensor) runPoll(ctx context.Context, out platform.Emitter) error {
	type key struct {
		pid   int64
		start uint64
	}
	snapshot := func() map[key]procStat {
		m := map[key]procStat{}
		pids, _ := listPIDs()
		for _, pid := range pids {
			if st, err := readStat(pid); err == nil {
				m[key{pid, st.StartTick}] = st
			}
		}
		return m
	}
	done := make(chan struct{})
	defer close(done)
	en := newEnricher(s.env, event.ModuleProcfs)
	if s.cfg.HashExecutables {
		en.startHashers(1, done)
	}
	prev := snapshot()
	s.env.Log.Info("process sensor running", "impl", "procfs")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		now := time.Now().UTC()
		cur := snapshot()
		for k, st := range cur {
			if _, ok := prev[k]; ok {
				continue
			}
			pi := &procInfo{PID: k.pid, PPID: st.PPID, StartKey: k.start, Comm: st.Comm}
			en.fillFromProc(pi)
			en.emitExec(en.execEvent(pi, now), k.pid, s.cfg.HashExecutables, out)
		}
		for k, st := range prev {
			if _, ok := cur[k]; !ok {
				out.Emit(en.exitEvent(k.pid, k.start, st.Comm, 0, false, now))
			}
		}
		prev = cur
	}
}
