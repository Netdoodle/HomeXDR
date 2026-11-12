//go:build darwin

package darwin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const lsofPath = "/usr/sbin/lsof"

// networkPollInterval is how often the socket table is read. Connections that open and
// close within it are missed: macOS has no unprivileged per-connection event source
// short of a Network Extension.
const networkPollInterval = 5 * time.Second

// readSockets runs lsof for every Internet socket.
func readSockets(ctx context.Context) ([]sockEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, lsofPath, lsofArgs...).Output()
	// lsof exits 1 when some files could not be read but still prints the rest.
	var ee *exec.ExitError
	if err != nil && !(errors.As(err, &ee) && len(out) > 0) {
		return nil, err
	}
	return parseLsof(out), nil
}

// networkSensor reports new TCP connections with the owning process by polling lsof.
type networkSensor struct {
	sensorState
	env   platform.Env
	procs *lru[string, procSummary]
}

func newNetworkSensor(env platform.Env) *networkSensor {
	return &networkSensor{sensorState: sensorState{name: "network"}, env: env, procs: newLRU[string, procSummary](4096)}
}

// Run polls until ctx is cancelled.
func (s *networkSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	if _, err := os.Stat(lsofPath); err != nil {
		s.set(event.ModuleLsof, api.SensorFailed, "lsof not found")
		return errors.New("lsof not found")
	}
	entries, err := readSockets(ctx)
	if err != nil {
		s.set(event.ModuleLsof, api.SensorFailed, err.Error())
		return err
	}
	s.set(event.ModuleLsof, api.SensorRunning, "")
	self := int64(os.Getpid())
	prev := established(entries)
	t := time.NewTicker(networkPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		entries, err := readSockets(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.env.Log.Warn("network sensor: lsof failed", "err", err)
			continue
		}
		cur, fresh := newConnections(prev, entries)
		prev = cur
		now := time.Now().UTC()
		for _, c := range fresh {
			if c.PID == self {
				continue // the agent's own server traffic is not reported
			}
			p := describe(s.env, s.procs, c.PID)
			if p.Name == "" {
				p.Name = c.Command
			}
			p.User = &event.User{ID: itoa(c.UID), Name: users.name(c.UID)}
			dir, action := event.DirectionOutbound, "connection_attempted"
			if c.Inbound {
				dir, action = event.DirectionInbound, "connection_accepted"
			}
			out.Emit(connEvent("tcp", dir, action, c.Local, c.Remote, p, event.ModuleLsof, now))
		}
	}
}
