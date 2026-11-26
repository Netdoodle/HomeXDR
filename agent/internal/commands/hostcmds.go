package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

// restartDelay is how long agent.restart waits after the command was accepted, so the
// result reaches the server before the agent stops.
const restartDelay = 2 * time.Second

// preparePower validates host.reboot / host.shutdown.
func (h *Handler) preparePower(cmd *api.Command) (runFunc, error) {
	p, err := api.ParseHostPower(cmd.Params)
	if err != nil {
		return nil, err
	}
	shutdown := cmd.Type == api.CmdHostShutdown
	return func(ctx context.Context) (any, int, error) {
		at := time.Now().UTC().Add(time.Duration(p.DelaySec) * time.Second)
		if err := schedulePower(ctx, shutdown, p); err != nil {
			return nil, 0, err
		}
		h.Log.Warn("host power action scheduled", "type", cmd.Type, "delay_sec", p.DelaySec, "issued_by", cmd.IssuedBy)
		return api.HostPowerResult{ScheduledFor: at.Format(time.RFC3339), DelaySec: p.DelaySec}, 0, nil
	}, nil
}

// prepareRestart validates agent.restart. The restart is started from a timer, after the
// command's result was posted; it goes through the core's clean stop (spool closed,
// sensors stopped), the same path a self-update takes.
func (h *Handler) prepareRestart(cmd *api.Command) (runFunc, error) {
	var p struct{}
	if err := decodeParams(cmd.Params, &p); err != nil {
		return nil, err
	}
	if h.Restart == nil {
		return nil, errors.New("this agent cannot restart itself")
	}
	delay := h.RestartDelay
	if delay <= 0 {
		delay = restartDelay
	}
	return func(context.Context) (any, int, error) {
		h.Log.Warn("agent restart requested", "id", cmd.ID, "issued_by", cmd.IssuedBy, "in", delay)
		time.AfterFunc(delay, h.Restart)
		return map[string]any{"restart_in_sec": int(delay.Seconds())}, 0, nil
	}, nil
}

// prepareFlushQueue validates agent.flush_queue.
func (h *Handler) prepareFlushQueue(cmd *api.Command) (runFunc, error) {
	var p struct{}
	if err := decodeParams(cmd.Params, &p); err != nil {
		return nil, err
	}
	if h.Spool == nil {
		return nil, errors.New("this agent has no event queue")
	}
	return func(context.Context) (any, int, error) {
		events, bytes, err := h.Spool.Purge()
		if err != nil {
			return nil, 0, fmt.Errorf("flush queue: %w", err)
		}
		h.Log.Warn("event queue flushed", "events", events, "bytes", bytes, "issued_by", cmd.IssuedBy)
		return api.FlushQueueResult{EventsDropped: events, BytesDropped: bytes}, 0, nil
	}, nil
}

// prepareLogs validates agent.logs.
func (h *Handler) prepareLogs(cmd *api.Command) (runFunc, error) {
	var p struct{}
	if err := decodeParams(cmd.Params, &p); err != nil {
		return nil, err
	}
	return func(ctx context.Context) (any, int, error) {
		r, err := h.agentLogs(ctx, cmd.ID)
		if err != nil {
			return nil, 0, err
		}
		return r, 0, nil
	}, nil
}
