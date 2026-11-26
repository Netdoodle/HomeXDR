package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Host power and agent housekeeping commands. They take no free-form input: the only
// text is the optional shutdown message, which is checked here and handed to the OS
// without a shell.

const (
	// CmdHostReboot restarts the host after HostPowerParams.DelaySec seconds.
	CmdHostReboot = "host.reboot"
	// CmdHostShutdown powers the host off after HostPowerParams.DelaySec seconds.
	CmdHostShutdown = "host.shutdown"
	// CmdAgentRestart restarts the agent process (no params). The agent reports the
	// command as completed first.
	CmdAgentRestart = "agent.restart"
	// CmdAgentLogs uploads the agent's own recent logs as a zip (no params), like
	// CmdFileGet uploads a file; the output is a FileHashResult.
	CmdAgentLogs = "agent.logs"
	// CmdAgentFlushQueue drops every event waiting in the agent's local spool (no
	// params). The output is a FlushQueueResult.
	CmdAgentFlushQueue = "agent.flush_queue"
)

func init() {
	DefaultAllowedActions = append(DefaultAllowedActions,
		CmdHostReboot, CmdHostShutdown, CmdAgentRestart, CmdAgentLogs, CmdAgentFlushQueue)
}

// Limits of HostPowerParams.
const (
	// DefaultPowerDelaySec applies when delay_sec is missing; it gives the agent time to
	// post the result before the host goes down.
	DefaultPowerDelaySec = 60
	MaxPowerDelaySec     = 3600
	MaxPowerMessageChars = 200
)

// HostPowerParams for CmdHostReboot and CmdHostShutdown.
type HostPowerParams struct {
	// DelaySec is the wait before the action, 0..MaxPowerDelaySec. A missing field means
	// DefaultPowerDelaySec; use ParseHostPower to decode it.
	DelaySec int `json:"delay_sec"`
	// Message is shown to logged-in users; at most MaxPowerMessageChars printable
	// characters.
	Message string `json:"message,omitempty"`
}

// HostPowerResult is the output of CmdHostReboot and CmdHostShutdown.
type HostPowerResult struct {
	ScheduledFor string `json:"scheduled_for"` // RFC 3339
	DelaySec     int    `json:"delay_sec"`
}

// FlushQueueResult is the output of CmdAgentFlushQueue.
type FlushQueueResult struct {
	EventsDropped int64 `json:"events_dropped"`
	BytesDropped  int64 `json:"bytes_dropped"`
}

// Validate checks the ranges and the message.
func (p HostPowerParams) Validate() error {
	if p.DelaySec < 0 || p.DelaySec > MaxPowerDelaySec {
		return fmt.Errorf("delay_sec must be between 0 and %d", MaxPowerDelaySec)
	}
	if utf8.RuneCountInString(p.Message) > MaxPowerMessageChars {
		return fmt.Errorf("message must be at most %d characters", MaxPowerMessageChars)
	}
	for _, r := range p.Message {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return errors.New("message may only contain printable characters")
		}
	}
	return nil
}

// ParseHostPower decodes and validates the params of CmdHostReboot and CmdHostShutdown:
// unknown fields are refused and a missing delay_sec becomes DefaultPowerDelaySec.
func ParseHostPower(raw json.RawMessage) (HostPowerParams, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage(`{}`)
	}
	var aux struct {
		DelaySec *int   `json:"delay_sec"`
		Message  string `json:"message"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&aux); err != nil {
		return HostPowerParams{}, fmt.Errorf("invalid params: %w", err)
	}
	p := HostPowerParams{DelaySec: DefaultPowerDelaySec, Message: aux.Message}
	if aux.DelaySec != nil {
		p.DelaySec = *aux.DelaySec
	}
	if err := p.Validate(); err != nil {
		return HostPowerParams{}, err
	}
	return p, nil
}
