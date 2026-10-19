// Package commands verifies signed commands from the server and executes the ones the
// local policy allows (docs/protocol.md, "Commands").
package commands

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Doodlebug12/homexdr/shared/api"
)

// SeenStore persists command IDs for replay protection.
type SeenStore interface {
	// MarkSeen records id and returns false if it was already recorded.
	MarkSeen(id string) (bool, error)
}

// Verifier checks SignedCommands. Policy reports whether the local config allows a type.
type Verifier struct {
	AgentID string
	Key     ed25519.PublicKey
	Seen    SeenStore
	Policy  func(typ string) bool
	Now     func() time.Time
}

// Rejection is a command that failed verification. ID is the command ID from the
// payload when it could be decoded (it is untrusted if the signature failed).
type Rejection struct {
	ID     string
	Reason string
}

func (r *Rejection) Error() string { return r.Reason }

func reject(id, format string, a ...any) *Rejection {
	return &Rejection{ID: id, Reason: fmt.Sprintf(format, a...)}
}

// Verify runs the checks in protocol order: signature, decode, agent ID, expiry, replay,
// local policy. It returns the command, or a *Rejection.
func (v *Verifier) Verify(sc api.SignedCommand) (*api.Command, error) {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	// The ID is needed to report a rejection even if the signature fails; it is only
	// used as the result URL, which the server checks against the agent's own commands.
	peekID := func() string {
		var c struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sc.Payload, &c)
		return c.ID
	}
	if len(v.Key) != ed25519.PublicKeySize {
		return nil, reject(peekID(), "agent has no pinned command key")
	}
	if len(sc.Signature) != ed25519.SignatureSize || !ed25519.Verify(v.Key, sc.Payload, sc.Signature) {
		return nil, reject(peekID(), "invalid command signature")
	}
	var c api.Command
	dec := json.NewDecoder(bytes.NewReader(sc.Payload))
	if err := dec.Decode(&c); err != nil {
		return nil, reject(peekID(), "malformed command payload: %v", err)
	}
	if c.ID == "" {
		return nil, reject("", "command has no id")
	}
	if c.AgentID != v.AgentID {
		return nil, reject(c.ID, "command is addressed to agent %q, not this agent", c.AgentID)
	}
	// From here on the command is authentic and ours: record it so it is never processed
	// twice, whatever the outcome of the remaining checks.
	fresh, err := v.Seen.MarkSeen(c.ID)
	if err != nil {
		return nil, reject(c.ID, "cannot persist replay state: %v", err)
	}
	if c.ExpiresAt.IsZero() || !now().Before(c.ExpiresAt) {
		return nil, reject(c.ID, "command expired at %s", c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if !fresh {
		return nil, reject(c.ID, "command %s was already received (replay)", c.ID)
	}
	if v.Policy == nil || !v.Policy(c.Type) {
		return nil, reject(c.ID, "action %q is not allowed by this agent's local policy (allowed_actions)", c.Type)
	}
	return &c, nil
}

// IsRejection reports whether err is a verification failure.
func IsRejection(err error) bool {
	var r *Rejection
	return errors.As(err, &r)
}
