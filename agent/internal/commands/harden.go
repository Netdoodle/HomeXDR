package commands

import (
	"context"
	"errors"

	"github.com/Netdoodle/homexdr/agent/internal/hardening"
	"github.com/Netdoodle/homexdr/shared/api"
)

// prepareHarden validates a defender.harden command: a mode and a version, nothing else.
func (h *Handler) prepareHarden(cmd *api.Command) (runFunc, error) {
	var p api.DefenderHardenParams
	if err := decodeParams(cmd.Params, &p); err != nil {
		return nil, err
	}
	if h.Hardening == nil {
		return nil, errors.New("Defender hardening is only available on Windows")
	}
	if err := hardening.Validate(p); err != nil {
		return nil, err
	}
	return func(ctx context.Context) (any, int, error) {
		r, err := h.Hardening.DefenderHarden(ctx, p)
		if err != nil {
			return nil, 0, err
		}
		return r, 0, nil
	}, nil
}
