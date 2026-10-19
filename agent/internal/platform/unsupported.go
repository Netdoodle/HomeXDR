package platform

import (
	"context"
	"errors"

	"github.com/Netdoodle/homexdr/shared/api"
)

// ErrUnsupported is returned by actions a platform does not implement yet.
var ErrUnsupported = errors.New("not supported on this platform yet")

// UnsupportedResponder rejects every action. Platforms embed it while they are partial.
type UnsupportedResponder struct{}

// KillProcess returns ErrUnsupported.
func (UnsupportedResponder) KillProcess(context.Context, api.KillParams) (api.KillResult, error) {
	return api.KillResult{}, ErrUnsupported
}

// Isolate returns ErrUnsupported.
func (UnsupportedResponder) Isolate(context.Context, Isolation) error { return ErrUnsupported }

// Release returns nil: there is nothing to release.
func (UnsupportedResponder) Release(context.Context) error { return nil }

// Isolated returns false.
func (UnsupportedResponder) Isolated() bool { return false }

// UnsupportedService cannot install itself; the agent runs in the foreground.
type UnsupportedService struct{}

// Install returns ErrUnsupported.
func (UnsupportedService) Install(string) error { return ErrUnsupported }

// Uninstall returns ErrUnsupported.
func (UnsupportedService) Uninstall() error { return ErrUnsupported }

// Status reports that there is no service integration.
func (UnsupportedService) Status() (string, error) { return "no service integration", nil }

// RunAsService reports not handled.
func (UnsupportedService) RunAsService(func(context.Context) error) (bool, error) { return false, nil }
