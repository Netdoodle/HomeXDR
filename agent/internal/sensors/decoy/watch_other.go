//go:build !linux

package decoy

import "log/slog"

// realtime is false: only Linux has cheap per-file notifications that include reads.
// Windows and macOS rely on the periodic check.
const realtime = false

func newWatcher(func(string, watchKind), *slog.Logger) (watcher, error) { return nil, nil }
