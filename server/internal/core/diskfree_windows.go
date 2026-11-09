//go:build windows

package core

// diskFree is not implemented on Windows, which is only a development platform for the server.
func diskFree(string) (uint64, bool) { return 0, false }

// diskSpace is not implemented on Windows either.
func diskSpace(string) (total, free int64) { return 0, 0 }
