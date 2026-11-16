//go:build unix && !darwin

package decoy

// hiddenSupported: Linux (and other Unix systems) have no hidden attribute; a file name
// starting with a dot is how files are hidden there, so the Hidden option is ignored.
const hiddenSupported = false

func setHiddenFd(int, bool) error { return nil }
