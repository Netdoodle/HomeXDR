//go:build darwin

package decoy

import "golang.org/x/sys/unix"

// hiddenSupported: macOS hides files with the UF_HIDDEN flag (chflags hidden).
const hiddenSupported = true

// setHiddenFd sets or clears UF_HIDDEN on an open file. Changing file flags updates only
// the inode change time, not the size or modification time the checks compare.
func setHiddenFd(fd int, hidden bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	flags := st.Flags &^ unix.UF_HIDDEN
	if hidden {
		flags |= unix.UF_HIDDEN
	}
	if flags == st.Flags {
		return nil
	}
	return unix.Fchflags(fd, int(flags))
}
