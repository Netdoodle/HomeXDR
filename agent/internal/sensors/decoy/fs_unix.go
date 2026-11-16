//go:build unix

package decoy

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// openChain opens base (following links: an administrator controls it), then each of
// dirs below it with O_NOFOLLOW, so a user who swaps a folder in their home for a link
// cannot redirect the agent. With mkLast the last folder is created (0700) if it is
// missing, owned by uid/gid when chown is set, or by the owner of the folder it is
// created in when inherit is set. It returns the last folder's descriptor.
func openChain(base string, dirs []string, mkLast bool, uid, gid int, chown, inherit bool) (fd int, made bool, err error) {
	fd, err = unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, false, errNoFolder
		}
		if errors.Is(err, unix.ENOTDIR) {
			return -1, false, errUnsafe
		}
		return -1, false, err
	}
	for i, d := range dirs {
		const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		nfd, err := unix.Openat(fd, d, flags, 0)
		if errors.Is(err, unix.ENOENT) && mkLast && i == len(dirs)-1 {
			if err = unix.Mkdirat(fd, d, 0o700); err == nil || errors.Is(err, unix.EEXIST) {
				made = err == nil
				nfd, err = unix.Openat(fd, d, flags, 0)
				if err == nil && made {
					_ = unix.Fchmod(nfd, 0o700)
					var pst unix.Stat_t
					switch {
					case chown:
						_ = unix.Fchown(nfd, uid, gid)
					case inherit && unix.Fstat(fd, &pst) == nil:
						_ = unix.Fchown(nfd, int(pst.Uid), int(pst.Gid))
					}
				}
			}
		}
		unix.Close(fd)
		if err != nil {
			switch {
			case errors.Is(err, unix.ENOENT):
				return -1, false, errNoFolder
			case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EMLINK):
				return -1, false, errUnsafe
			}
			return -1, false, err
		}
		fd = nfd
	}
	return fd, made, nil
}

func folderOK(t target, n int) error {
	fd, _, err := openChain(t.Base, t.Dirs[:n], false, 0, 0, false, false)
	if err == nil {
		unix.Close(fd)
	}
	return err
}

func stateFromStat(st *unix.Stat_t) fileState {
	fs := fileState{Size: st.Size, MTime: time.Unix(st.Mtim.Unix()).UnixNano(), Dev: uint64(st.Dev), Inode: uint64(st.Ino)}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		fs.Type = "file"
	case unix.S_IFLNK:
		fs.Type = "symlink"
	case unix.S_IFDIR:
		fs.Type = "dir"
	default:
		fs.Type = "other"
	}
	return fs
}

func createFile(t target, data []byte, mtime time.Time) (created, error) {
	var c created
	uid, gid, chown := t.UID, t.GID, t.HasOwner
	dfd, made, err := openChain(t.Base, t.Dirs, t.MakeDir, uid, gid, chown, t.OwnerFromParent)
	if err != nil {
		return c, err
	}
	defer unix.Close(dfd)
	c.createdDir = made
	if t.OwnerFromParent {
		var st unix.Stat_t
		if err := unix.Fstat(dfd, &st); err == nil {
			uid, gid, chown = int(st.Uid), int(st.Gid), true
		}
	}
	ffd, err := unix.Openat(dfd, t.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return c, errExists
		}
		return c, err
	}
	f := os.NewFile(uintptr(ffd), t.path())
	defer f.Close()
	fail := func(err error) (created, error) {
		_ = unix.Unlinkat(dfd, t.Name, 0)
		return c, err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	_ = unix.Fchmod(ffd, 0o600)
	if chown {
		// Best effort: the file still works as a decoy if it stays the agent's.
		if unix.Fchown(ffd, uid, gid) == nil {
			c.uid, c.gid, c.hasOwner = uid, gid, true
		}
	}
	if t.Hidden && hiddenSupported {
		// Best effort too: the next check tries again.
		c.hidden = setHiddenFd(ffd, true) == nil
	}
	tv := unix.NsecToTimeval(mtime.UnixNano())
	_ = unix.Futimes(ffd, []unix.Timeval{tv, tv})
	var st unix.Stat_t
	if err := unix.Fstat(ffd, &st); err != nil {
		return fail(err)
	}
	c.st = stateFromStat(&st)
	return c, nil
}

func statPath(p string) (fileState, error) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return fileState{}, os.ErrNotExist
		}
		return fileState{}, err
	}
	return stateFromStat(&st), nil
}

// hashPath hashes a decoy without following a link at its path and without blocking on a
// FIFO someone put there.
func hashPath(p string) (string, int64, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	return hashOpen(f)
}

// removeFile deletes a decoy if its content still hashes to want, and returns the hash
// it found. It also removes a folder the agent created for it, when that folder is empty.
func removeFile(t target, want string, createdDir bool) (bool, string, error) {
	dfd, _, err := openChain(t.Base, t.Dirs, false, 0, 0, false, false)
	if err != nil {
		return false, "", err
	}
	defer unix.Close(dfd)
	ffd, err := unix.Openat(dfd, t.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, "", err
	}
	f := os.NewFile(uintptr(ffd), t.path())
	sum, _, err := hashOpen(f)
	f.Close()
	if err != nil || sum != want {
		return false, sum, err
	}
	if err := unix.Unlinkat(dfd, t.Name, 0); err != nil {
		return false, sum, err
	}
	if createdDir && len(t.Dirs) > 0 {
		if pfd, _, err := openChain(t.Base, t.Dirs[:len(t.Dirs)-1], false, 0, 0, false, false); err == nil {
			_ = unix.Unlinkat(pfd, t.Dirs[len(t.Dirs)-1], unix.AT_REMOVEDIR) // fails if not empty
			unix.Close(pfd)
		}
	}
	return true, sum, nil
}

// setHidden sets or clears the hidden flag of a decoy (macOS), but only on the file the
// agent created: the one with the recorded device and inode, reached without following
// links. The flag does not change the size, modification time or content, so the
// checks do not see it.
func setHidden(t target, dev, ino uint64, hidden bool) error {
	if !hiddenSupported {
		return nil
	}
	dfd, _, err := openChain(t.Base, t.Dirs, false, 0, 0, false, false)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	ffd, err := unix.Openat(dfd, t.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(ffd)
	var st unix.Stat_t
	if err := unix.Fstat(ffd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Dev) != dev || uint64(st.Ino) != ino {
		return errNotOurs
	}
	return setHiddenFd(ffd, hidden)
}
