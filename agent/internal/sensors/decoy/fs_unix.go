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
// cannot redirect the agent. With mkLast the last folder is created (0700, owned by
// uid/gid when chown is set) if it is missing. It returns the last folder's descriptor.
func openChain(base string, dirs []string, mkLast bool, uid, gid int, chown bool) (fd int, made bool, err error) {
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
					if chown {
						_ = unix.Fchown(nfd, uid, gid)
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
	fd, _, err := openChain(t.Base, t.Dirs[:n], false, 0, 0, false)
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
	dfd, made, err := openChain(t.Base, t.Dirs, t.MakeDir, uid, gid, chown)
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

// removeFile deletes a decoy if its content still hashes to want. It also removes a
// folder the agent created for it, when that folder is empty.
func removeFile(t target, want string, createdDir bool) (bool, error) {
	dfd, _, err := openChain(t.Base, t.Dirs, false, 0, 0, false)
	if err != nil {
		return false, err
	}
	defer unix.Close(dfd)
	ffd, err := unix.Openat(dfd, t.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(ffd), t.path())
	sum, _, err := hashOpen(f)
	f.Close()
	if err != nil || sum != want {
		return false, err
	}
	if err := unix.Unlinkat(dfd, t.Name, 0); err != nil {
		return false, err
	}
	if createdDir && len(t.Dirs) > 0 {
		if pfd, _, err := openChain(t.Base, t.Dirs[:len(t.Dirs)-1], false, 0, 0, false); err == nil {
			_ = unix.Unlinkat(pfd, t.Dirs[len(t.Dirs)-1], unix.AT_REMOVEDIR) // fails if not empty
			unix.Close(pfd)
		}
	}
	return true, nil
}
