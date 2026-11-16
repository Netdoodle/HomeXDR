//go:build windows

package decoy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// checkChain checks that base is a folder and that each of the first n of t.Dirs is a
// real folder, not a symbolic link or junction (which a user can create in their own
// profile). With mkLast the last folder is created when missing; it inherits the
// parent's permissions. It returns the deepest folder.
func checkChain(t target, n int, mkLast bool) (string, bool, error) {
	fi, err := os.Stat(t.Base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, errNoFolder
		}
		return "", false, err
	}
	if !fi.IsDir() {
		return "", false, errUnsafe
	}
	dir, made := t.Base, false
	for i := range n {
		dir = filepath.Join(dir, t.Dirs[i])
		fi, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) && mkLast && i == len(t.Dirs)-1 {
			if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return "", false, err
			} else if err == nil {
				made = true
			}
			fi, err = os.Lstat(dir)
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", false, errNoFolder
			}
			return "", false, err
		}
		if !isRealDir(fi) {
			return "", false, errUnsafe
		}
	}
	return dir, made, nil
}

func folderOK(t target, n int) error {
	_, _, err := checkChain(t, n, false)
	return err
}

func createFile(t target, data []byte, mtime time.Time) (created, error) {
	var c created
	dir, made, err := checkChain(t, len(t.Dirs), t.MakeDir)
	if err != nil {
		return c, err
	}
	c.createdDir = made
	p := filepath.Join(dir, t.Name)
	// CREATE_NEW: never replaces a file, and fails on a link at the path.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return c, errExists
		}
		return c, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(p)
		return c, err
	}
	ft := windows.NsecToFiletime(mtime.UnixNano())
	_ = windows.SetFileTime(windows.Handle(f.Fd()), nil, &ft, &ft)
	if err := f.Close(); err != nil {
		os.Remove(p)
		return c, err
	}
	c.st, err = statPath(p)
	return c, err
}

// openNoFollow opens a file without following a reparse point at its path.
func openNoFollow(p string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func statPath(p string) (fileState, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fileState{}, os.ErrNotExist
		}
		return fileState{}, err
	}
	st := fileState{Type: typeOf(fi.Mode()), Size: fi.Size(), MTime: fi.ModTime().UnixNano()}
	if fi.Mode()&os.ModeIrregular != 0 {
		st.Type = "other"
	}
	if st.Type == "file" {
		// Reading attributes is not reading the file.
		if h, err := openNoFollow(p, windows.FILE_READ_ATTRIBUTES); err == nil {
			var info windows.ByHandleFileInformation
			if windows.GetFileInformationByHandle(h, &info) == nil {
				st.Dev = uint64(info.VolumeSerialNumber)
				st.Inode = uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
			}
			windows.CloseHandle(h)
		}
	}
	return st, nil
}

func hashPath(p string) (string, int64, error) {
	h, err := openNoFollow(p, windows.GENERIC_READ)
	if err != nil {
		return "", 0, err
	}
	f := os.NewFile(uintptr(h), p)
	defer f.Close()
	return hashOpen(f)
}

func removeFile(t target, want string, createdDir bool) (bool, error) {
	dir, _, err := checkChain(t, len(t.Dirs), false)
	if err != nil {
		return false, err
	}
	p := filepath.Join(dir, t.Name)
	sum, _, err := hashPath(p)
	if err != nil || sum != want {
		return false, err
	}
	if err := os.Remove(p); err != nil {
		return false, err
	}
	if createdDir {
		_ = os.Remove(dir) // fails if not empty
	}
	return true, nil
}
