//go:build windows

package decoy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hiddenSupported: Windows has FILE_ATTRIBUTE_HIDDEN.
const hiddenSupported = true

// isReparsePoint reports whether fi (from Lstat) is a reparse point of any kind: a
// symbolic link, junction, mount point or anything else that can send a path elsewhere.
func isReparsePoint(fi os.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// checkChain checks that base is a folder and that each of the first n of t.Dirs is a
// real folder, not a symbolic link, junction or other reparse point (Base is the drive
// root, so this covers every folder on the way). With mkLast the last folder is created
// when missing, after the folders above it were checked; it inherits the parent's
// permissions. It returns the deepest folder.
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
	if t.Hidden {
		// Best effort: the next check tries again.
		c.hidden = setHiddenHandle(windows.Handle(f.Fd()), true) == nil
	}
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

// removeFile deletes a decoy if its content still hashes to want, and returns the hash
// it found. It also removes a folder the agent created for it, when that folder is empty.
func removeFile(t target, want string, createdDir bool) (bool, string, error) {
	dir, _, err := checkChain(t, len(t.Dirs), false)
	if err != nil {
		return false, "", err
	}
	p := filepath.Join(dir, t.Name)
	sum, _, err := hashPath(p)
	if err != nil || sum != want {
		return false, sum, err
	}
	if err := os.Remove(p); err != nil {
		return false, sum, err
	}
	if createdDir && len(t.Dirs) > 0 {
		// The same check again before removing the folder: nothing on the way, and not the
		// folder itself, may have become a link since.
		if _, _, err := checkChain(t, len(t.Dirs), false); err == nil {
			_ = os.Remove(dir) // fails if not empty
		}
	}
	return true, sum, nil
}

// fileBasicInfo is FILE_BASIC_INFO. Zero times leave the file's times as they are.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

// setHiddenHandle sets or clears FILE_ATTRIBUTE_HIDDEN on an open file. Attributes are
// not content: the size and last write time the checks compare stay as they are.
func setHiddenHandle(h windows.Handle, hidden bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	attrs := info.FileAttributes &^ windows.FILE_ATTRIBUTE_HIDDEN
	if hidden {
		attrs |= windows.FILE_ATTRIBUTE_HIDDEN
	}
	if attrs == info.FileAttributes {
		return nil
	}
	if attrs == 0 {
		attrs = windows.FILE_ATTRIBUTE_NORMAL // 0 would mean "leave unchanged"
	}
	bi := fileBasicInfo{FileAttributes: attrs}
	return windows.SetFileInformationByHandle(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi)))
}

// setHidden sets or clears the hidden attribute of a decoy, but only on the file the
// agent created: the one with the recorded volume and file ID, opened without following
// a link or junction at its path.
func setHidden(t target, dev, ino uint64, hidden bool) error {
	dir, _, err := checkChain(t, len(t.Dirs), false)
	if err != nil {
		return err
	}
	h, err := openNoFollow(filepath.Join(dir, t.Name), windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	id := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		uint64(info.VolumeSerialNumber) != dev || id != ino {
		return errNotOurs
	}
	return setHiddenHandle(h, hidden)
}

// isHidden reports whether the file at p has the hidden attribute (tests).
func isHidden(p string) (bool, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return false, err
	}
	a, err := windows.GetFileAttributes(name)
	return a&windows.FILE_ATTRIBUTE_HIDDEN != 0, err
}
