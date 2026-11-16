package decoy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
)

var (
	errExists   = errors.New("a file already exists there")
	errNoFolder = errors.New("folder does not exist")
	errUnsafe   = errors.New("folder is a symbolic link, junction or not a folder")
)

// maxDecoySize bounds what the agent reads when hashing a decoy. Decoys are a few hundred
// bytes; anything larger has been changed.
const maxDecoySize = 1 << 20

// fileState is what a check sees at a decoy's path, without following links.
type fileState struct {
	Type  string // file, symlink, dir, other
	Size  int64
	MTime int64 // Unix nanoseconds
	Dev   uint64
	Inode uint64 // inode, or the NTFS file index on Windows
}

func typeOf(m os.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	}
	return "other"
}

// created describes a decoy just written.
type created struct {
	st         fileState
	uid, gid   int
	hasOwner   bool
	createdDir bool
}

// hashOpen hashes an open regular file of at most maxDecoySize bytes.
func hashOpen(f *os.File) (string, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, fmt.Errorf("not a regular file")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxDecoySize+1))
	if err != nil {
		return "", 0, err
	}
	if n > maxDecoySize {
		return "", n, fmt.Errorf("larger than %d bytes", maxDecoySize)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// userName resolves a numeric owner for events; it returns the number when unknown.
func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// systemOwner is the default owner lookup for profile folders: the folder's owner, if
// the user database knows it. It always fails on Windows, where files inherit the
// folder's permissions instead.
func systemOwner(_ string, fi os.FileInfo) (owner, bool) {
	m := fsutil.StatMeta(fi)
	if !m.HasOwner {
		return owner{}, false
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(m.UID), 10))
	if err != nil {
		return owner{}, false
	}
	return owner{UID: int(m.UID), GID: int(m.GID), Name: u.Username}, true
}
