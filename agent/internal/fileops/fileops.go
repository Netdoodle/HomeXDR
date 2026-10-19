// Package fileops implements the file response actions in the agent core: quarantine
// (move a file into the data dir and remove its permissions), restore, hash and the
// file-reading half of file.get.
package fileops

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/fsutil"
	"github.com/Doodlebug12/homexdr/agent/internal/globs"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// DefaultMaxGet is the default size cap for file.get.
const DefaultMaxGet = 100 << 20

const (
	metaName = "meta.json"
	dataName = "file"
)

// Meta is what quarantine records about a file, stored next to it as meta.json.
type Meta struct {
	ID            string    `json:"id"`
	OriginalPath  string    `json:"original_path"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	Mode          string    `json:"mode"`
	UID           uint32    `json:"uid,omitempty"`
	GID           uint32    `json:"gid,omitempty"`
	HasOwner      bool      `json:"has_owner,omitempty"`
	MTime         time.Time `json:"mtime"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

// Store manages the quarantine directory.
type Store struct {
	dir       string
	protected []string // paths (files or directories) that must never be moved
}

// NewStore returns a store keeping quarantined files in dir. protected lists paths the
// agent refuses to quarantine (its data dir, config file and executable).
func NewStore(dir string, protected ...string) *Store {
	s := &Store{dir: dir}
	for _, p := range protected {
		if p != "" {
			s.protected = append(s.protected, filepath.Clean(p))
		}
	}
	return s
}

// Dir returns the quarantine directory.
func (s *Store) Dir() string { return s.dir }

func cleanAbs(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("path is required")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path must be absolute: %q", p)
	}
	return filepath.Clean(p), nil
}

// Quarantine moves path into the quarantine dir.
func (s *Store) Quarantine(path string) (api.QuarantineResult, error) {
	path, err := cleanAbs(path)
	if err != nil {
		return api.QuarantineResult{}, err
	}
	for _, p := range append([]string{s.dir}, s.protected...) {
		if globs.Under(path, p) {
			return api.QuarantineResult{}, fmt.Errorf("refusing to quarantine %s: it belongs to the agent", path)
		}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return api.QuarantineResult{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return api.QuarantineResult{}, fmt.Errorf("%s is a symbolic link; quarantine its target instead", path)
	}
	if !fi.Mode().IsRegular() {
		return api.QuarantineResult{}, fmt.Errorf("%s is not a regular file", path)
	}
	id := event.NewID()
	qdir := filepath.Join(s.dir, id)
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return api.QuarantineResult{}, err
	}
	dst := filepath.Join(qdir, dataName)
	if err := move(path, dst); err != nil {
		os.RemoveAll(qdir)
		return api.QuarantineResult{}, fmt.Errorf("move into quarantine: %w", err)
	}
	sum, err := fsutil.SHA256File(dst, 0)
	if err != nil {
		sum = ""
	}
	m := fsutil.StatMeta(fi)
	meta := Meta{
		ID: id, OriginalPath: path, SHA256: sum, Size: fi.Size(), Mode: fsutil.ModeString(fi.Mode()),
		UID: m.UID, GID: m.GID, HasOwner: m.HasOwner, MTime: fi.ModTime().UTC(), QuarantinedAt: time.Now().UTC(),
	}
	if err := fsutil.WriteJSONAtomic(filepath.Join(qdir, metaName), meta, 0o600); err != nil {
		// Put the file back rather than leave it without metadata.
		if rerr := move(dst, path); rerr == nil {
			os.RemoveAll(qdir)
		}
		return api.QuarantineResult{}, fmt.Errorf("write quarantine metadata: %w", err)
	}
	// Remove all permissions so the quarantined copy cannot be executed or read by
	// accident. (On Windows this only sets the read-only attribute.)
	_ = os.Chmod(dst, noPerm())
	return api.QuarantineResult{ID: id, OriginalPath: path, SHA256: sum, Size: fi.Size()}, nil
}

func noPerm() os.FileMode {
	if runtime.GOOS == "windows" {
		return 0o400
	}
	return 0
}

// validID accepts IDs made by event.NewID.
func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

// Restore moves a quarantined file back to its original path.
func (s *Store) Restore(id string) (api.QuarantineResult, error) {
	if !validID(id) {
		return api.QuarantineResult{}, fmt.Errorf("invalid quarantine id %q", id)
	}
	qdir := filepath.Join(s.dir, id)
	var meta Meta
	if err := fsutil.ReadJSON(filepath.Join(qdir, metaName), &meta); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return api.QuarantineResult{}, fmt.Errorf("no quarantined file with id %s", id)
		}
		return api.QuarantineResult{}, err
	}
	if _, err := os.Lstat(meta.OriginalPath); err == nil {
		return api.QuarantineResult{}, fmt.Errorf("a file already exists at %s; not overwriting it", meta.OriginalPath)
	}
	if st, err := os.Stat(filepath.Dir(meta.OriginalPath)); err != nil || !st.IsDir() {
		return api.QuarantineResult{}, fmt.Errorf("parent directory of %s no longer exists", meta.OriginalPath)
	}
	src := filepath.Join(qdir, dataName)
	if err := os.Chmod(src, 0o600); err != nil {
		return api.QuarantineResult{}, err
	}
	if err := move(src, meta.OriginalPath); err != nil {
		_ = os.Chmod(src, noPerm())
		return api.QuarantineResult{}, fmt.Errorf("restore: %w", err)
	}
	restoreAttrs(meta)
	os.RemoveAll(qdir)
	return api.QuarantineResult{ID: id, OriginalPath: meta.OriginalPath, SHA256: meta.SHA256, Size: meta.Size}, nil
}

func restoreAttrs(m Meta) {
	if mode, err := parseMode(m.Mode); err == nil {
		_ = os.Chmod(m.OriginalPath, mode)
	}
	if m.HasOwner && runtime.GOOS != "windows" {
		_ = os.Chown(m.OriginalPath, int(m.UID), int(m.GID))
		// chown clears setuid/setgid bits; apply the mode again.
		if mode, err := parseMode(m.Mode); err == nil {
			_ = os.Chmod(m.OriginalPath, mode)
		}
	}
	if !m.MTime.IsZero() {
		_ = os.Chtimes(m.OriginalPath, m.MTime, m.MTime)
	}
}

func parseMode(s string) (os.FileMode, error) {
	var v uint32
	if _, err := fmt.Sscanf(s, "%o", &v); err != nil {
		return 0, err
	}
	mode := os.FileMode(v & 0o777)
	if v&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if v&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if v&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode, nil
}

// List returns the metadata of all quarantined files.
func (s *Store) List() ([]Meta, error) {
	ents, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Meta
	for _, e := range ents {
		var m Meta
		if e.IsDir() && fsutil.ReadJSON(filepath.Join(s.dir, e.Name(), metaName), &m) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// move renames src to dst, falling back to copy+delete across file systems.
func move(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	in.Close()
	if err := os.Remove(src); err != nil {
		os.Remove(dst)
		return fmt.Errorf("cannot remove original: %w", err)
	}
	return nil
}

// Hash computes MD5, SHA-1 and SHA-256 of a regular file.
func Hash(path string) (api.FileHashResult, error) {
	path, err := cleanAbs(path)
	if err != nil {
		return api.FileHashResult{}, err
	}
	f, err := OpenRegular(path)
	if err != nil {
		return api.FileHashResult{}, err
	}
	defer f.Close()
	h, err := fsutil.HashReader(f)
	if err != nil {
		return api.FileHashResult{}, err
	}
	return api.FileHashResult{Path: path, Size: h.Size, MD5: h.MD5, SHA1: h.SHA1, SHA256: h.SHA256}, nil
}

// OpenRegular opens a file for reading and checks (on the open handle) that it is a
// regular file.
func OpenRegular(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}

// Get opens path for file.get and checks it against maxBytes (<= 0: DefaultMaxGet).
// It returns the open file and the number of bytes to send.
func Get(path string, maxBytes int64) (*os.File, int64, error) {
	path, err := cleanAbs(path)
	if err != nil {
		return nil, 0, err
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxGet
	}
	f, err := OpenRegular(path)
	if err != nil {
		return nil, 0, err
	}
	st, _ := f.Stat()
	if st.Size() > maxBytes {
		f.Close()
		return nil, 0, fmt.Errorf("%s is %d bytes, larger than max_bytes %d", path, st.Size(), maxBytes)
	}
	return f, st.Size(), nil
}
