// Package collect holds artifact collectors that work the same on every platform.
package collect

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// MaxHashBytes caps hashing in file.find.
const MaxHashBytes = 256 << 20

// IntParam reads an int parameter with a default.
func IntParam(p map[string]string, k string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(p[k])); err == nil {
		return v
	}
	return def
}

// BoolParam reads a bool parameter with a default.
func BoolParam(p map[string]string, k string, def bool) bool {
	if v, err := strconv.ParseBool(strings.TrimSpace(p[k])); err == nil {
		return v
	}
	return def
}

var errEnough = errors.New("enough results")

// FileFind implements the file.find artifact: walk root up to max_depth, match file
// names against glob, optionally hash. It never follows symlinks.
func FileFind(ctx context.Context, p map[string]string, emit func(platform.Row) error) error {
	root := strings.TrimSpace(p["root"])
	if root == "" {
		return errors.New("root is required")
	}
	if !filepath.IsAbs(root) {
		return errors.New("root must be an absolute path")
	}
	root = filepath.Clean(root)
	glob := p["glob"]
	if glob == "" {
		glob = "*"
	}
	if _, err := filepath.Match(glob, "x"); err != nil {
		return errors.New("invalid glob pattern")
	}
	maxDepth := IntParam(p, "max_depth", 5)
	maxResults := IntParam(p, "max_results", 1000)
	if maxResults <= 0 || maxResults > 100000 {
		maxResults = 100000
	}
	hash := BoolParam(p, "hash", false)
	baseDepth := strings.Count(root, string(filepath.Separator))
	fold := runtime.GOOS == "windows"
	if fold {
		glob = strings.ToLower(glob)
	}
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		depth := strings.Count(path, string(filepath.Separator)) - baseDepth
		if d.IsDir() {
			if path != root && depth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if fold {
			name = strings.ToLower(name)
		}
		if ok, _ := filepath.Match(glob, name); !ok {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		row := platform.Row{
			"path":  path,
			"size":  fi.Size(),
			"mtime": fi.ModTime().UTC().Format(time.RFC3339),
			"mode":  fsutil.ModeString(fi.Mode()),
		}
		if m := fsutil.StatMeta(fi); m.HasOwner {
			row["owner"] = fsutil.UserName(m.UID)
		}
		if hash && fi.Mode().IsRegular() {
			if h, err := fsutil.SHA256File(path, MaxHashBytes); err == nil {
				row["sha256"] = h
			}
		}
		if err := emit(row); err != nil {
			return err
		}
		n++
		if n >= maxResults {
			return errEnough
		}
		return nil
	})
	if errors.Is(err, errEnough) {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("root does not exist")
	}
	return err
}
