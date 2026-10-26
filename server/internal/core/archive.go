package core

// The release archive keeps signed agent releases after the server moves on to a newer
// one, so update policies can hold agents on an older version (N-1, pinned). Each
// archived release is a directory <archive>/<version>/ with the manifest, its signature
// and the binaries the manifest lists, copied from the bundled release the first time
// the server offers it. Archived releases are re-verified with the update key whenever
// the release state is reloaded, so a tampered archive is simply not offered.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

const (
	archiveSig  = api.AgentReleaseName + ".sig"
	archiveMeta = "archived.json"
)

var versionDirRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)

// ArchivedRelease is a signed release that agents can be offered.
type ArchivedRelease struct {
	Version    string    `json:"version"`
	Commit     string    `json:"commit,omitempty"`
	CommitTime int64     `json:"commit_time"`
	ArchivedAt time.Time `json:"archived_at"` // when this server first had it
	Bundled    bool      `json:"bundled"`     // built into the running server
	Files      []string  `json:"files"`
}

// Path is the directory agents fetch the release from.
func (a ArchivedRelease) Path() string { return api.PathReleases + a.Version + "/" }

// SetArchive enables the release archive: dir holds archived releases, keep is how many
// to retain, and protect lists versions never to remove (e.g. pinned by a policy).
func (r *Release) SetArchive(dir string, keep int, protect func() []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.archiveDir, r.keep, r.protect = dir, keep, protect
	r.loadedAt = time.Time{}
}

// archiveBundled copies the verified bundled release into the archive unless present.
// Binaries are hashed while copying and must match the signed manifest.
func (r *Release) archiveBundled(st releaseState) error {
	rel := st.info
	if !versionDirRe.MatchString(rel.Version) {
		return fmt.Errorf("version %q cannot be used as a directory name", rel.Version)
	}
	dst := filepath.Join(r.archiveDir, rel.Version)
	if _, err := os.Stat(filepath.Join(dst, archiveMeta)); err == nil {
		return nil
	}
	if err := os.MkdirAll(r.archiveDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(r.archiveDir, ".incoming-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, api.AgentReleaseName), st.manifest, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, archiveSig), st.sig, 0o644); err != nil {
		return err
	}
	for name, f := range rel.Files {
		if err := copyVerified(filepath.Join(r.downloadsDir, name), filepath.Join(tmp, name), f); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	meta, _ := json.Marshal(map[string]time.Time{"archived_at": time.Now().UTC()})
	if err := os.WriteFile(filepath.Join(tmp, archiveMeta), meta, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(dst) // a partial copy from an interrupted run
	return os.Rename(tmp, dst)
}

func copyVerified(src, dst string, want api.ReleaseFile) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != want.Size || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return errors.New("does not match the signed manifest")
	}
	return nil
}

// scanArchive returns the archived releases that verify with key, newest first.
func (r *Release) scanArchive(key ed25519.PublicKey, bundled string) []ArchivedRelease {
	entries, err := os.ReadDir(r.archiveDir)
	if err != nil {
		return nil
	}
	var out []ArchivedRelease
	for _, e := range entries {
		if !e.IsDir() || !versionDirRe.MatchString(e.Name()) {
			continue
		}
		dir := filepath.Join(r.archiveDir, e.Name())
		m, err1 := os.ReadFile(filepath.Join(dir, api.AgentReleaseName))
		sig, err2 := os.ReadFile(filepath.Join(dir, archiveSig))
		if err1 != nil || err2 != nil {
			continue
		}
		info, err := api.VerifyRelease(key, m, sig)
		if err != nil || info.Version != e.Name() {
			continue
		}
		a := ArchivedRelease{Version: info.Version, Commit: info.Commit, CommitTime: info.CommitTime, Bundled: info.Version == bundled}
		complete := true
		for name, f := range info.Files {
			st, err := os.Stat(filepath.Join(dir, name))
			if err != nil || st.Size() != f.Size {
				complete = false
			}
			a.Files = append(a.Files, name)
		}
		if !complete {
			continue
		}
		sort.Strings(a.Files)
		var meta struct {
			ArchivedAt time.Time `json:"archived_at"`
		}
		if b, err := os.ReadFile(filepath.Join(dir, archiveMeta)); err == nil && json.Unmarshal(b, &meta) == nil {
			a.ArchivedAt = meta.ArchivedAt
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CommitTime > out[j].CommitTime })
	return out
}

// pruneArchive removes the oldest archived releases beyond keep, sparing the bundled
// release and protected versions. It returns the releases kept.
func (r *Release) pruneArchive(list []ArchivedRelease) []ArchivedRelease {
	if r.keep <= 0 || len(list) <= r.keep {
		return list
	}
	protected := map[string]bool{}
	if r.protect != nil {
		for _, v := range r.protect() {
			protected[v] = true
		}
	}
	var kept []ArchivedRelease
	for i, a := range list {
		if i < r.keep || a.Bundled || protected[a.Version] {
			kept = append(kept, a)
			continue
		}
		if err := os.RemoveAll(filepath.Join(r.archiveDir, a.Version)); err != nil {
			r.log.Warn("remove archived agent release", "version", a.Version, "err", err)
			kept = append(kept, a)
			continue
		}
		r.log.Info("removed archived agent release", "version", a.Version)
	}
	return kept
}

// Archive returns the releases agents can be offered, newest first.
func (r *Release) Archive() []ArchivedRelease {
	return append([]ArchivedRelease(nil), r.state().archive...)
}

// ArchiveFile returns the path of a file of an archived release, if it is one.
func (r *Release) ArchiveFile(version, name string) (string, bool) {
	for _, a := range r.state().archive {
		if a.Version != version {
			continue
		}
		ok := name == api.AgentReleaseName || name == archiveSig
		for _, f := range a.Files {
			ok = ok || f == name
		}
		if ok {
			return filepath.Join(r.archiveDir, version, name), true
		}
	}
	return "", false
}
