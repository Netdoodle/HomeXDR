// Package selfupdate installs agent releases the server offers, after checking them
// against the release key pinned in the local config (docs/protocol.md, "Agent updates").
//
// Install verifies the signed release manifest, refuses anything not newer than the
// running build, downloads the binary for this OS and architecture, checks its SHA-256
// and that it starts, keeps the running binary as <exe>.prev and moves the new one into
// place. The caller then restarts into it (Exec).
//
// A marker in the data dir counts the new version's start-ups until it reaches the server
// (Confirm). If it keeps restarting without getting that far, CheckStartup puts the
// previous binary back and the failed version is skipped for a day.
package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/shared/api"
)

const (
	// MarkerFile records an installed update until the new version confirms it.
	MarkerFile = "update.json"
	// FailedFile records a version that was rolled back.
	FailedFile = "update-failed.json"

	maxBinaryBytes   = 512 << 20
	maxStartAttempts = 3
	retryFailedAfter = time.Hour      // a download or check failure
	skipRolledBack   = 24 * time.Hour // a version that would not start
)

// ErrNotNewer is returned when the offered release is not newer than the running build.
var ErrNotNewer = errors.New("offered agent release is not newer than the running build")

// Supported reports whether this platform can replace and restart its own binary.
// Windows cannot overwrite a running executable or re-exec a service in place.
func Supported() bool { return runtime.GOOS != "windows" }

// Fetcher downloads from the agent API over the pinned mTLS connection.
type Fetcher interface {
	Fetch(ctx context.Context, path string, w io.Writer, max int64) error
}

// Updater installs releases.
type Updater struct {
	Key     ed25519.PublicKey // release key from the local config
	Exe     string            // path of the running binary
	DataDir string
	Fetcher Fetcher
	Log     *slog.Logger

	GOOS, GOARCH string // default: runtime values
	// Version and CommitTime describe the running build.
	Version    string
	CommitTime int64
	// Check runs a downloaded binary to make sure it starts and reports the expected
	// version. Default: "<path> version" must print the version within 15 seconds.
	Check func(ctx context.Context, path, version string) error

	mu     sync.Mutex
	failed map[string]time.Time // version -> last failure
}

// Marker is the content of MarkerFile.
type Marker struct {
	Version         string    `json:"version"`
	PreviousVersion string    `json:"previous_version"`
	Previous        string    `json:"previous"` // path of the kept binary
	Exe             string    `json:"exe"`
	InstalledAt     time.Time `json:"installed_at"`
	Starts          int       `json:"starts"`
}

type failedRecord struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

// Install fetches, verifies and installs the offered release. It returns the release
// when a new binary is in place (restart to run it), nil when there is nothing to do,
// and an error when the release was rejected or could not be installed.
func (u *Updater) Install(ctx context.Context, offer api.AgentUpdate) (*api.AgentRelease, error) {
	if offer.Version == "" || offer.Version == u.Version {
		return nil, nil
	}
	if u.recentlyFailed(offer.Version) {
		return nil, nil
	}
	rel, err := u.install(ctx, offer)
	if err != nil { // includes ErrNotNewer: don't re-fetch the manifest every heartbeat
		u.mu.Lock()
		if u.failed == nil {
			u.failed = map[string]time.Time{}
		}
		u.failed[offer.Version] = time.Now()
		u.mu.Unlock()
	}
	return rel, err
}

func (u *Updater) recentlyFailed(version string) bool {
	u.mu.Lock()
	at, ok := u.failed[version]
	u.mu.Unlock()
	if ok && time.Since(at) < retryFailedAfter {
		return true
	}
	var rec failedRecord
	if b, err := os.ReadFile(filepath.Join(u.DataDir, FailedFile)); err == nil && json.Unmarshal(b, &rec) == nil {
		return rec.Version == version && time.Since(rec.At) < skipRolledBack
	}
	return false
}

// releasePaths returns where to fetch an offered release from: an archived release's
// directory, or the server's bundled release for offers without a path.
func releasePaths(offer api.AgentUpdate) (manifest, sig, binDir string, err error) {
	if offer.Path == "" {
		return api.PathAgentRelease, api.PathAgentReleaseSig, "/v1/download/", nil
	}
	rest, ok := strings.CutPrefix(offer.Path, api.PathReleases)
	if !ok || !strings.HasSuffix(rest, "/") || strings.Count(rest, "/") != 1 || strings.Contains(rest, "..") {
		return "", "", "", fmt.Errorf("unexpected release path %q", offer.Path)
	}
	manifest = offer.Path + api.AgentReleaseName
	return manifest, manifest + ".sig", offer.Path, nil
}

func (u *Updater) install(ctx context.Context, offer api.AgentUpdate) (*api.AgentRelease, error) {
	if len(u.Key) != ed25519.PublicKeySize {
		return nil, errors.New("no update key configured")
	}
	manifestPath, sigPath, binDir, err := releasePaths(offer)
	if err != nil {
		return nil, err
	}
	var manifest, sig bytes.Buffer
	if err := u.Fetcher.Fetch(ctx, manifestPath, &manifest, api.MaxReleaseManifestBytes); err != nil {
		return nil, fmt.Errorf("fetch release manifest: %w", err)
	}
	if err := u.Fetcher.Fetch(ctx, sigPath, &sig, 4096); err != nil {
		return nil, fmt.Errorf("fetch release signature: %w", err)
	}
	rel, err := api.VerifyRelease(u.Key, manifest.Bytes(), sig.Bytes())
	if err != nil {
		return nil, err
	}
	if offer.Path != "" && rel.Version != offer.Version {
		return nil, fmt.Errorf("offered %s but the server sent release %s", offer.Version, rel.Version)
	}
	if rel.Version == u.Version {
		return nil, nil
	}
	if u.CommitTime > 0 && rel.CommitTime <= u.CommitTime {
		return nil, fmt.Errorf("%w (%s from %s, running %s)", ErrNotNewer, rel.Version,
			time.Unix(rel.CommitTime, 0).UTC().Format(time.DateOnly), u.Version)
	}
	goos, goarch := u.GOOS, u.GOARCH
	if goos == "" {
		goos, goarch = runtime.GOOS, runtime.GOARCH
	}
	name := api.AgentBinaryName(goos, goarch)
	file, ok := rel.Files[name]
	if !ok {
		return nil, fmt.Errorf("release %s has no %s", rel.Version, name)
	}
	if file.Size <= 0 || file.Size > maxBinaryBytes {
		return nil, fmt.Errorf("release %s: implausible size %d for %s", rel.Version, file.Size, name)
	}

	// Download next to the binary so the final rename stays on one file system.
	dir := filepath.Dir(u.Exe)
	tmp, err := os.CreateTemp(dir, ".homexdr-agent-update-*")
	if err != nil {
		return nil, fmt.Errorf("cannot write next to %s: %w", u.Exe, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed
	h := sha256.New()
	err = u.Fetcher.Fetch(ctx, binDir+name, io.MultiWriter(tmp, h), file.Size)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, file.SHA256) {
		return nil, fmt.Errorf("download %s: sha256 %s does not match the signed manifest", name, got)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return nil, err
	}
	check := u.Check
	if check == nil {
		check = runVersion
	}
	if err := check(ctx, tmpPath, rel.Version); err != nil {
		return nil, fmt.Errorf("new binary failed its start check: %w", err)
	}

	// Keep the running binary as .prev (a hard link where possible), then swap.
	prev := u.Exe + ".prev"
	_ = os.Remove(prev)
	if err := os.Link(u.Exe, prev); err != nil {
		if err := copyFile(u.Exe, prev); err != nil {
			return nil, fmt.Errorf("keep previous binary: %w", err)
		}
	}
	m := Marker{Version: rel.Version, PreviousVersion: u.Version, Previous: prev, Exe: u.Exe, InstalledAt: time.Now().UTC()}
	if err := fsutil.WriteJSONAtomic(filepath.Join(u.DataDir, MarkerFile), m, 0o600); err != nil {
		return nil, fmt.Errorf("write update marker: %w", err)
	}
	if err := os.Rename(tmpPath, u.Exe); err != nil {
		_ = os.Remove(filepath.Join(u.DataDir, MarkerFile))
		return nil, fmt.Errorf("replace %s: %w", u.Exe, err)
	}
	return rel, nil
}

// runVersion runs "<path> version" and expects the version in its output.
func runVersion(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, bytes.TrimSpace(out))
	}
	if !strings.Contains(string(out), version) {
		return fmt.Errorf("reports %q, expected version %s", strings.TrimSpace(string(out)), version)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Pending returns the marker of an installed update that has not been confirmed yet.
func Pending(dataDir string) (Marker, bool) {
	var m Marker
	b, err := os.ReadFile(filepath.Join(dataDir, MarkerFile))
	if err != nil || json.Unmarshal(b, &m) != nil {
		return Marker{}, false
	}
	return m, true
}

// CheckStartup runs before the agent starts. While an update is pending it counts
// start-ups of the new version; after too many without a Confirm it moves the previous
// binary back and returns restore=true, and the caller should Exec exe again.
func CheckStartup(dataDir, exe, version string, log *slog.Logger) (restore bool, err error) {
	m, ok := Pending(dataDir)
	if !ok {
		return false, nil
	}
	markerPath := filepath.Join(dataDir, MarkerFile)
	if m.Version != version || m.Exe != exe {
		// Not the binary the marker is about (already rolled back, or replaced by hand).
		return false, os.Remove(markerPath)
	}
	m.Starts++
	if m.Starts <= maxStartAttempts {
		return false, fsutil.WriteJSONAtomic(markerPath, m, 0o600)
	}
	log.Error("updated agent keeps restarting without reaching the server; restoring the previous version",
		"version", m.Version, "previous_version", m.PreviousVersion, "starts", m.Starts-1)
	if err := os.Rename(m.Previous, exe); err != nil {
		return false, fmt.Errorf("restore %s: %w", m.Previous, err)
	}
	_ = fsutil.WriteJSONAtomic(filepath.Join(dataDir, FailedFile), failedRecord{Version: m.Version, At: time.Now().UTC()}, 0o600)
	return true, os.Remove(markerPath)
}

// Confirm marks a pending update as good once the new version has reached the server.
// It returns the confirmed marker, if there was one.
func Confirm(dataDir, version string) (Marker, bool) {
	m, ok := Pending(dataDir)
	if !ok || m.Version != version {
		return Marker{}, false
	}
	if err := os.Remove(filepath.Join(dataDir, MarkerFile)); err != nil {
		return Marker{}, false
	}
	return m, true
}
