package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

// UpdateKeyFile is the release public key ("ed25519:<base64>") in the signatures dir.
const UpdateKeyFile = "update-key.pub"

// SignatureFile is the name of a manifest's signature in the signatures dir. Naming it
// by the manifest's hash keeps old signatures valid for old images (rollbacks).
func SignatureFile(manifest []byte) string {
	sum := sha256.Sum256(manifest)
	return "agent-release." + hex.EncodeToString(sum[:]) + ".sig"
}

// Release offers the agent binaries bundled with this server to agents that update
// themselves (docs/protocol.md, "Agent updates"). The manifest comes from the downloads
// dir (built into the image) and its signature from the signatures dir, where the host's
// update script puts it. The server never sees the release private key; it only offers a
// release whose signature verifies with the public key next to it, so agents are not
// told about updates they would reject.
type Release struct {
	downloadsDir, sigDir string
	log                  *slog.Logger

	archiveDir string          // archive.go; "" when disabled
	keep       int             // archived releases to retain
	protect    func() []string // versions never to remove

	mu       sync.Mutex
	loadedAt time.Time
	cur      releaseState
}

type releaseState struct {
	manifest []byte
	sig      []byte            // set only when it verified
	info     *api.AgentRelease // set only when signed and verified
	key      string            // public key from UpdateKeyFile
	version  string            // manifest version, even when unsigned
	problem  string            // why no update is offered
	archive  []ArchivedRelease // verified archived releases, newest first
}

// ReleaseStatus is shown on the console's settings page.
type ReleaseStatus struct {
	Version   string `json:"version,omitempty"`
	Signed    bool   `json:"signed"`
	UpdateKey string `json:"update_key,omitempty"`
	Problem   string `json:"problem,omitempty"`
}

// NewRelease returns a Release reading from the two directories.
func NewRelease(downloadsDir, sigDir string, log *slog.Logger) *Release {
	return &Release{downloadsDir: downloadsDir, sigDir: sigDir, log: log}
}

// state returns the current state, re-reading the directories at most once a minute so
// a signature written after start-up is picked up.
func (r *Release) state() releaseState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadedAt.IsZero() || time.Since(r.loadedAt) > time.Minute {
		next := r.load()
		if next.problem != r.cur.problem || next.version != r.cur.version || r.loadedAt.IsZero() {
			if next.info != nil {
				r.log.Info("offering signed agent release", "version", next.info.Version)
			} else {
				r.log.Info("not offering agent updates", "reason", next.problem)
			}
		}
		r.cur, r.loadedAt = next, time.Now()
	}
	return r.cur
}

func (r *Release) load() releaseState {
	var st releaseState
	if b, err := os.ReadFile(filepath.Join(r.sigDir, UpdateKeyFile)); err == nil {
		k := strings.TrimSpace(string(b))
		if _, err := api.ParseUpdateKey(k); err == nil {
			st.key = k
		}
	}
	m, err := os.ReadFile(filepath.Join(r.downloadsDir, api.AgentReleaseName))
	if err != nil {
		st.problem = "no release manifest bundled with this server"
		return st
	}
	st.manifest = m
	var rel api.AgentRelease
	if json.Unmarshal(m, &rel) == nil {
		st.version = rel.Version
	}
	if st.key == "" {
		st.problem = "no update key (" + UpdateKeyFile + ") in " + r.sigDir
		return st
	}
	sig, err := os.ReadFile(filepath.Join(r.sigDir, SignatureFile(m)))
	if err != nil {
		st.problem = "this release is not signed"
		return st
	}
	key, _ := api.ParseUpdateKey(st.key)
	info, err := api.VerifyRelease(key, m, sig)
	if err != nil {
		st.problem = err.Error()
		return st
	}
	st.sig, st.info = sig, info
	if r.archiveDir != "" {
		if err := r.archiveBundled(st); err != nil {
			r.log.Warn("archive agent release", "version", info.Version, "err", err)
		}
		st.archive = r.pruneArchive(r.scanArchive(key, info.Version))
	}
	return st
}

// Offer returns the signed release to offer agents, or nil.
func (r *Release) Offer() *api.AgentRelease { return r.state().info }

// Manifest returns the bundled manifest, or nil.
func (r *Release) Manifest() []byte { return r.state().manifest }

// Signature returns the manifest's verified signature, or nil.
func (r *Release) Signature() []byte { return r.state().sig }

// Status summarizes the release for the console.
func (r *Release) Status() ReleaseStatus {
	st := r.state()
	return ReleaseStatus{Version: st.version, Signed: st.info != nil, UpdateKey: st.key, Problem: st.problem}
}

// WriteManifest hashes the agent binaries in dir and writes the release manifest there.
// The image build runs it (homexdr-server release-manifest) with the same version
// metadata the binaries were built with.
func WriteManifest(dir, version, commit string, commitTime int64) (*api.AgentRelease, error) {
	names, err := filepath.Glob(filepath.Join(dir, "homexdr-agent-*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	rel := &api.AgentRelease{Version: version, Commit: commit, CommitTime: commitTime, Files: map[string]api.ReleaseFile{}}
	for _, p := range names {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		rel.Files[filepath.Base(p)] = api.ReleaseFile{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))}
	}
	if len(rel.Files) == 0 {
		return nil, fmt.Errorf("no agent binaries (homexdr-agent-*) in %s", dir)
	}
	b, err := json.MarshalIndent(rel, "", "  ")
	if err != nil {
		return nil, err
	}
	return rel, os.WriteFile(filepath.Join(dir, api.AgentReleaseName), append(b, '\n'), 0o644)
}
