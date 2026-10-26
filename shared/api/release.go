package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Agent updates (docs/protocol.md, "Agent updates").
//
// The server image bundles agent binaries and a release manifest that lists their
// SHA-256 hashes. The manifest is signed outside the server, with a release key the
// server never holds, and agents that opted in through their local config install only
// releases signed with the key pinned there. A compromised server can therefore offer
// an update but cannot make agents run a binary the release key did not sign.
const (
	// AgentReleaseName is the manifest's file name in the downloads directory.
	AgentReleaseName = "agent-release.json"
	// PathAgentRelease serves the manifest and PathAgentReleaseSig its signature
	// (base64 of the 64-byte Ed25519 signature over the manifest's exact bytes). Both
	// are served without a client certificate, like the binaries.
	PathAgentRelease    = "/v1/download/" + AgentReleaseName
	PathAgentReleaseSig = "/v1/download/" + AgentReleaseName + ".sig"

	// MaxReleaseManifestBytes bounds what an agent reads for the manifest.
	MaxReleaseManifestBytes = 1 << 20
)

// AgentRelease is the release manifest.
type AgentRelease struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	CommitTime int64  `json:"commit_time"` // Unix seconds; agents never install an older build
	// Files maps a download name (AgentBinaryName) to its hash and size.
	Files map[string]ReleaseFile `json:"files"`
}

// ReleaseFile is one binary in a release.
type ReleaseFile struct {
	SHA256 string `json:"sha256"` // lowercase hex
	Size   int64  `json:"size"`
}

// AgentUpdate is set in HeartbeatResponse when the server offers a signed agent release
// whose version differs from the agent's. It is only a hint: the agent fetches the
// manifest and verifies it itself.
type AgentUpdate struct {
	Version    string `json:"version"`
	CommitTime int64  `json:"commit_time"`
	// Path is the directory the release's manifest, signature and binaries are served
	// from (PathReleases + version + "/"). Empty means the bundled release at
	// PathAgentRelease and /v1/download/ (servers before release archives).
	Path string `json:"path,omitempty"`
}

// PathReleases serves archived releases: <PathReleases><version>/agent-release.json,
// agent-release.json.sig and the binaries, without a client certificate.
const PathReleases = "/v1/releases/"

// AgentBinaryName returns the download name of the agent for an OS and architecture,
// e.g. homexdr-agent-linux-amd64 or homexdr-agent-windows-amd64.exe.
func AgentBinaryName(goos, goarch string) string {
	name := "homexdr-agent-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

const updateKeyPrefix = "ed25519:"

// ParseUpdateKey parses a release public key written as "ed25519:<base64>".
func ParseUpdateKey(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), updateKeyPrefix)
	if !ok {
		return nil, errors.New("update key must look like ed25519:<base64>")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("update key must be a base64 Ed25519 public key (32 bytes)")
	}
	return ed25519.PublicKey(b), nil
}

// FormatUpdateKey writes a public key as "ed25519:<base64>".
func FormatUpdateKey(pub ed25519.PublicKey) string {
	return updateKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// SignRelease returns the signature file contents for a manifest (used by tests and
// tools; the deployment signs with openssl, which produces the same signature).
func SignRelease(priv ed25519.PrivateKey, manifest []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)) + "\n")
}

// VerifyRelease checks a signature file against the manifest's exact bytes and then
// decodes the manifest.
func VerifyRelease(key ed25519.PublicKey, manifest, sig []byte) (*AgentRelease, error) {
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("release signature is not a base64 Ed25519 signature")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, manifest, raw) {
		return nil, errors.New("release signature does not verify with the update key")
	}
	var rel AgentRelease
	if err := json.Unmarshal(manifest, &rel); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if rel.Version == "" || len(rel.Files) == 0 {
		return nil, errors.New("release manifest has no version or no files")
	}
	return &rel, nil
}
