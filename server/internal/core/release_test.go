package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

func TestRelease(t *testing.T) {
	downloads, sigs := t.TempDir(), t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	write := func(dir, name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fresh := func() *Release { return NewRelease(downloads, sigs, log) }

	if fresh().Offer() != nil || fresh().Status().Problem == "" {
		t.Fatal("offered a release with no manifest")
	}
	if _, err := WriteManifest(downloads, "v2", "abc", 200); err == nil {
		t.Fatal("manifest written without binaries")
	}
	write(downloads, "homexdr-agent-linux-amd64", []byte("binary"))
	write(downloads, "SHA256SUMS", []byte("ignored"))
	rel, err := WriteManifest(downloads, "v2", "abc", 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(rel.Files) != 1 || rel.Files["homexdr-agent-linux-amd64"].Size != 6 {
		t.Fatalf("manifest files %+v", rel.Files)
	}
	manifest, _ := os.ReadFile(filepath.Join(downloads, api.AgentReleaseName))

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	write(sigs, UpdateKeyFile, []byte(api.FormatUpdateKey(pub)+"\n"))
	if st := fresh().Status(); st.Signed || st.Version != "v2" || st.UpdateKey == "" {
		t.Fatalf("unsigned release status %+v", st)
	}

	// A signature made with another key is not offered.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	write(sigs, SignatureFile(manifest), api.SignRelease(otherPriv, manifest))
	if fresh().Offer() != nil {
		t.Fatal("offered a release signed with the wrong key")
	}

	write(sigs, SignatureFile(manifest), api.SignRelease(priv, manifest))
	r := fresh()
	if got := r.Offer(); got == nil || got.Version != "v2" || got.CommitTime != 200 {
		t.Fatalf("Offer() = %+v (%s)", got, r.Status().Problem)
	}
	if _, err := api.VerifyRelease(pub, r.Manifest(), r.Signature()); err != nil {
		t.Fatalf("served manifest and signature do not verify: %v", err)
	}
}
