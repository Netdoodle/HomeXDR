package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestReleaseSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest, _ := json.Marshal(AgentRelease{
		Version: "v1.2.3", Commit: "abc", CommitTime: 100,
		Files: map[string]ReleaseFile{AgentBinaryName("linux", "amd64"): {SHA256: strings.Repeat("a", 64), Size: 3}},
	})
	sig := SignRelease(priv, manifest)

	key, err := ParseUpdateKey(FormatUpdateKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	rel, err := VerifyRelease(key, manifest, sig)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "v1.2.3" || rel.Files["homexdr-agent-linux-amd64"].Size != 3 {
		t.Fatalf("decoded %+v", rel)
	}

	tampered := append([]byte{}, manifest...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyRelease(key, tampered, sig); err == nil {
		t.Fatal("tampered manifest verified")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyRelease(other, manifest, sig); err == nil {
		t.Fatal("signature verified with the wrong key")
	}
	if _, err := VerifyRelease(key, manifest, []byte("not base64!")); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

func TestParseUpdateKey(t *testing.T) {
	for _, bad := range []string{"", "ed25519:", "ed25519:AAAA", "rsa:" + strings.Repeat("A", 44), strings.Repeat("A", 44)} {
		if _, err := ParseUpdateKey(bad); err == nil {
			t.Errorf("ParseUpdateKey(%q) accepted", bad)
		}
	}
	if AgentBinaryName("windows", "amd64") != "homexdr-agent-windows-amd64.exe" {
		t.Error("windows binary name")
	}
}
