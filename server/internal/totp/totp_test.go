package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA1, secret "12345678901234567890", 8 digits.
func TestRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		if got := codeAt(key, v.unix/30, 8); got != v.want {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestVerify(t *testing.T) {
	secret := NewSecret()
	if len(secret) != 32 || strings.Contains(secret, "=") {
		t.Fatalf("secret %q", secret)
	}
	key, _ := b32.DecodeString(secret)
	now := time.Unix(1700000000, 0)
	cur := now.Unix() / 30
	code := codeAt(key, cur, 6)

	step, ok := Verify(secret, code, now, 0)
	if !ok || step != cur {
		t.Fatalf("current code: %d %v", step, ok)
	}
	if _, ok := Verify(secret, code[:3]+" "+code[3:], now, 0); !ok {
		t.Error("spaces not tolerated")
	}
	if _, ok := Verify(secret, code, now, cur); ok {
		t.Error("reused step accepted")
	}
	if _, ok := Verify(secret, code, now, cur+5); ok {
		t.Error("older step accepted")
	}
	if s, ok := Verify(secret, codeAt(key, cur-1, 6), now, 0); !ok || s != cur-1 {
		t.Error("previous step refused")
	}
	if s, ok := Verify(secret, codeAt(key, cur+1, 6), now, 0); !ok || s != cur+1 {
		t.Error("next step refused")
	}
	if _, ok := Verify(secret, codeAt(key, cur+2, 6), now, 0); ok {
		t.Error("step +2 accepted")
	}
	if _, ok := Verify(secret, codeAt(key, cur-2, 6), now, 0); ok {
		t.Error("step -2 accepted")
	}
	if _, ok := Verify(secret, "abcdef", now, 0); ok {
		t.Error("garbage accepted")
	}
	if _, ok := Verify("", code, now, 0); ok {
		t.Error("empty secret accepted")
	}
}

func TestURI(t *testing.T) {
	u := URI("HomeXDR", "ann smith", "ABC")
	if !strings.HasPrefix(u, "otpauth://totp/HomeXDR:ann%20smith?") || !strings.Contains(u, "secret=ABC") || !strings.Contains(u, "issuer=HomeXDR") {
		t.Fatal(u)
	}
}
