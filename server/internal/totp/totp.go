// Package totp implements time-based one-time passwords (RFC 6238) as used by
// authenticator apps: HMAC-SHA1, 6 digits, 30 second steps.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a code.
	Digits = 6
	// Period is the length of a step in seconds.
	Period = 30
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a new random secret: 20 bytes, base32 without padding.
func NewSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// URI returns the otpauth:// URI that authenticator apps read from a QR code.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// codeAt computes the code for a raw key and step with the given number of digits.
func codeAt(key []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Code returns the code for a base32 secret at a time. The server only verifies codes;
// this exists for tests and tools.
func Code(secret string, at time.Time) string {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(strings.TrimSpace(secret), "=")))
	if err != nil {
		return ""
	}
	return codeAt(key, at.Unix()/Period, Digits)
}

// Verify checks a code against the current step and the ones either side of it. A step at
// or before lastStep is refused, so a code works once. It returns the step that matched.
func Verify(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(strings.TrimSpace(secret), "=")))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	code = strings.Join(strings.Fields(code), "")
	if len(code) != Digits {
		return 0, false
	}
	cur := now.Unix() / Period
	var matched int64
	// Check every candidate without early exit so timing does not reveal which matched.
	for d := int64(-1); d <= 1; d++ {
		step := cur + d
		if step <= lastStep || step <= 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(codeAt(key, step, Digits)), []byte(code)) == 1 {
			matched = step
		}
	}
	return matched, matched != 0
}
