package authenticode

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// minimalPE builds a PE32+ image with a certificate table of certLen bytes at its end.
func minimalPE(certLen int) []byte {
	b := make([]byte, 0x400)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x80+20:], 240) // SizeOfOptionalHeader
	opt := 0x80 + 24
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)
	binary.LittleEndian.PutUint32(b[opt+64:], 0xdeadbeef) // CheckSum
	binary.LittleEndian.PutUint32(b[opt+108:], 16)        // NumberOfRvaAndSizes
	for i := 0x200; i < 0x400; i++ {
		b[i] = byte(i)
	}
	if certLen > 0 {
		binary.LittleEndian.PutUint32(b[opt+112+4*8:], uint32(len(b)))
		binary.LittleEndian.PutUint32(b[opt+112+4*8+4:], uint32(certLen))
		b = append(b, bytes.Repeat([]byte{0xcc}, certLen)...)
	}
	return b
}

func TestCompute(t *testing.T) {
	unsigned := minimalPE(0)
	signed := minimalPE(64)
	// Signing changes the checksum and adds the certificate: the hash stays the same.
	opt := 0x80 + 24
	binary.LittleEndian.PutUint32(signed[opt+64:], 0x12345678)
	hu, err := Compute(bytes.NewReader(unsigned), int64(len(unsigned)))
	if err != nil {
		t.Fatal(err)
	}
	hs, err := Compute(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		t.Fatal(err)
	}
	if hu != hs || len(hu.SHA256) != 64 || len(hu.SHA1) != 40 {
		t.Fatalf("unsigned %+v, signed %+v", hu, hs)
	}
	// It is not the plain file hash, and the code bytes count.
	plain := sha256.Sum256(unsigned)
	if hu.SHA256 == hex.EncodeToString(plain[:]) {
		t.Fatal("Authenticode hash equals the file hash")
	}
	changed := minimalPE(0)
	changed[0x300] ^= 1
	if hc, _ := Compute(bytes.NewReader(changed), int64(len(changed))); hc == hu {
		t.Fatal("a code change kept the hash")
	}
	for _, b := range [][]byte{[]byte("#!/bin/sh\n"), {}, append([]byte("MZ"), make([]byte, 100)...)} {
		if _, err := Compute(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrNotPE) {
			t.Errorf("non-PE %q: %v", b[:min(len(b), 8)], err)
		}
	}
}
