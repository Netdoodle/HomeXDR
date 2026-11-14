package darwin

import (
	"encoding/binary"
	"testing"
	"time"
)

// bplistOf builds a binary plist from raw objects; object 0 is the top.
func bplistOf(objs ...[]byte) []byte {
	b := []byte("bplist00")
	var offs []int
	for _, o := range objs {
		offs = append(offs, len(b))
		b = append(b, o...)
	}
	table := len(b)
	for _, o := range offs {
		b = append(b, byte(o>>8), byte(o))
	}
	tr := make([]byte, 32)
	tr[6], tr[7] = 2, 1
	binary.BigEndian.PutUint64(tr[8:], uint64(len(objs)))
	binary.BigEndian.PutUint64(tr[24:], uint64(table))
	return append(b, tr...)
}

func TestHostileBinaryPlists(t *testing.T) {
	huge := []byte{0x6F, 0x13, 0x80, 0, 0, 0, 0, 0, 0, 1} // a UTF-16 string of 2^63+1 characters
	// Twenty arrays, each holding the next one sixteen times: 16^20 objects from 400 bytes.
	var bomb [][]byte
	for i := 0; i < 20; i++ {
		a := []byte{0xAF, 0x10, 16}
		for j := 0; j < 16; j++ {
			a = append(a, byte(i+1))
		}
		bomb = append(bomb, a)
	}
	bomb = append(bomb, []byte{0x51, 'x'})
	for name, b := range map[string][]byte{"huge count": bplistOf(huge), "shared arrays": bplistOf(bomb...)} {
		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic: %v", name, r)
					done <- nil
				}
			}()
			_, err := decodePlist(b)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: decoded without an error", name)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the decoder did not finish", name)
		}
	}
}
