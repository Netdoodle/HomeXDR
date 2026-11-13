// Package authenticode computes the Authenticode hashes of Windows PE files (EXE, DLL,
// SYS): the hash of the file without its checksum field, its certificate table entry and
// the certificate table itself. Windows App Control (WDAC) identifies files by these
// hashes in its hash rules, so the same file hashes the same whether or not it is signed.
package authenticode

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
)

// ErrNotPE means the file is not a PE image.
var ErrNotPE = errors.New("not a PE file")

// Hashes are a PE file's Authenticode digests, lower-case hex.
type Hashes struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// File hashes the PE file at path.
func File(path string) (Hashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return Hashes{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Hashes{}, err
	}
	return Compute(f, fi.Size())
}

// Compute hashes a PE image of the given size.
func Compute(r io.ReaderAt, size int64) (Hashes, error) {
	skip, err := excluded(r, size)
	if err != nil {
		return Hashes{}, err
	}
	h1, h256 := sha1.New(), sha256.New()
	w := io.MultiWriter(h1, h256)
	pos := int64(0)
	for _, s := range skip {
		if s.off > pos {
			if err := copyRange(w, r, pos, s.off-pos); err != nil {
				return Hashes{}, err
			}
		}
		if end := s.off + s.n; end > pos {
			pos = end
		}
	}
	if size > pos {
		if err := copyRange(w, r, pos, size-pos); err != nil {
			return Hashes{}, err
		}
	}
	return Hashes{SHA1: sum(h1), SHA256: sum(h256)}, nil
}

func sum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

func copyRange(w io.Writer, r io.ReaderAt, off, n int64) error {
	_, err := io.Copy(w, io.NewSectionReader(r, off, n))
	return err
}

type span struct{ off, n int64 }

// excluded returns the byte ranges Authenticode leaves out, in file order: the
// optional header's CheckSum, the certificate table directory entry and the certificate
// table.
func excluded(r io.ReaderAt, size int64) ([]span, error) {
	read := func(off int64, n int) ([]byte, error) {
		if off < 0 || off+int64(n) > size {
			return nil, ErrNotPE
		}
		b := make([]byte, n)
		if _, err := r.ReadAt(b, off); err != nil {
			return nil, err
		}
		return b, nil
	}
	dos, err := read(0, 64)
	if err != nil {
		return nil, err
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return nil, ErrNotPE
	}
	peOff := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	sig, err := read(peOff, 24)
	if err != nil {
		return nil, err
	}
	if string(sig[:4]) != "PE\x00\x00" {
		return nil, ErrNotPE
	}
	optSize := int64(binary.LittleEndian.Uint16(sig[20:]))
	opt := peOff + 24
	magic, err := read(opt, 2)
	if err != nil {
		return nil, err
	}
	var numDirsOff, dirsOff int64
	switch binary.LittleEndian.Uint16(magic) {
	case 0x10b: // PE32
		numDirsOff, dirsOff = opt+92, opt+96
	case 0x20b: // PE32+
		numDirsOff, dirsOff = opt+108, opt+112
	default:
		return nil, ErrNotPE
	}
	if dirsOff > opt+optSize {
		return nil, ErrNotPE
	}
	spans := []span{{opt + 64, 4}} // CheckSum
	nd, err := read(numDirsOff, 4)
	if err != nil {
		return nil, err
	}
	const certDir = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
	if binary.LittleEndian.Uint32(nd) <= certDir {
		return spans, nil
	}
	entryOff := dirsOff + certDir*8
	if entryOff+8 > opt+optSize {
		return spans, nil
	}
	entry, err := read(entryOff, 8)
	if err != nil {
		return nil, err
	}
	spans = append(spans, span{entryOff, 8})
	// The certificate table's "virtual address" is a file offset.
	certOff := int64(binary.LittleEndian.Uint32(entry))
	certSize := int64(binary.LittleEndian.Uint32(entry[4:]))
	if certOff > 0 && certSize > 0 && certOff >= entryOff+8 && certOff+certSize <= size {
		spans = append(spans, span{certOff, certSize})
	}
	return spans, nil
}
