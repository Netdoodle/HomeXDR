// Package safefile reads small files whose location an unprivileged user may control
// (a home directory, a per-user configuration folder). The agent runs as root, so a plain
// os.ReadFile there can be pointed at /dev/zero (out of memory) or a FIFO (blocks forever).
package safefile

import (
	"fmt"
	"io"
	"os"
)

// Max is the default size limit: far above any real configuration file.
const Max = 1 << 20

// Read returns the contents of a regular file of at most max bytes. Anything else (a
// device, a FIFO, a directory, a larger file) is an error; opening never blocks.
func Read(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|nonblock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	return b, nil
}
