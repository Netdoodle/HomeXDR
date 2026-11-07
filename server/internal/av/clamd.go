package av

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Clamd talks to a ClamAV daemon over its TCP protocol (zINSTREAM, zVERSION, zPING).
// Nothing is written to disk on the ClamAV side: the file is streamed in chunks.
type Clamd struct {
	Addr    string
	Timeout time.Duration // per scan; default 2 minutes
}

const clamdChunk = 64 << 10

// ErrClamdFailed means clamd answered with an error, for example a stream larger than
// its StreamMaxLength.
var ErrClamdFailed = errors.New("clamd error")

func (c *Clamd) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	t := c.Timeout
	if t <= 0 {
		t = 2 * time.Minute
	}
	deadline := time.Now().Add(t)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	return conn, nil
}

// command sends a z-prefixed command (NUL-terminated) and reads one NUL-terminated reply.
func (c *Clamd) command(ctx context.Context, cmd string) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", err
	}
	return readReply(conn)
}

func readReply(r io.Reader) (string, error) {
	s, err := bufio.NewReader(r).ReadString(0)
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimRight(s, "\x00\n"), nil
}

// Version returns clamd's version line, e.g. "ClamAV 1.4.6/27450/Fri Nov  6 08:21:00 2026"
// (engine, signature database version, database date).
func (c *Clamd) Version(ctx context.Context) (string, error) {
	return c.command(ctx, "VERSION")
}

// Ping checks that clamd answers.
func (c *Clamd) Ping(ctx context.Context) error {
	r, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if r != "PONG" {
		return fmt.Errorf("unexpected reply %q", r)
	}
	return nil
}

// Scan streams r to clamd. It returns the signature name when clamd finds something,
// and "" when the file is clean.
func (c *Clamd) Scan(ctx context.Context, r io.Reader) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}
	buf := make([]byte, clamdChunk)
	var size [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(size[:], uint32(n))
			if _, err := conn.Write(size[:]); err != nil {
				return "", c.earlyReply(conn, err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return "", c.earlyReply(conn, err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	binary.BigEndian.PutUint32(size[:], 0)
	if _, err := conn.Write(size[:]); err != nil {
		return "", err
	}
	reply, err := readReply(conn)
	if err != nil {
		return "", err
	}
	return parseScanReply(reply)
}

// earlyReply reads what clamd said when it closed the stream early (usually "INSTREAM size
// limit exceeded").
func (c *Clamd) earlyReply(conn net.Conn, werr error) error {
	if reply, err := readReply(conn); err == nil && reply != "" {
		return fmt.Errorf("%w: %s", ErrClamdFailed, reply)
	}
	return werr
}

// parseScanReply reads "stream: OK", "stream: <name> FOUND" or "... ERROR".
func parseScanReply(reply string) (string, error) {
	body := strings.TrimSpace(strings.TrimPrefix(reply, "stream:"))
	switch {
	case body == "OK":
		return "", nil
	case strings.HasSuffix(body, " FOUND"):
		return strings.TrimSpace(strings.TrimSuffix(body, " FOUND")), nil
	}
	return "", fmt.Errorf("%w: %s", ErrClamdFailed, reply)
}
