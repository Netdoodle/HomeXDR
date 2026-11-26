package commands

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

// What CmdAgentLogs puts in its zip, and how much.
const (
	// MaxLogBundleBytes caps the uncompressed size of everything in the zip.
	MaxLogBundleBytes = 50 << 20
	maxJournalBytes   = 25 << 20
	journalLines      = 20000
	journalUnit       = "homexdr-agent.service"
	syslogTag         = "homexdr-agent"
	statusFileName    = "status.json" // core.StatusFile
	maxStatusBytes    = 1 << 20
	maxSyslogScan     = 32 << 20
)

// logPlan says where the agent's log is on this platform. Only the agent's own log
// files, status.json and journal/syslog lines of the agent are ever read: never the
// config file, keys or certificates.
type logPlan struct {
	Files   []string // log files, newest first
	Globs   []string // rotated files that may exist (newest first within a glob is by name)
	Journal bool     // journalctl -u homexdr-agent.service
	Syslog  []string // plain syslog files, filtered to the agent's lines
}

// planLogs returns the log locations for goos:
//   - windows: <data dir>\logs\agent.log and the rotated agent.log.1 (the service has no stderr)
//   - darwin: /Library/Logs/HomeXDR/agent.log (launchd StandardOutPath) and the files
//     newsyslog rotated it into
//   - linux: the journal when systemd runs the agent, otherwise (Unraid/Slackware: the
//     plugin's supervisor logs with `logger -t homexdr-agent`) the agent's lines of the
//     syslog file
func planLogs(goos, dataDir string, systemd bool) logPlan {
	switch goos {
	case "windows":
		dir := filepath.Join(dataDir, "logs")
		return logPlan{Files: []string{filepath.Join(dir, "agent.log"), filepath.Join(dir, "agent.log.1")}}
	case "darwin":
		const dir = "/Library/Logs/HomeXDR"
		return logPlan{Files: []string{dir + "/agent.log"}, Globs: []string{dir + "/agent.log.*"}}
	}
	if systemd {
		return logPlan{Journal: true}
	}
	return logPlan{Syslog: []string{"/var/log/syslog", "/var/log/messages"}}
}

func systemdRunning() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

// runJournal writes the journal of the agent's unit to w (replaceable in tests).
var runJournal = func(ctx context.Context, w io.Writer) error {
	jc, err := exec.LookPath("journalctl")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, jc, "-u", journalUnit, "-n", fmt.Sprint(journalLines), "--no-pager")
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = w, &stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("journalctl: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// capWriter passes at most n bytes to w and discards the rest, without failing (a
// failing writer would leave journalctl blocked on a full pipe).
type capWriter struct {
	w         io.Writer
	n         int64
	truncated bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.n {
		c.truncated = true
		p2 := p[:c.n]
		c.n = 0
		if len(p2) > 0 {
			if _, err := c.w.Write(p2); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}
	c.n -= int64(len(p))
	return c.w.Write(p)
}

type bundler struct {
	zw     *zip.Writer
	budget int64
	notes  []string
}

func (b *bundler) note(format string, a ...any) { b.notes = append(b.notes, fmt.Sprintf(format, a...)) }

func (b *bundler) create(name string, mod time.Time) (io.Writer, error) {
	if mod.IsZero() {
		mod = time.Now()
	}
	return b.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mod})
}

// addFile adds the tail of a regular file (all of it when it fits the budget and limit).
func (b *bundler) addFile(name, path string, limit int64) {
	if b.budget <= 0 {
		b.note("%s: skipped, the %d MB limit was reached", path, MaxLogBundleBytes>>20)
		return
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			b.note("%s: %v", path, err)
		}
		return
	}
	if !fi.Mode().IsRegular() {
		b.note("%s: not a regular file, skipped", path)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		b.note("%s: %v", path, err)
		return
	}
	defer f.Close()
	limit = min(limit, b.budget)
	size := fi.Size()
	var r io.Reader = f
	if size > limit {
		// Keep the end of the file, starting at a line boundary.
		if _, err := f.Seek(size-limit, io.SeekStart); err != nil {
			b.note("%s: %v", path, err)
			return
		}
		br := bufio.NewReader(f)
		skipped, _ := br.ReadBytes('\n')
		b.note("%s: %d bytes, only the last %d bytes are included", path, size, limit-int64(len(skipped)))
		r = br
	}
	w, err := b.create(name, fi.ModTime())
	if err != nil {
		b.note("%s: %v", path, err)
		return
	}
	n, err := io.Copy(w, io.LimitReader(r, limit))
	b.budget -= n
	if err != nil {
		b.note("%s: read error after %d bytes: %v", path, n, err)
	}
}

// addJournal adds the journal of the agent's unit.
func (b *bundler) addJournal(ctx context.Context) bool {
	w, err := b.create("journal.txt", time.Time{})
	if err != nil {
		b.note("journal: %v", err)
		return false
	}
	cw := &capWriter{w: w, n: min(maxJournalBytes, max(b.budget, 0))}
	if err := runJournal(ctx, cw); err != nil {
		b.note("journal: %v", err)
		return false
	}
	b.budget -= min(maxJournalBytes, max(b.budget, 0)) - cw.n
	if cw.truncated {
		b.note("journal: cut off at its size limit; the oldest lines are included")
	}
	return true
}

// addSyslog adds the agent's lines (tag syslogTag) from the tail of a syslog file.
func (b *bundler) addSyslog(name, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		b.note("%s: %v", path, err)
		return false
	}
	defer f.Close()
	if fi.Size() > maxSyslogScan {
		if _, err := f.Seek(fi.Size()-maxSyslogScan, io.SeekStart); err != nil {
			b.note("%s: %v", path, err)
			return false
		}
		b.note("%s: only the last %d MB were searched", path, maxSyslogScan>>20)
	}
	var lines [][]byte
	var total int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l := sc.Bytes(); bytes.Contains(l, []byte(syslogTag)) {
			lines = append(lines, append([]byte(nil), l...))
			total += int64(len(l)) + 1
			// Keep the newest lines within the budget.
			for total > b.budget && len(lines) > 1 {
				total -= int64(len(lines[0])) + 1
				lines = lines[1:]
			}
		}
	}
	w, err := b.create(name, fi.ModTime())
	if err != nil {
		b.note("%s: %v", path, err)
		return false
	}
	for _, l := range lines {
		_, _ = w.Write(append(l, '\n'))
	}
	b.budget -= total
	return true
}

// buildLogBundle writes the zip of the agent's logs for plan to dst.
func buildLogBundle(ctx context.Context, dst io.Writer, plan logPlan, dataDir string) error {
	b := &bundler{zw: zip.NewWriter(dst), budget: MaxLogBundleBytes}
	included := 0
	if dataDir != "" {
		before := b.budget
		b.addFile(statusFileName, filepath.Join(dataDir, statusFileName), maxStatusBytes)
		if b.budget < before {
			included++
		}
	}
	if plan.Journal {
		if b.addJournal(ctx) {
			included++
		}
	}
	files := slicesClone(plan.Files)
	for _, g := range plan.Globs {
		m, _ := filepath.Glob(g)
		sort.Strings(m)
		for _, p := range m {
			if !containsStr(files, p) {
				files = append(files, p)
			}
		}
	}
	for _, p := range files {
		before := b.budget
		b.addFile(filepath.Base(p), p, MaxLogBundleBytes)
		if b.budget < before {
			included++
		}
	}
	for _, p := range plan.Syslog {
		if b.addSyslog("syslog-"+filepath.Base(p)+".txt", p) {
			included++
			break // the first syslog file that exists is the system log
		}
	}
	b.note("collected %s on %s/%s", time.Now().UTC().Format(time.RFC3339), runtime.GOOS, runtime.GOARCH)
	if included == 0 {
		b.note("no agent log was found")
	}
	if w, err := b.create("NOTES.txt", time.Time{}); err == nil {
		_, _ = io.WriteString(w, strings.Join(b.notes, "\n")+"\n")
	}
	return b.zw.Close()
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// agentLogs zips the agent's logs and uploads the zip like fileGet uploads a file, so
// the server and console treat it as a fetched file.
func (h *Handler) agentLogs(ctx context.Context, id string) (api.FileHashResult, error) {
	dir := h.DataDir
	tmp, err := os.CreateTemp(dir, ".agent-logs-*.zip") // the data dir is private
	if err != nil {
		return api.FileHashResult{}, fmt.Errorf("create bundle: %w", err)
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	plan := planLogs(runtime.GOOS, dir, runtime.GOOS == "linux" && systemdRunning())
	if err := buildLogBundle(ctx, tmp, plan, dir); err != nil {
		return api.FileHashResult{}, fmt.Errorf("build bundle: %w", err)
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return api.FileHashResult{}, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return api.FileHashResult{}, err
	}
	name := "homexdr-agent-logs-" + time.Now().UTC().Format("20060102T150405Z") + ".zip"
	hm, h1, h256 := md5.New(), sha1.New(), sha256.New()
	body := io.TeeReader(io.LimitReader(tmp, size), io.MultiWriter(hm, h1, h256))
	if err := h.API.Upload(ctx, id, name, body, size); err != nil {
		return api.FileHashResult{}, fmt.Errorf("upload: %w", err)
	}
	hexsum := func(x hash.Hash) string { return hex.EncodeToString(x.Sum(nil)) }
	return api.FileHashResult{Path: name, Size: size, MD5: hexsum(hm), SHA1: hexsum(h1), SHA256: hexsum(h256)}, nil
}
