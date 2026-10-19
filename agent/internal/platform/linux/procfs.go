//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procRoot is /proc (overridable in tests).
var procRoot = "/proc"

// userHZ is the clock-tick rate of /proc/<pid>/stat times. It is the kernel ABI
// constant USER_HZ, which is 100 on every architecture Go supports on Linux (sysconf
// _SC_CLK_TCK returns it), independent of the kernel's internal CONFIG_HZ.
const userHZ = 100

// nsPerTick converts task->start_boottime (ns) to /proc clock ticks: the kernel's
// nsec_to_clock_t() is a plain division by NSEC_PER_SEC / USER_HZ.
const nsPerTick = uint64(time.Second) / userHZ

// StartKeyFromNS converts a task start_boottime in nanoseconds (as read by eBPF) to the
// start key used for entity IDs, i.e. /proc/<pid>/stat field 22.
func StartKeyFromNS(ns uint64) uint64 { return ns / nsPerTick }

// procStat is the part of /proc/<pid>/stat we use.
type procStat struct {
	PID       int64
	Comm      string
	State     byte
	PPID      int64
	StartTick uint64 // field 22: start time in clock ticks since boot
}

// parseStat parses /proc/<pid>/stat. The comm field is in parentheses and may contain
// spaces and parentheses itself, so fields are counted from the last ')'.
func parseStat(b []byte) (procStat, error) {
	var st procStat
	open := bytes.IndexByte(b, '(')
	close := bytes.LastIndexByte(b, ')')
	if open < 0 || close < open {
		return st, errors.New("malformed stat")
	}
	pid, err := strconv.ParseInt(string(bytes.TrimSpace(b[:open])), 10, 64)
	if err != nil {
		return st, fmt.Errorf("stat pid: %w", err)
	}
	st.PID = pid
	st.Comm = string(b[open+1 : close])
	rest := strings.Fields(string(b[close+1:]))
	// rest[0] is field 3 (state), so field N is rest[N-3].
	if len(rest) < 20 {
		return st, errors.New("short stat")
	}
	if len(rest[0]) > 0 {
		st.State = rest[0][0]
	}
	if st.PPID, err = strconv.ParseInt(rest[1], 10, 64); err != nil {
		return st, fmt.Errorf("stat ppid: %w", err)
	}
	if st.StartTick, err = strconv.ParseUint(rest[19], 10, 64); err != nil {
		return st, fmt.Errorf("stat starttime: %w", err)
	}
	return st, nil
}

func procPath(pid int64, name string) string {
	return filepath.Join(procRoot, strconv.FormatInt(pid, 10), name)
}

func readStat(pid int64) (procStat, error) {
	b, err := os.ReadFile(procPath(pid, "stat"))
	if err != nil {
		return procStat{}, err
	}
	return parseStat(b)
}

// startKey returns /proc/<pid>/stat field 22.
func startKey(pid int64) (uint64, error) {
	st, err := readStat(pid)
	if err != nil {
		return 0, err
	}
	return st.StartTick, nil
}

// readCmdline returns argv from /proc/<pid>/cmdline.
func readCmdline(pid int64) []string {
	b, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil || len(b) == 0 {
		return nil
	}
	return splitNul(b)
}

func splitNul(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}

// joinArgs renders argv as a command line, quoting arguments that need it.
func joinArgs(args []string) string {
	var sb strings.Builder
	for i, a := range args {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$`") {
			sb.WriteString(strconv.Quote(a))
		} else {
			sb.WriteString(a)
		}
	}
	return sb.String()
}

func readLink(pid int64, name string) string {
	s, err := os.Readlink(procPath(pid, name))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(s, " (deleted)")
}

// procStatus holds UIDs from /proc/<pid>/status.
type procStatus struct {
	UID, EUID uint32
	GID, EGID uint32
	TGID      int64
	Name      string
}

func parseStatus(b []byte) procStatus {
	var st procStatus
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		switch k {
		case "Name":
			st.Name = strings.TrimSpace(v)
		case "Tgid":
			if len(f) > 0 {
				st.TGID, _ = strconv.ParseInt(f[0], 10, 64)
			}
		case "Uid":
			if len(f) >= 2 {
				st.UID = parseU32(f[0])
				st.EUID = parseU32(f[1])
			}
		case "Gid":
			if len(f) >= 2 {
				st.GID = parseU32(f[0])
				st.EGID = parseU32(f[1])
			}
		}
	}
	return st
}

func parseU32(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}

func readStatus(pid int64) (procStatus, error) {
	b, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return procStatus{}, err
	}
	return parseStatus(b), nil
}

// listPIDs returns the numeric entries of /proc.
func listPIDs() ([]int64, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(ents))
	for _, e := range ents {
		if pid, err := strconv.ParseInt(e.Name(), 10, 64); err == nil {
			out = append(out, pid)
		}
	}
	return out, nil
}

var (
	bootOnce sync.Once
	bootTime time.Time
)

// parseBootTime reads "btime" from /proc/stat content.
func parseBootTime(b []byte) (time.Time, bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			if s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(s, 0).UTC(), true
			}
		}
	}
	return time.Time{}, false
}

// BootTime returns the system boot time.
func BootTime() time.Time {
	bootOnce.Do(func() {
		if b, err := os.ReadFile(filepath.Join(procRoot, "stat")); err == nil {
			bootTime, _ = parseBootTime(b)
		}
	})
	return bootTime
}

// startTimeFromTicks converts a start key to wall-clock time. btime is whole seconds, so
// the result is accurate to about a second.
func startTimeFromTicks(ticks uint64) time.Time {
	bt := BootTime()
	if bt.IsZero() {
		return time.Time{}
	}
	return bt.Add(time.Duration(ticks) * (time.Second / userHZ)).UTC()
}
