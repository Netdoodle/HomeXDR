//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/collect"
	"github.com/Doodlebug12/homexdr/agent/internal/fsutil"
	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/communityid"
)

// collectors returns every Linux artifact in api.Artifacts.
func collectors(env platform.Env) map[string]platform.Collector {
	hc := newLRU[fileKey, string](4096)
	return map[string]platform.Collector{
		"system.info": collectSystemInfo,
		"process.list": func(ctx context.Context, p map[string]string, emit func(platform.Row) error) error {
			return collectProcesses(ctx, env, hc, p, emit)
		},
		"network.connections": collectConnections,
		"users.list":          collectUsers,
		"users.sessions":      collectSessions,
		"persistence.autoruns": func(ctx context.Context, p map[string]string, emit func(platform.Row) error) error {
			return collectAutoruns(ctx, hc, emit)
		},
		"services.list":  collectServices,
		"software.list":  collectSoftware,
		"file.find":      collect.FileFind,
		"kernel.modules": collectKernelModules,
	}
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// domainName derives the DNS domain from the FQDN or resolv.conf.
func domainName(fq string) string {
	if _, d, ok := strings.Cut(fq, "."); ok {
		return d
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 && (f[0] == "domain" || f[0] == "search") {
				return f[1]
			}
		}
	}
	return ""
}

func collectSystemInfo(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	h := hostInfo(ctx)
	row := platform.Row{
		"hostname": h.Hostname, "os_name": h.OS.Name, "os_version": h.OS.Version, "kernel": h.OS.Kernel,
		"arch": h.Arch, "cpus": h.CPUs, "memory_bytes": h.MemoryBytes, "domain": domainName(h.FQDN),
		"family": h.OS.Family, "machine_id": h.MachineID, "timezone": h.Timezone, "container": h.Container,
		"ips": h.IPs,
	}
	if h.BootTime != nil {
		row["boot_time"] = rfc3339(*h.BootTime)
	}
	return emit(row)
}

// hashExe hashes a process's executable through /proc/<pid>/exe with a cache.
func hashExe(hc *lru[fileKey, string], pid int64) string {
	link := procPath(pid, "exe")
	fi, err := os.Stat(link)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxHashBytes {
		return ""
	}
	key, ok := keyOf(fi)
	if ok {
		if h, hit := hc.get(key); hit {
			return h
		}
	}
	h, err := fsutil.SHA256File(link, maxHashBytes)
	if err != nil {
		return ""
	}
	if ok {
		hc.put(key, h)
	}
	return h
}

func collectProcesses(ctx context.Context, env platform.Env, hc *lru[fileKey, string], p map[string]string, emit func(platform.Row) error) error {
	hash := collect.BoolParam(p, "hash", true)
	pids, err := listPIDs()
	if err != nil {
		return err
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	for _, pid := range pids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st, err := readStat(pid)
		if err != nil {
			continue
		}
		row := platform.Row{
			"pid": pid, "ppid": st.PPID, "entity_id": env.EntityID(pid, st.StartTick), "name": st.Comm,
			"start": rfc3339(startTimeFromTicks(st.StartTick)),
		}
		if exe := readLink(pid, "exe"); exe != "" {
			row["executable"] = exe
			if hash {
				if h := hashExe(hc, pid); h != "" {
					row["sha256"] = h
				}
			}
		}
		if args := readCmdline(pid); len(args) > 0 {
			row["command_line"] = joinArgs(args)
		}
		if s, err := readStatus(pid); err == nil {
			row["user"] = users.name(s.UID)
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

func collectConnections(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	entries := readSockets("tcp", "tcp6", "udp", "udp6")
	owners := socketOwners(nil)
	names := map[int64]string{}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		state := tcpStates[e.State]
		if e.Transport == "udp" {
			state = "UNCONNECTED"
			if e.State == stateEstablished {
				state = "CONNECTED"
			}
		}
		row := platform.Row{
			"transport": e.Transport, "state": state,
			"local_ip": e.Local.Addr().String(), "local_port": e.Local.Port(),
			"remote_ip": e.Remote.Addr().String(), "remote_port": e.Remote.Port(),
		}
		if pid, ok := owners[e.Inode]; ok {
			row["pid"] = pid
			n, ok := names[pid]
			if !ok {
				if exe := readLink(pid, "exe"); exe != "" {
					n = filepath.Base(exe)
				} else if st, err := readStat(pid); err == nil {
					n = st.Comm
				}
				names[pid] = n
			}
			row["process_name"] = n
		}
		if e.Remote.Port() != 0 && !e.Remote.Addr().IsUnspecified() {
			proto := communityid.ProtoTCP
			if e.Transport == "udp" {
				proto = communityid.ProtoUDP
			}
			row["community_id"] = communityid.Compute(e.Local.Addr(), e.Remote.Addr(), proto, e.Local.Port(), e.Remote.Port())
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

// lastlogTimes reads /var/log/lastlog: fixed 292-byte records indexed by UID
// (int32 time, char line[32], char host[256] on glibc, including 64-bit).
func lastlogTimes(uids []uint32) map[uint32]time.Time {
	out := map[uint32]time.Time{}
	f, err := os.Open("/var/log/lastlog")
	if err != nil {
		return out
	}
	defer f.Close()
	const rec = 292
	buf := make([]byte, 4)
	for _, uid := range uids {
		if _, err := f.ReadAt(buf, int64(uid)*rec); err != nil {
			continue
		}
		if t := int32(binary.LittleEndian.Uint32(buf)); t > 0 {
			out[uid] = time.Unix(int64(t), 0).UTC()
		}
	}
	return out
}

func collectUsers(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	pb, err := os.ReadFile(passwdFile)
	if err != nil {
		return err
	}
	pw := parsePasswd(pb)
	var groups []groupEntry
	if gb, err := os.ReadFile(groupFile); err == nil {
		groups = parseGroup(gb)
	}
	locked := map[string]bool{}
	if sb, err := os.ReadFile(shadowFile); err == nil {
		locked = shadowLocked(sb)
	}
	gidName := map[uint32]string{}
	for _, g := range groups {
		gidName[g.GID] = g.Name
	}
	var uids []uint32
	for _, u := range pw {
		uids = append(uids, u.UID)
	}
	last := lastlogTimes(uids)
	adminGroups := []string{"sudo", "wheel", "admin", "root"}
	for _, u := range pw {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var gs []string
		if n, ok := gidName[u.GID]; ok {
			gs = append(gs, n)
		}
		for _, g := range groups {
			if slices.Contains(g.Members, u.Name) && !slices.Contains(gs, g.Name) {
				gs = append(gs, g.Name)
			}
		}
		admin := u.UID == 0
		for _, g := range gs {
			if slices.Contains(adminGroups, g) {
				admin = true
			}
		}
		noLogin := strings.HasSuffix(u.Shell, "/nologin") || strings.HasSuffix(u.Shell, "/false")
		row := platform.Row{
			"name": u.Name, "id": strconv.FormatUint(uint64(u.UID), 10), "groups": gs, "shell": u.Shell,
			"home": u.Home, "admin": admin, "disabled": locked[u.Name] || noLogin, "gid": u.GID, "gecos": u.Gecos,
		}
		if t, ok := last[u.UID]; ok {
			row["last_logon"] = rfc3339(t)
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

// utmp record layout (glibc, x86-64 and arm64; times are 32-bit for compatibility).
const (
	utmpSize        = 384
	utmpUserProcess = 7
)

type utmpEntry struct {
	Type    int16
	PID     int32
	Line    string
	User    string
	Host    string
	Session int32
	Time    time.Time
	Addr    netip.Addr
}

func parseUtmp(b []byte) []utmpEntry {
	le := binary.LittleEndian
	var out []utmpEntry
	for len(b) >= utmpSize {
		r := b[:utmpSize]
		b = b[utmpSize:]
		e := utmpEntry{
			Type: int16(le.Uint16(r[0:])), PID: int32(le.Uint32(r[4:])),
			Line: cstr(r[8:40]), User: cstr(r[44:76]), Host: cstr(r[76:332]),
			Session: int32(le.Uint32(r[336:])),
			Time:    time.Unix(int64(int32(le.Uint32(r[340:]))), int64(int32(le.Uint32(r[344:])))*1000).UTC(),
		}
		addr := r[348:364]
		if bytes.Equal(addr[4:], make([]byte, 12)) {
			if !bytes.Equal(addr[:4], make([]byte, 4)) {
				e.Addr = netip.AddrFrom4([4]byte(addr[:4]))
			}
		} else {
			e.Addr = netip.AddrFrom16([16]byte(addr))
		}
		out = append(out, e)
	}
	return out
}

func collectSessions(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	var b []byte
	for _, f := range []string{"/run/utmp", "/var/run/utmp"} {
		if d, err := os.ReadFile(f); err == nil {
			b = d
			break
		}
	}
	n := 0
	for _, e := range parseUtmp(b) {
		if e.Type != utmpUserProcess || e.User == "" {
			continue
		}
		// Skip records whose process is gone (stale utmp entries).
		if e.PID > 0 {
			if _, err := os.Stat(procPath(int64(e.PID), "stat")); err != nil {
				continue
			}
		}
		typ := "tty"
		if strings.HasPrefix(e.Line, "pts/") {
			typ = "pty"
			if e.Host != "" && !strings.HasPrefix(e.Host, ":") {
				typ = "remote"
			}
		}
		row := platform.Row{"user": e.User, "session": e.Line, "type": typ, "started": rfc3339(e.Time), "pid": e.PID}
		if e.Addr.IsValid() {
			row["source_ip"] = e.Addr.String()
		} else if e.Host != "" {
			row["source_ip"] = e.Host
		}
		if err := emit(row); err != nil {
			return err
		}
		n++
	}
	if n > 0 {
		return nil
	}
	// No utmp (newer distributions may drop it): ask systemd-logind.
	lc, err := exec.LookPath("loginctl")
	if err != nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, lc, "list-sessions", "--no-legend", "--no-pager").Output()
	if err != nil {
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		row := platform.Row{"session": f[0], "user": f[2], "type": "logind"}
		if len(f) >= 5 {
			row["tty"] = f[len(f)-1]
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

// modulePaths maps module names to files from modules.dep. Names use '_' as the kernel
// does in /proc/modules.
func modulePaths(release string) map[string]string {
	out := map[string]string{}
	base := filepath.Join("/lib/modules", release)
	b, err := os.ReadFile(filepath.Join(base, "modules.dep"))
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		p, _, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name := filepath.Base(p)
		if i := strings.Index(name, ".ko"); i >= 0 {
			name = name[:i]
		}
		out[strings.ReplaceAll(name, "-", "_")] = filepath.Join(base, p)
	}
	return out
}

func collectKernelModules(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	b, err := os.ReadFile(filepath.Join(procRoot, "modules"))
	if err != nil {
		return err
	}
	paths := modulePaths(hostInfo(ctx).OS.Kernel)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		size, _ := strconv.ParseInt(f[1], 10, 64)
		row := platform.Row{"name": f[0], "size": size, "state": strings.ToLower(f[4]), "path": paths[f[0]]}
		if t, err := os.ReadFile(filepath.Join("/sys/module", f[0], "taint")); err == nil {
			taint := strings.TrimSpace(string(t))
			// 'E' marks a module loaded without a valid signature; 'O' an out-of-tree one.
			row["signed"] = !strings.Contains(taint, "E")
			row["taint"] = taint
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}
