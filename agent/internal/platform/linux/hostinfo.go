//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/unix"
)

// osRelease holds the /etc/os-release fields we use.
type osRelease struct {
	ID, IDLike, Name, VersionID, PrettyName string
}

func parseOSRelease(b []byte) osRelease {
	kv := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		kv[k] = v
	}
	return osRelease{ID: kv["ID"], IDLike: kv["ID_LIKE"], Name: kv["NAME"], VersionID: kv["VERSION_ID"], PrettyName: kv["PRETTY_NAME"]}
}

// family maps os-release IDs to a distribution family.
func (r osRelease) family() string {
	ids := append([]string{strings.ToLower(r.ID)}, strings.Fields(strings.ToLower(r.IDLike))...)
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu", "raspbian", "linuxmint", "pop", "kali":
			return "debian"
		case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn":
			return "rhel"
		case "suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed":
			return "suse"
		case "arch", "manjaro", "endeavouros":
			return "arch"
		case "alpine":
			return "alpine"
		case "nixos":
			return "nixos"
		case "gentoo":
			return "gentoo"
		}
	}
	if r.ID != "" {
		return strings.ToLower(r.ID)
	}
	return "linux"
}

func readFirst(paths ...string) string {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}

// parseMemTotal returns MemTotal from /proc/meminfo content, in bytes.
func parseMemTotal(b []byte) uint64 {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			f := strings.Fields(v)
			if len(f) >= 1 {
				n, _ := strconv.ParseUint(f[0], 10, 64)
				return n * 1024
			}
		}
	}
	return 0
}

// timezone returns the IANA zone name of the host.
func timezone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		return strings.TrimPrefix(tz, ":")
	}
	if s := readFirst("/etc/timezone"); s != "" {
		return s
	}
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(l, "zoneinfo/"); i >= 0 {
			return l[i+len("zoneinfo/"):]
		}
	}
	return ""
}

// inContainer detects common container runtimes.
func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if b, err := os.ReadFile("/proc/1/environ"); err == nil {
		for _, kv := range bytes.Split(b, []byte{0}) {
			if bytes.HasPrefix(kv, []byte("container=")) {
				return true
			}
		}
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, k := range []string{"docker", "kubepods", "containerd", "lxc", "libpod"} {
			if strings.Contains(s, k) {
				return true
			}
		}
	}
	return false
}

// fqdn looks the host name up in /etc/hosts.
func fqdn(hostname string) string {
	if strings.Contains(hostname, ".") {
		return hostname
	}
	b, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) < 2 || !slices.Contains(f[1:], hostname) {
			continue
		}
		for _, n := range f[1:] {
			if strings.HasPrefix(n, hostname+".") {
				return n
			}
		}
	}
	return ""
}

func addrsAndMACs() (ips, macs []string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if mac := ifc.HardwareAddr.String(); mac != "" && mac != "00:00:00:00:00:00" && !slices.Contains(macs, mac) {
			macs = append(macs, mac)
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if s := ipn.IP.String(); !slices.Contains(ips, s) {
				ips = append(ips, s)
			}
		}
	}
	return ips, macs
}

func hostInfo(context.Context) api.HostInfo {
	h, _ := os.Hostname()
	info := api.HostInfo{
		Hostname: h, FQDN: fqdn(h), Arch: runtime.GOARCH, CPUs: runtime.NumCPU(),
		OS: event.OS{Platform: event.PlatformLinux},
	}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		info.OS.Kernel = unix.ByteSliceToString(u.Release[:])
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		r := parseOSRelease(b)
		info.OS.Family = r.family()
		info.OS.Name = r.Name
		info.OS.Version = r.VersionID
	} else if b, err := os.ReadFile("/usr/lib/os-release"); err == nil {
		r := parseOSRelease(b)
		info.OS.Family, info.OS.Name, info.OS.Version = r.family(), r.Name, r.VersionID
	}
	info.MachineID = readFirst("/etc/machine-id", "/var/lib/dbus/machine-id")
	info.IPs, info.MACs = addrsAndMACs()
	if bt := BootTime(); !bt.IsZero() {
		info.BootTime = &bt
	}
	info.Timezone = timezone()
	if b, err := os.ReadFile(filepath.Join(procRoot, "meminfo")); err == nil {
		info.MemoryBytes = parseMemTotal(b)
	}
	info.Container = inContainer()
	return info
}
