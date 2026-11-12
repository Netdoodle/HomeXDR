//go:build darwin

package darwin

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/unix"
)

var (
	machineIDOnce sync.Once
	machineID     string
)

// platformUUID is the hardware UUID (IOPlatformUUID), which survives reinstalls.
func platformUUID() string {
	machineIDOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			machineID = parseIOPlatformUUID(out)
		}
	})
	return machineID
}

func hostInfo(context.Context) api.HostInfo {
	h, _ := os.Hostname()
	info := api.HostInfo{
		Hostname: strings.TrimSuffix(h, ".local"), Arch: runtime.GOARCH, CPUs: runtime.NumCPU(),
		OS: event.OS{Platform: event.PlatformDarwin, Family: "macos", Name: "macOS"},
	}
	if strings.Contains(info.Hostname, ".") {
		info.FQDN = info.Hostname
	}
	if v, err := unix.Sysctl("kern.osproductversion"); err == nil {
		info.OS.Version = v
	}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		info.OS.Kernel = unix.ByteSliceToString(u.Release[:])
	}
	if n, err := unix.SysctlUint64("hw.memsize"); err == nil {
		info.MemoryBytes = n
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		bt := time.Unix(tv.Sec, int64(tv.Usec)*1000).UTC()
		info.BootTime = &bt
	}
	info.MachineID = platformUUID()
	info.IPs, info.MACs = addrsAndMACs()
	info.Timezone = timezone()
	return info
}

// timezone returns the IANA zone name of the host.
func timezone() string {
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(l, "zoneinfo/"); i >= 0 {
			return l[i+len("zoneinfo/"):]
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
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		var any bool
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			any = true
			if s := ipn.IP.String(); !slices.Contains(ips, s) {
				ips = append(ips, s)
			}
		}
		// Only interfaces with an address: macOS has many idle virtual ones (awdl, llw,
		// anpi, bridge members).
		if mac := ifc.HardwareAddr.String(); any && mac != "" && mac != "00:00:00:00:00:00" && !slices.Contains(macs, mac) {
			macs = append(macs, mac)
		}
	}
	return ips, macs
}
