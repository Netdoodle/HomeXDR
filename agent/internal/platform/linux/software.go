//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
)

var (
	dpkgStatus   = "/var/lib/dpkg/status"
	apkInstalled = "/lib/apk/db/installed"
	pacmanLocal  = "/var/lib/pacman/local"
)

type pkg struct {
	Name, Version, Vendor, Type, Arch string
	Installed                         time.Time
}

func (p pkg) row() platform.Row {
	r := platform.Row{"name": p.Name, "version": p.Version, "vendor": p.Vendor, "type": p.Type, "arch": p.Arch}
	if !p.Installed.IsZero() {
		r["install_date"] = rfc3339(p.Installed)
	}
	return r
}

// parseDpkgStatus parses /var/lib/dpkg/status, keeping installed packages.
func parseDpkgStatus(b []byte) []pkg {
	var out []pkg
	for _, para := range bytes.Split(b, []byte("\n\n")) {
		f := map[string]string{}
		sc := bufio.NewScanner(bytes.NewReader(para))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue // continuation lines (descriptions)
			}
			if k, v, ok := strings.Cut(line, ":"); ok {
				f[k] = strings.TrimSpace(v)
			}
		}
		if f["Package"] == "" || !strings.HasSuffix(f["Status"], " installed") {
			continue
		}
		vendor := f["Maintainer"]
		if i := strings.Index(vendor, " <"); i > 0 {
			vendor = vendor[:i]
		}
		out = append(out, pkg{Name: f["Package"], Version: f["Version"], Vendor: vendor, Type: "deb", Arch: f["Architecture"]})
	}
	return out
}

func dpkgInstallTime(name, arch string) time.Time {
	for _, n := range []string{name + ":" + arch, name} {
		if fi, err := os.Stat(filepath.Join("/var/lib/dpkg/info", n+".list")); err == nil {
			return fi.ModTime()
		}
	}
	return time.Time{}
}

// parseAPK parses /lib/apk/db/installed.
func parseAPK(b []byte) []pkg {
	var out []pkg
	for _, para := range bytes.Split(b, []byte("\n\n")) {
		var p pkg
		sc := bufio.NewScanner(bytes.NewReader(para))
		for sc.Scan() {
			line := sc.Text()
			if len(line) < 2 || line[1] != ':' {
				continue
			}
			v := line[2:]
			switch line[0] {
			case 'P':
				p.Name = v
			case 'V':
				p.Version = v
			case 'A':
				p.Arch = v
			case 'm':
				p.Vendor = v
			case 't':
				if s, err := strconv.ParseInt(v, 10, 64); err == nil {
					p.Installed = time.Unix(s, 0)
				}
			}
		}
		if p.Name != "" {
			p.Type = "apk"
			out = append(out, p)
		}
	}
	return out
}

// parsePacmanDesc parses one /var/lib/pacman/local/<pkg>/desc file.
func parsePacmanDesc(b []byte) pkg {
	p := pkg{Type: "pacman"}
	var key string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%"):
			key = line
		case line == "":
			key = ""
		default:
			switch key {
			case "%NAME%":
				p.Name = line
			case "%VERSION%":
				p.Version = line
			case "%ARCH%":
				p.Arch = line
			case "%PACKAGER%":
				p.Vendor = line
			case "%INSTALLDATE%":
				if s, err := strconv.ParseInt(line, 10, 64); err == nil {
					p.Installed = time.Unix(s, 0)
				}
			}
		}
	}
	return p
}

func collectSoftware(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	if b, err := os.ReadFile(dpkgStatus); err == nil {
		for _, p := range parseDpkgStatus(b) {
			p.Installed = dpkgInstallTime(p.Name, p.Arch)
			if err := emit(p.row()); err != nil {
				return err
			}
		}
	}
	if rpm, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.CommandContext(ctx, rpm, "-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{ARCH}\n`).Output()
		if err == nil && len(out) > 0 {
			sc := bufio.NewScanner(bytes.NewReader(out))
			for sc.Scan() {
				f := strings.Split(sc.Text(), "\t")
				if len(f) < 5 || f[0] == "gpg-pubkey" {
					continue
				}
				p := pkg{Name: f[0], Version: f[1], Vendor: strings.TrimPrefix(f[2], "(none)"), Type: "rpm", Arch: f[4]}
				if s, err := strconv.ParseInt(f[3], 10, 64); err == nil {
					p.Installed = time.Unix(s, 0)
				}
				if err := emit(p.row()); err != nil {
					return err
				}
			}
		}
	}
	if b, err := os.ReadFile(apkInstalled); err == nil {
		for _, p := range parseAPK(b) {
			if err := emit(p.row()); err != nil {
				return err
			}
		}
	}
	if ents, err := os.ReadDir(pacmanLocal); err == nil {
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(pacmanLocal, e.Name(), "desc"))
			if err != nil {
				continue
			}
			if p := parsePacmanDesc(b); p.Name != "" {
				if err := emit(p.row()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
