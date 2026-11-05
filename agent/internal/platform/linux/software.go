//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

var (
	dpkgStatus   = "/var/lib/dpkg/status"
	apkInstalled = "/lib/apk/db/installed"
	pacmanLocal  = "/var/lib/pacman/local"
	// slackwarePackages is the Slackware (and Unraid) package database: one file per
	// package, named name-version-arch-build. /var/log/packages is a link to it on
	// current systems and the real directory on older ones.
	slackwarePackages = []string{"/var/lib/pkgtools/packages", "/var/log/packages"}
	dockerSocket      = "/var/run/docker.sock"
)

// errNoPackageDB is what software.list reports on a system whose packages it cannot read,
// so the inventory sensor shows a reason instead of quietly sending nothing.
var errNoPackageDB = errors.New("no supported package database found (looked for dpkg, rpm, apk, pacman and Slackware packages)")

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

// parseSlackwareName splits a Slackware package file name, name-version-arch-build. The
// name may hold dashes; the other three never do.
func parseSlackwareName(file string) (pkg, bool) {
	parts := strings.Split(file, "-")
	if len(parts) < 4 || strings.HasPrefix(file, ".") {
		return pkg{}, false
	}
	n := len(parts)
	name, version := strings.Join(parts[:n-3], "-"), parts[n-3]
	if name == "" || version == "" {
		return pkg{}, false
	}
	build := parts[n-1]
	vendor := ""
	if strings.Contains(build, "_slack") || (build != "" && !strings.Contains(build, "_")) {
		vendor = "Slackware"
	}
	return pkg{Name: name, Version: version, Vendor: vendor, Type: "slackware", Arch: parts[n-2]}, true
}

// readSlackware lists the packages in a Slackware package directory. ok is false when
// there is no such directory.
func readSlackware(dirs []string) (out []pkg, ok bool) {
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			p, valid := parseSlackwareName(e.Name())
			if !valid {
				continue
			}
			if fi, err := e.Info(); err == nil {
				p.Installed = fi.ModTime()
			}
			out = append(out, p)
		}
		return out, true
	}
	return nil, false
}

// parseDockerContainers reads the Docker API's container list. Each image in use once.
func parseDockerContainers(b []byte) []pkg {
	var list []struct {
		Image string `json:"Image"`
	}
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []pkg
	for _, c := range list {
		img := c.Image
		if img == "" || strings.HasPrefix(img, "sha256:") || seen[img] {
			continue
		}
		seen[img] = true
		img, _, _ = strings.Cut(img, "@") // drop a digest
		name, tag := img, "latest"
		if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
			name, tag = img[:i], img[i+1:]
		}
		out = append(out, pkg{Name: name, Version: tag, Type: "docker"})
	}
	return out
}

// dockerImages asks the local Docker socket which images containers run. A host without
// Docker, or a socket that does not answer, simply has none.
func dockerImages(ctx context.Context, socket string) []pkg {
	if _, err := os.Stat(socket); err != nil {
		return nil
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=1", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil
	}
	return parseDockerContainers(b)
}

func collectSoftware(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	found := false
	if b, err := os.ReadFile(dpkgStatus); err == nil {
		found = true
		for _, p := range parseDpkgStatus(b) {
			p.Installed = dpkgInstallTime(p.Name, p.Arch)
			if err := emit(p.row()); err != nil {
				return err
			}
		}
	}
	if rpm, err := exec.LookPath("rpm"); err == nil {
		found = true
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
		found = true
		for _, p := range parseAPK(b) {
			if err := emit(p.row()); err != nil {
				return err
			}
		}
	}
	if ents, err := os.ReadDir(pacmanLocal); err == nil {
		found = true
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
	if list, ok := readSlackware(slackwarePackages); ok {
		found = true
		for _, p := range list {
			if err := emit(p.row()); err != nil {
				return err
			}
		}
	}
	for _, p := range dockerImages(ctx, dockerSocket) {
		if err := emit(p.row()); err != nil {
			return err
		}
	}
	if !found {
		return errNoPackageDB
	}
	return nil
}
