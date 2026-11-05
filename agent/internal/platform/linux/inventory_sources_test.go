//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// touch creates empty fixture files named like a Slackware package database.
func touch(t *testing.T, dir string, mode os.FileMode, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseSlackwareName(t *testing.T) {
	cases := []struct {
		file, name, version, arch, vendor string
	}{
		{"openssl-3.5.7-x86_64-1", "openssl", "3.5.7", "x86_64", "Slackware"},
		{"aaa_glibc-solibs-2.43-x86_64-1", "aaa_glibc-solibs", "2.43", "x86_64", "Slackware"},
		{"bash-completion-2.18.0-noarch-1", "bash-completion", "2.18.0", "noarch", "Slackware"},
		{"docker-29.5.3-x86_64-1_LT", "docker", "29.5.3", "x86_64", ""},
		{"nginx-1.30.3-x86_64-1_SBo_LT", "nginx", "1.30.3", "x86_64", ""},
		{"ca-certificates-20240101-noarch-1_slack15.0", "ca-certificates", "20240101", "noarch", "Slackware"},
		// A plugin package that does not follow the arch convention still parses.
		{"Coral-20240425-6.12.98-Unraid-1", "Coral-20240425", "6.12.98", "Unraid", "Slackware"},
	}
	for _, c := range cases {
		p, ok := parseSlackwareName(c.file)
		if !ok || p.Name != c.name || p.Version != c.version || p.Arch != c.arch || p.Vendor != c.vendor || p.Type != "slackware" {
			t.Errorf("%s: %+v ok=%v", c.file, p, ok)
		}
	}
	for _, bad := range []string{"", "short-name", ".hidden-1-x86_64-1", "-1-x86_64-1"} {
		if p, ok := parseSlackwareName(bad); ok {
			t.Errorf("%q parsed as %+v", bad, p)
		}
	}
}

func TestReadSlackwareFallsBackToSecondDirectory(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, 0o644, "sudo-1.9.17p2-x86_64-1", "curl-8.21.0-x86_64-1", "not-a-package")
	got, ok := readSlackware([]string{filepath.Join(dir, "missing"), dir})
	if !ok || len(got) != 2 {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := readSlackware([]string{filepath.Join(dir, "missing")}); ok {
		t.Fatal("a missing directory must report no database")
	}
}

func TestParseDockerContainers(t *testing.T) {
	got := parseDockerContainers([]byte(`[
		{"Image":"lscr.io/linuxserver/plex:1.40"},{"Image":"lscr.io/linuxserver/plex:1.40"},
		{"Image":"redis"},{"Image":"registry:5000/team/app:2.1"},
		{"Image":"sha256:0123"},{"Image":"grafana/grafana:11.0@sha256:abcd"}]`))
	want := []pkg{
		{Name: "lscr.io/linuxserver/plex", Version: "1.40", Type: "docker"},
		{Name: "redis", Version: "latest", Type: "docker"},
		{Name: "registry:5000/team/app", Version: "2.1", Type: "docker"},
		{Name: "grafana/grafana", Version: "11.0", Type: "docker"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if parseDockerContainers([]byte("not json")) != nil {
		t.Fatal("bad JSON should give nothing")
	}
}

func TestDockerImagesFromSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"Image":"nginx:1.27"}]`))
	})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()
	got := dockerImages(context.Background(), sock)
	if len(got) != 1 || got[0].Name != "nginx" || got[0].Version != "1.27" {
		t.Fatalf("%+v", got)
	}
	if dockerImages(context.Background(), sock+".none") != nil {
		t.Fatal("no socket should give nothing")
	}
}

// withNoPackageDBs points the collector at empty paths and takes rpm off PATH.
func withNoPackageDBs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	d, a, p, s, sock := dpkgStatus, apkInstalled, pacmanLocal, slackwarePackages, dockerSocket
	t.Cleanup(func() {
		dpkgStatus, apkInstalled, pacmanLocal, slackwarePackages, dockerSocket = d, a, p, s, sock
	})
	dpkgStatus = filepath.Join(dir, "dpkg")
	apkInstalled = filepath.Join(dir, "apk")
	pacmanLocal = filepath.Join(dir, "pacman")
	slackwarePackages = []string{filepath.Join(dir, "slack")}
	dockerSocket = filepath.Join(dir, "docker.sock")
	t.Setenv("PATH", dir)
	return dir
}

func TestCollectSoftwareReportsNoPackageDatabase(t *testing.T) {
	withNoPackageDBs(t)
	err := collectSoftware(context.Background(), nil, func(platform.Row) error { return nil })
	if !errors.Is(err, errNoPackageDB) {
		t.Fatalf("got %v", err)
	}
}

func TestCollectSoftwareReadsSlackware(t *testing.T) {
	dir := withNoPackageDBs(t)
	slack := filepath.Join(dir, "slack")
	if err := os.Mkdir(slack, 0o755); err != nil {
		t.Fatal(err)
	}
	touch(t, slack, 0o644, "openssl-3.5.7-x86_64-1")
	var rows []platform.Row
	err := collectSoftware(context.Background(), nil, func(r platform.Row) error {
		rows = append(rows, r)
		return nil
	})
	if err != nil || len(rows) != 1 || rows[0]["name"] != "openssl" || rows[0]["version"] != "3.5.7" || rows[0]["type"] != "slackware" || rows[0]["install_date"] == nil {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}

func TestCollectNoSystemdSlackware(t *testing.T) {
	rc, pids := t.TempDir(), t.TempDir()
	touch(t, rc, 0o755, "rc.sshd", "rc.docker", "rc.S", "rc.M", "rc.0", "rc.local", "rc.inet1.conf")
	touch(t, rc, 0o644, "rc.nfsd")
	if err := os.Mkdir(filepath.Join(rc, "rc0.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// sshd's pid file names this test's own process; docker's is dockerd.pid and stale.
	if err := os.WriteFile(filepath.Join(pids, "sshd.pid"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pids, "dockerd.pid"), []byte("999999999"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := map[string]platform.Row{}
	err := collectNoSystemd(filepath.Join(rc, "no-initd"), rc, pids, func(r platform.Row) error {
		got[r["name"].(string)] = r
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	if r := got["sshd"]; r["start_type"] != "auto" || r["state"] != "running" {
		t.Errorf("sshd: %v", r)
	}
	if r := got["docker"]; r["start_type"] != "auto" || r["state"] != "unknown" {
		t.Errorf("docker: %v", r)
	}
	if r := got["nfsd"]; r["start_type"] != "disabled" || r["state"] != "unknown" {
		t.Errorf("nfsd: %v", r)
	}
}

func TestCollectNoSystemdReportsNothingFound(t *testing.T) {
	dir := t.TempDir()
	err := collectNoSystemd(filepath.Join(dir, "a"), filepath.Join(dir, "b"), dir, func(platform.Row) error { return nil })
	if !errors.Is(err, errNoServiceManager) {
		t.Fatalf("got %v", err)
	}
}

func TestCollectNoSystemdInitd(t *testing.T) {
	initd := t.TempDir()
	touch(t, initd, 0o755, "ssh", "README")
	var names []string
	if err := collectNoSystemd(initd, filepath.Join(initd, "none"), initd, func(r platform.Row) error {
		names = append(names, r["name"].(string))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"ssh"}) {
		t.Fatalf("%v", names)
	}
}
