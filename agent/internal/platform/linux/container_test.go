//go:build linux

package linux

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	cid1 = "3f9c2b7d1e4a5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
	cid2 = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900"
)

func TestCgroupContainer(t *testing.T) {
	cases := []struct {
		name, file, id, runtime string
	}{
		{"docker cgroupfs v2", "0::/docker/" + cid1 + "\n", cid1, "docker"},
		{"docker cgroupfs v1", "12:pids:/docker/" + cid1 + "\n11:memory:/docker/" + cid1 + "\n", cid1, "docker"},
		{"docker systemd", "0::/system.slice/docker-" + cid1 + ".scope\n", cid1, "docker"},
		{"containerd cri", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-" + cid1 + ".scope\n", cid1, "containerd"},
		{"cri-o", "0::/kubepods.slice/kubepods-pod1.slice/crio-" + cid1 + ".scope\n", cid1, "cri-o"},
		{"kubernetes cgroupfs", "0::/kubepods/burstable/pod0e1d/" + cid1 + "\n", cid1, "containerd"},
		{"podman", "0::/machine.slice/libpod-" + cid1 + ".scope/container\n", cid1, "podman"},
		{"lxc payload", "0::/lxc.payload.web01/system.slice/nginx.service\n", "web01", "lxc"},
		{"lxc v1", "4:memory:/lxc/db02\n", "db02", "lxc"},
		{"nested: outermost wins", "0::/docker/" + cid1 + "/docker/" + cid2 + "\n", cid1, "docker"},
		{"host service", "0::/system.slice/sshd.service\n", "", ""},
		{"host init", "0::/init.scope\n", "", ""},
		{"host root", "0::/\n", "", ""},
		{"short hex is not an ID", "0::/docker/3f9c2b7d1e4a\n", "", ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		id, rt := cgroupContainer([]byte(c.file))
		if id != c.id || rt != c.runtime {
			t.Errorf("%s: got %q %q, want %q %q", c.name, id, rt, c.id, c.runtime)
		}
	}
}

func TestSplitImage(t *testing.T) {
	cases := map[string][2]string{
		"binhex/arch-sonarr":               {"binhex/arch-sonarr", "latest"},
		"binhex/arch-sonarr:latest":        {"binhex/arch-sonarr", "latest"},
		"registry:5000/team/app":           {"registry:5000/team/app", "latest"},
		"registry:5000/team/app:2.1":       {"registry:5000/team/app", "2.1"},
		"grafana/grafana:11.0@sha256:abcd": {"grafana/grafana", "11.0"},
	}
	for ref, want := range cases {
		if n, tag := splitImage(ref); n != want[0] || tag != want[1] {
			t.Errorf("%s: got %q %q", ref, n, tag)
		}
	}
}

// fakeHost is a /proc and Docker data root in a temp dir.
type fakeHost struct {
	t                *testing.T
	proc, data, sock string
	r                *containerResolver
}

func newFakeHost(t *testing.T) *fakeHost {
	dir := t.TempDir()
	h := &fakeHost{t: t, proc: filepath.Join(dir, "proc"), data: filepath.Join(dir, "docker"), sock: filepath.Join(dir, "docker.sock")}
	h.r = newContainerResolver(h.proc, h.data, h.sock)
	return h
}

func (h *fakeHost) process(pid int64, cgroup string) {
	d := filepath.Join(h.proc, strconv.FormatInt(pid, 10))
	if err := os.MkdirAll(d, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "cgroup"), []byte(cgroup), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) exit(pid int64) {
	_ = os.RemoveAll(filepath.Join(h.proc, strconv.FormatInt(pid, 10)))
}

func (h *fakeHost) container(id, name, image string) {
	d := filepath.Join(h.data, "containers", id)
	if err := os.MkdirAll(d, 0o755); err != nil {
		h.t.Fatal(err)
	}
	cfg := `{"ID":"` + id + `","Name":"/` + name + `","Config":{"Image":"` + image + `","Env":["A=1"]},"State":{"Running":true}}`
	if err := os.WriteFile(filepath.Join(d, "config.v2.json"), []byte(cfg), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func TestContainerFromConfigFile(t *testing.T) {
	h := newFakeHost(t)
	h.container(cid1, "binhex-sonarr", "binhex/arch-sonarr:latest")
	h.process(100, "0::/docker/"+cid1+"\n")
	h.process(200, "0::/system.slice/sshd.service\n")

	c := h.r.forProcess(&event.Process{PID: 100, EntityID: "e100"})
	if c == nil || c.ID != cid1 || c.Name != "binhex-sonarr" || c.Runtime != "docker" ||
		c.Image == nil || c.Image.Name != "binhex/arch-sonarr" || c.Image.Tag != "latest" {
		t.Fatalf("got %+v", c)
	}
	if c := h.r.forProcess(&event.Process{PID: 200, EntityID: "e200"}); c != nil {
		t.Fatalf("a host process got %+v", c)
	}
	// Callers get their own copy.
	c.Image.Name = "changed"
	if c2 := h.r.forProcess(&event.Process{PID: 100, EntityID: "e100"}); c2.Image.Name != "binhex/arch-sonarr" {
		t.Fatal("the cache was modified through a returned container")
	}
}

func TestContainerRememberedAfterExit(t *testing.T) {
	h := newFakeHost(t)
	h.container(cid1, "binhex-radarr", "binhex/arch-radarr")
	h.process(300, "0::/docker/"+cid1+"\n")
	h.r.remember("e300", 300)
	h.exit(300)
	if c := h.r.forProcess(&event.Process{PID: 300, EntityID: "e300"}); c == nil || c.Name != "binhex-radarr" {
		t.Fatalf("got %+v", c)
	}
}

func TestContainerFromParentWhenGone(t *testing.T) {
	h := newFakeHost(t)
	h.container(cid1, "binhex-sonarr", "binhex/arch-sonarr")
	h.process(10, "0::/docker/"+cid1+"\n") // bash init.sh; its sed (pid 11) has exited
	p := &event.Process{PID: 11, EntityID: "e11", Parent: &event.Process{PID: 10, EntityID: "e10"}}
	if c := h.r.forProcess(p); c == nil || c.ID != cid1 {
		t.Fatalf("got %+v", c)
	}
	// Neither readable: unknown, not "host".
	if c := h.r.forProcess(&event.Process{PID: 12, EntityID: "e12"}); c != nil {
		t.Fatalf("got %+v", c)
	}
}

func TestContainerFromSocket(t *testing.T) {
	h := newFakeHost(t)
	l, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	var calls atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch {
		case r.URL.Path == "/info":
			_, _ = w.Write([]byte(`{"DockerRootDir":"/nowhere"}`))
		case strings.HasSuffix(r.URL.Path, "/"+cid2+"/json"):
			_, _ = w.Write([]byte(`{"Id":"` + cid2 + `","Name":"/frigate","Config":{"Image":"ghcr.io/blakeblackshear/frigate:stable"}}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	h.process(400, "0::/system.slice/docker-"+cid2+".scope\n")
	c := h.r.forProcess(&event.Process{PID: 400, EntityID: "e400"})
	if c == nil || c.Name != "frigate" || c.Image == nil || c.Image.Name != "ghcr.io/blakeblackshear/frigate" || c.Image.Tag != "stable" {
		t.Fatalf("got %+v", c)
	}
	n := calls.Load()
	h.process(401, "0::/system.slice/docker-"+cid2+".scope\n")
	h.r.forProcess(&event.Process{PID: 401, EntityID: "e401"})
	if calls.Load() != n {
		t.Fatal("a known container was looked up again")
	}
}

func TestContainerUnknownIsRetriedLater(t *testing.T) {
	h := newFakeHost(t)
	now := time.Unix(1000, 0)
	h.r.now = func() time.Time { return now }
	h.process(500, "0::/docker/"+cid1+"\n")
	c := h.r.forProcess(&event.Process{PID: 500, EntityID: "e500"})
	if c == nil || c.ID != cid1 || c.Name != "" || c.Image != nil {
		t.Fatalf("with no runtime answer, want the ID alone: %+v", c)
	}
	h.container(cid1, "late", "busybox")
	if c := h.r.forProcess(&event.Process{PID: 500, EntityID: "e500"}); c.Name != "" {
		t.Fatal("asked again before the retry interval")
	}
	now = now.Add(containerRetry + time.Second)
	if c := h.r.forProcess(&event.Process{PID: 500, EntityID: "e500"}); c.Name != "late" {
		t.Fatalf("not asked again after the retry interval: %+v", c)
	}
}
