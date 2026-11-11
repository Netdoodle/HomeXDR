//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Container attribution: which container a process runs in, from /proc/<pid>/cgroup,
// and that container's name and image, from the runtime. Every sensor's events pass
// through countingEmitter, which adds it, so process, file, network and DNS events all
// get it.

const (
	containerLookupTimeout = 300 * time.Millisecond // a socket lookup on the event path
	containerRetry         = 30 * time.Second       // before asking again about an unknown ID
	dockerDataRoot         = "/var/lib/docker"
)

// cgroupContainer finds a container ID in a /proc/<pid>/cgroup file. It returns "" for
// a process on the host. The outermost container wins, since that is the one the host's
// runtime knows by name.
func cgroupContainer(b []byte) (id, runtime string) {
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		// hierarchy-ID:controllers:path
		parts := bytes.SplitN(line, []byte{':'}, 3)
		if len(parts) != 3 {
			continue
		}
		if id, runtime = containerInPath(string(parts[2])); id != "" {
			return id, runtime
		}
	}
	return "", ""
}

// containerInPath reads one cgroup path. Layouts:
//
//	/docker/<id>                                     Docker, cgroupfs driver
//	/system.slice/docker-<id>.scope                  Docker, systemd driver
//	/kubepods/.../cri-containerd-<id>.scope          containerd (CRI)
//	/kubepods/.../crio-<id>.scope                    CRI-O
//	/machine.slice/libpod-<id>.scope                 Podman
//	/kubepods/burstable/pod<uid>/<id>                Kubernetes, cgroupfs driver
//	/lxc.payload.<name>, /lxc/<name>                 LXC (the name is the ID)
func containerInPath(path string) (id, runtime string) {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		switch {
		case strings.HasPrefix(seg, "lxc.payload."):
			if n := strings.TrimPrefix(seg, "lxc.payload."); n != "" {
				return n, "lxc"
			}
		case seg == "lxc" && i+1 < len(segs) && segs[i+1] != "":
			return segs[i+1], "lxc"
		}
		s := strings.TrimSuffix(seg, ".scope")
		for _, p := range []struct{ prefix, runtime string }{
			{"docker-", "docker"}, {"cri-containerd-", "containerd"}, {"crio-", "cri-o"}, {"libpod-", "podman"},
		} {
			if rest, ok := strings.CutPrefix(s, p.prefix); ok && isContainerID(rest) {
				return rest, p.runtime
			}
		}
		if isContainerID(seg) {
			rt := ""
			if i > 0 {
				switch segs[i-1] {
				case "docker":
					rt = "docker"
				case "libpod_parent":
					rt = "podman"
				}
			}
			if rt == "" && strings.Contains(path, "kubepods") {
				rt = "containerd"
			}
			return seg, rt
		}
	}
	return "", ""
}

// isContainerID reports a full 64-character lowercase hex ID.
func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// splitImage splits an image reference into name and tag. A digest is dropped, and a
// registry port ("host:5000/app") is not mistaken for a tag.
func splitImage(ref string) (name, tag string) {
	ref, _, _ = strings.Cut(ref, "@")
	name, tag = ref, "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	return name, tag
}

// dockerInspect is the part of Docker's container JSON we use. config.v2.json on disk and
// GET /containers/<id>/json share it.
type dockerInspect struct {
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

func parseDockerInspect(b []byte) (name, image string, ok bool) {
	var d dockerInspect
	if json.Unmarshal(b, &d) != nil || (d.Name == "" && d.Config.Image == "") {
		return "", "", false
	}
	return strings.TrimPrefix(d.Name, "/"), d.Config.Image, true
}

type containerMeta struct {
	c        *event.Container
	complete bool // name and image known; otherwise asked again after containerRetry
	at       time.Time
}

// containerResolver maps processes to containers, with caches so /proc and the runtime
// are read once per process and once per container.
type containerResolver struct {
	procRoot string // "/proc"
	dataRoot string // Docker's data root, for config.v2.json
	socket   string
	byEntity *lru[string, string] // process entity -> container ID ("" on the host)
	meta     *lru[string, containerMeta]
	now      func() time.Time

	rootOnce sync.Once
	client   *http.Client
}

func newContainerResolver(procRoot, dataRoot, socket string) *containerResolver {
	r := &containerResolver{
		procRoot: procRoot, dataRoot: dataRoot, socket: socket,
		byEntity: newLRU[string, string](16384),
		meta:     newLRU[string, containerMeta](1024),
		now:      time.Now,
	}
	r.client = &http.Client{
		Timeout: containerLookupTimeout,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", r.socket)
		}},
	}
	return r
}

var containers = newContainerResolver("/proc", dockerDataRoot, dockerSocket)

// readID reads a process's container ID from /proc. ok is false when the process has
// gone, which is different from a process on the host ("" and true).
func (r *containerResolver) readID(pid int64) (id, runtime string, ok bool) {
	b, err := os.ReadFile(filepath.Join(r.procRoot, strconv.FormatInt(pid, 10), "cgroup"))
	if err != nil {
		return "", "", false
	}
	id, runtime = cgroupContainer(b)
	return id, runtime, true
}

// remember records the container of a process seen at exec time, so later events about
// it (a file it wrote just before exiting) find it without /proc.
func (r *containerResolver) remember(entity string, pid int64) {
	if entity == "" || pid <= 0 {
		return
	}
	if _, ok := r.byEntity.get(entity); ok {
		return
	}
	if id, rt, ok := r.readID(pid); ok {
		r.byEntity.put(entity, id)
		if id != "" {
			r.ensureMeta(id, rt)
		}
	}
}

// forProcess returns the container of an event's process, or nil on the host.
func (r *containerResolver) forProcess(p *event.Process) *event.Container {
	if p == nil || p.PID <= 0 {
		return nil
	}
	id, known := "", false
	if p.EntityID != "" {
		id, known = r.byEntity.get(p.EntityID)
	}
	rt := ""
	if !known {
		var ok bool
		id, rt, ok = r.readID(p.PID)
		if !ok && p.Parent != nil && p.Parent.PID > 0 {
			// Gone already: a process starts in its parent's container.
			if p.Parent.EntityID != "" {
				id, ok = r.byEntity.get(p.Parent.EntityID)
			}
			if !ok {
				id, rt, ok = r.readID(p.Parent.PID)
			}
		}
		if !ok {
			return nil
		}
		if p.EntityID != "" {
			r.byEntity.put(p.EntityID, id)
		}
	}
	if id == "" {
		return nil
	}
	return r.ensureMeta(id, rt).copy()
}

func (m containerMeta) copy() *event.Container {
	c := *m.c
	if m.c.Image != nil {
		img := *m.c.Image
		c.Image = &img
	}
	return &c
}

// ensureMeta returns what is known about a container, asking the runtime when it is new.
func (r *containerResolver) ensureMeta(id, runtime string) containerMeta {
	if m, ok := r.meta.get(id); ok && (m.complete || r.now().Sub(m.at) < containerRetry) {
		return m
	}
	m := containerMeta{c: &event.Container{ID: id, Runtime: runtime}, at: r.now()}
	switch runtime {
	case "lxc":
		m.c.Name, m.complete = id, true
	case "docker", "":
		if name, image, ok := r.docker(id); ok {
			m.c.Runtime = "docker"
			m.c.Name = name
			if image != "" {
				n, t := splitImage(image)
				m.c.Image = &event.ContainerImage{Name: n, Tag: t}
			}
			m.complete = true
		}
	}
	r.meta.put(id, m)
	return m
}

// docker reads a container's name and image: from its config file on disk (fast, no
// socket), else from the API with a short timeout.
func (r *containerResolver) docker(id string) (name, image string, ok bool) {
	if b, err := os.ReadFile(filepath.Join(r.root(), "containers", id, "config.v2.json")); err == nil {
		if name, image, ok = parseDockerInspect(b); ok {
			return name, image, true
		}
	}
	b := r.get("/containers/" + id + "/json")
	if b == nil {
		return "", "", false
	}
	return parseDockerInspect(b)
}

// root is Docker's data root. When the default holds no containers, Docker is asked once
// where it keeps them (data-root can be moved).
func (r *containerResolver) root() string {
	r.rootOnce.Do(func() {
		if _, err := os.Stat(filepath.Join(r.dataRoot, "containers")); err == nil {
			return
		}
		var info struct {
			DockerRootDir string `json:"DockerRootDir"`
		}
		if b := r.get("/info"); b != nil && json.Unmarshal(b, &info) == nil && info.DockerRootDir != "" {
			r.dataRoot = info.DockerRootDir
		}
	})
	return r.dataRoot
}

func (r *containerResolver) get(path string) []byte {
	if _, err := os.Stat(r.socket); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), containerLookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	return b
}
