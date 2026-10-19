package globs

import (
	"runtime"
	"testing"
)

func TestMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix paths")
	}
	s := New("*.swp", "/proc", "/var/lib/homexdr", "/home/*/.cache", "/srv/**/tmp", "  ")
	cases := map[string]bool{
		"/etc/.passwd.swp":           true,
		"/etc/passwd":                false,
		"/proc":                      true,
		"/proc/1/status":             true,
		"/processes":                 false,
		"/var/lib/homexdr/spool/1":   true,
		"/var/lib/homexdr2/x":        false,
		"/home/bob/.cache/x/y":       true,
		"/home/bob/.config":          false,
		"/srv/tmp/a":                 true,
		"/srv/a/b/c/tmp/file":        true,
		"/srv/a/b/c/notmp/file":      false,
		"/home/bob/notes.swp.backup": false,
	}
	for p, want := range cases {
		if got := s.Match(p); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
	var empty *Set
	if empty.Match("/x") || !empty.Empty() {
		t.Error("nil set must match nothing")
	}
}

func TestUnder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix paths")
	}
	if !Under("/etc/ssh/sshd_config", "/etc") || !Under("/etc", "/etc") || Under("/etcetera", "/etc") || !Under("/x", "/") {
		t.Error("Under")
	}
}
