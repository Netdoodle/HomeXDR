package pipeline

import (
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestLimitEvent(t *testing.T) {
	big := strings.Repeat(`"`, 3<<20)
	e := &event.Event{Message: big, Process: &event.Process{
		CommandLine: big, Args: []string{"a", big, "never"},
		Parent: &event.Process{CommandLine: big, Args: []string{big}},
	}}
	limitEvent(e)
	for name, s := range map[string]string{"message": e.Message, "command line": e.Process.CommandLine, "parent command line": e.Process.Parent.CommandLine} {
		if len(s) > maxFieldBytes+32 || !strings.HasSuffix(s, "[truncated]") {
			t.Errorf("%s: %d bytes", name, len(s))
		}
	}
	if len(e.Process.Args) != 2 || e.Process.Args[0] != "a" || len(e.Process.Args[1]) > maxFieldBytes+32 {
		t.Errorf("args: %d entries", len(e.Process.Args))
	}
	// A short event is untouched, and a cut never splits a character.
	s := &event.Event{Message: "ok", Process: &event.Process{CommandLine: "ls -l", Args: []string{"ls", "-l"}}}
	limitEvent(s)
	if s.Message != "ok" || s.Process.CommandLine != "ls -l" || len(s.Process.Args) != 2 {
		t.Errorf("short event changed: %+v", s.Process)
	}
	if got := cut("aé", 2); got != "a…[truncated]" {
		t.Errorf("cut = %q", got)
	}
}
