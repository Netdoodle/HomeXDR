package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDecoyDefaultsHaveNoDesktop(t *testing.T) {
	for _, f := range DefaultDecoyFiles() {
		if strings.Contains(strings.ToLower(f.Path), "desktop") {
			t.Errorf("default decoy on the Desktop: %+v", f)
		}
		if msg := DecoyPathProblem(f.OS, f.Path); msg != "" {
			t.Errorf("default %s %q: %s", f.OS, f.Path, msg)
		}
	}
}

func TestDecoyConfigOldExtraAndMissingFiles(t *testing.T) {
	var c DecoyConfig
	raw := `{"enabled":true,"check_interval_sec":90,"extra":["C:\\Shares\\pay.csv","/srv/share/keys.txt",""]}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if !c.Enabled || c.CheckIntervalSec != 90 {
		t.Fatalf("fields: %+v", c)
	}
	want := append(DefaultDecoyFiles(),
		DecoyFile{OS: DecoyOSWindows, Path: `C:\Shares\pay.csv`},
		DecoyFile{OS: DecoyOSLinux, Path: "/srv/share/keys.txt"},
		DecoyFile{OS: DecoyOSDarwin, Path: "/srv/share/keys.txt"},
	)
	if !reflect.DeepEqual(c.Files, want) {
		t.Fatalf("files:\n%+v\nwant\n%+v", c.Files, want)
	}

	// No files and no extra: the defaults. null counts as missing.
	for _, raw := range []string{`{"enabled":true}`, `{"enabled":true,"files":null}`} {
		var d DecoyConfig
		if err := json.Unmarshal([]byte(raw), &d); err != nil || !reflect.DeepEqual(d.Files, DefaultDecoyFiles()) {
			t.Errorf("%s: %+v %v", raw, d.Files, err)
		}
	}

	// An explicit empty list stays empty and is written back as [].
	var e DecoyConfig
	if err := json.Unmarshal([]byte(`{"enabled":true,"files":[]}`), &e); err != nil || e.Files == nil || len(e.Files) != 0 {
		t.Fatalf("empty list: %+v %v", e.Files, err)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"files":[]`) || strings.Contains(string(b), "extra") {
		t.Errorf("marshalled %s", b)
	}

	// The default config round-trips.
	cfg := DefaultAgentConfig()
	b, _ = json.Marshal(cfg)
	var back AgentConfig
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back.Decoys, cfg.Decoys) {
		t.Fatalf("round trip: %+v %v", back.Decoys, err)
	}
}

func TestDecoyPathProblem(t *testing.T) {
	ok := []DecoyFile{
		{DecoyOSWindows, `{home}\Documents\Passwords.xlsx`, true},
		{DecoyOSWindows, `C:\ProgramData\Backup\credentials.csv`, false},
		{DecoyOSWindows, `d:\x.txt`, false},
		{DecoyOSLinux, "{home}/.aws/credentials.bak", false},
		{DecoyOSLinux, "/x.txt", false},
		{DecoyOSDarwin, "/Users/Shared/Notes/passwords.txt", true},
	}
	for _, f := range ok {
		if msg := DecoyPathProblem(f.OS, f.Path); msg != "" {
			t.Errorf("%s %q rejected: %s", f.OS, f.Path, msg)
		}
	}
	bad := []DecoyFile{
		{OS: "freebsd", Path: "/x.txt"},
		{OS: DecoyOSLinux, Path: ""},
		{OS: DecoyOSLinux, Path: "notes.txt"},
		{OS: DecoyOSLinux, Path: "~/notes.txt"},
		{OS: DecoyOSLinux, Path: "/srv/*.txt"},
		{OS: DecoyOSLinux, Path: "/srv/dir/"},
		{OS: DecoyOSLinux, Path: "/"},
		{OS: DecoyOSLinux, Path: "{home}/"},
		{OS: DecoyOSLinux, Path: "{home}"},
		{OS: DecoyOSLinux, Path: "/srv/../etc/x"},
		{OS: DecoyOSLinux, Path: "/srv/./x"},
		{OS: DecoyOSLinux, Path: "/srv//x"},
		{OS: DecoyOSLinux, Path: `/srv\x`},
		{OS: DecoyOSLinux, Path: "/srv/{home}/x"},
		{OS: DecoyOSLinux, Path: "/srv/a\nb"},
		{OS: DecoyOSLinux, Path: "/" + strings.Repeat("a", 260)},
		{OS: DecoyOSDarwin, Path: `{home}\Documents\x.txt`},
		{OS: DecoyOSWindows, Path: "/srv/x.txt"},
		{OS: DecoyOSWindows, Path: `C:rel.txt`},
		{OS: DecoyOSWindows, Path: `C:\a/b.txt`},
		{OS: DecoyOSWindows, Path: `C:\a\b.txt:stream`},
		{OS: DecoyOSWindows, Path: `C:\a\b|c.txt`},
		{OS: DecoyOSWindows, Path: `\\server\share\x.txt`},
		{OS: DecoyOSWindows, Path: `{home}/Documents/x.txt`},
		{OS: DecoyOSWindows, Path: `{HOME}\x.txt`},
	}
	for _, f := range bad {
		if msg := DecoyPathProblem(f.OS, f.Path); msg == "" {
			t.Errorf("%s %q accepted", f.OS, f.Path)
		}
	}
	if DecoyPathProblem(DecoyOSLinux, "/"+strings.Repeat("a", 259)) != "" {
		t.Error("260 characters rejected")
	}
}

func TestValidateDecoyFiles(t *testing.T) {
	out, err := ValidateDecoyFiles([]DecoyFile{{OS: DecoyOSLinux, Path: "  /srv/a.txt "}})
	if err != nil || out[0].Path != "/srv/a.txt" {
		t.Fatalf("trim: %+v %v", out, err)
	}
	if _, err := ValidateDecoyFiles([]DecoyFile{{OS: DecoyOSLinux, Path: "/a"}, {OS: DecoyOSLinux, Path: "/a", Hidden: true}}); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := ValidateDecoyFiles([]DecoyFile{{OS: DecoyOSLinux, Path: "/a"}, {OS: DecoyOSDarwin, Path: "/a"}}); err != nil {
		t.Errorf("same path on two platforms: %v", err)
	}
	many := make([]DecoyFile, DecoyMaxFiles+1)
	for i := range many {
		many[i] = DecoyFile{OS: DecoyOSLinux, Path: "/srv/" + strings.Repeat("x", i+1)}
	}
	if _, err := ValidateDecoyFiles(many); err == nil {
		t.Error("too many accepted")
	}
	if _, err := ValidateDecoyFiles(many[:DecoyMaxFiles]); err != nil {
		t.Errorf("64 entries: %v", err)
	}
}
