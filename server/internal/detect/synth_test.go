package detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// ruleDoc wraps a detection block in a rule. Values here are placeholders that test the
// generator's logic; they do not describe any attack.
func ruleDoc(logsource, detection string) string {
	return fmt.Sprintf("title: T\nid: 11111111-2222-3333-4444-555555555555\nlogsource:\n%s\ndetection:\n%s\nlevel: low\n", logsource, detection)
}

func TestSynthesizeFires(t *testing.T) {
	proc := "  product: linux\n  category: process_creation"
	cases := map[string]string{
		"exact":         "  selection:\n    Image: /usr/bin/sampletool\n  condition: selection",
		"contains":      "  selection:\n    CommandLine|contains: sample-arg\n  condition: selection",
		"startswith":    "  selection:\n    Image|startswith: /opt/sample\n  condition: selection",
		"endswith":      "  selection:\n    Image|endswith: /sample\n  condition: selection",
		"wildcards":     "  selection:\n    Image: '/opt/*/sam?le'\n  condition: selection",
		"only star":     "  selection:\n    Image: '*'\n  condition: selection",
		"escaped star":  "  selection:\n    CommandLine|contains: 'a\\*b'\n  condition: selection",
		"list":          "  selection:\n    Image|endswith:\n      - /one\n      - /two\n  condition: selection",
		"all":           "  selection:\n    CommandLine|contains|all:\n      - first\n      - second\n  condition: selection",
		"regex":         "  selection:\n    CommandLine|re: '^sam(ple|pel)[0-9]+\\.x{2,3}$'\n  condition: selection",
		"regex neg":     "  selection:\n    CommandLine|re: '^[^a]+z?$'\n  condition: selection",
		"cased":         "  selection:\n    Image|cased: /Sample\n  condition: selection",
		"cidr":          "  selection:\n    DestinationIp|cidr: 192.0.2.0/24\n  condition: selection",
		"gt":            "  selection:\n    DestinationPort|gt: 1024\n  condition: selection",
		"lt":            "  selection:\n    DestinationPort|lte: 80\n  condition: selection",
		"exists":        "  selection:\n    User|exists: true\n  condition: selection",
		"not exists":    "  selection:\n    Image: /x\n    User|exists: false\n  condition: selection",
		"null":          "  selection:\n    Image: /x\n    User: null\n  condition: selection",
		"null or value": "  selection:\n    User:\n      - null\n      - sample\n  condition: selection",
		"base64":        "  selection:\n    CommandLine|base64: sample\n  condition: selection",
		"base64offset":  "  selection:\n    CommandLine|base64offset|contains: sample\n  condition: selection",
		"utf16":         "  selection:\n    CommandLine|wide|base64offset|contains: sample\n  condition: selection",
		"windash":       "  selection:\n    CommandLine|windash|contains: -flag\n  condition: selection",
		"fieldref":      "  selection:\n    Image|fieldref: ParentImage\n  condition: selection",
		"fieldref all":  "  selection:\n    Image|fieldref|all:\n      - ParentImage\n      - CurrentDirectory\n  condition: selection",
		"keywords":      "  keywords:\n    - sampleword\n    - otherword\n  condition: keywords",
		"list of maps":  "  selection:\n    - Image: /a\n    - CommandLine: b\n  condition: selection",
		"and":           "  a:\n    Image: /a\n  b:\n    CommandLine: b\n  condition: a and b",
		"or":            "  a:\n    Image: /a\n  b:\n    CommandLine: b\n  condition: a or b",
		"not filter":    "  selection:\n    Image|endswith: /sample\n  filter:\n    User: root\n  condition: selection and not filter",
		"same field":    "  selection:\n    CommandLine|contains: sample\n  filter:\n    CommandLine|contains: sample-safe\n  condition: selection and not filter",
		"filter first":  "  selection:\n    Image|endswith:\n      - /one\n      - /two\n  filter:\n    Image: /opt/one\n  condition: selection and not filter",
		"not null":      "  selection:\n    Image: /a\n  filter:\n    User: null\n  condition: selection and not filter",
		"not and":       "  selection:\n    Image: /a\n  f1:\n    User: root\n  f2:\n    CommandLine: x\n  condition: selection and not (f1 and f2)",
		"not or":        "  selection:\n    Image: /a\n  f1:\n    User: root\n  f2:\n    CommandLine: x\n  condition: selection and not (f1 or f2)",
		"double not":    "  a:\n    Image: /a\n  condition: not not a",
		"1 of":          "  sel_a:\n    Image: /a\n  sel_b:\n    Image: /b\n  condition: 1 of sel_*",
		"all of":        "  sel_a:\n    Image: /a\n  sel_b:\n    CommandLine: b\n  condition: all of sel_*",
		"all of them":   "  sel_a:\n    Image: /a\n  sel_b:\n    CommandLine: b\n  condition: all of them",
		"two values":    "  a:\n    CommandLine|contains: first\n  b:\n    CommandLine|contains: second\n  condition: a and b",
		"multi cond":    "  a:\n    Image: /a\n  b:\n    Image: /b\n  condition:\n    - a\n    - b",
		"event id":      "  selection:\n    EventID: 4688\n  condition: selection",
		"dotted":        "  selection:\n    process.name: sample\n  condition: selection",
	}
	for name, det := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustRule(t, ruleDoc(proc, det))
			ev, err := Synthesize(r)
			if err != nil {
				t.Fatal(err)
			}
			e := NewEngine()
			e.SetRules([]*Rule{r})
			if hits := e.Evaluate(ev); len(hits) != 1 {
				t.Fatalf("the engine did not fire: %+v", ev)
			}
		})
	}
}

func TestSynthesizeEveryLogsource(t *testing.T) {
	det := "  selection:\n    SampleField: sample\n  condition: selection"
	for cat := range categoryFilters {
		t.Run(cat, func(t *testing.T) {
			r := mustRule(t, ruleDoc("  category: "+cat, det))
			if _, err := Synthesize(r); err != nil {
				t.Fatal(err)
			}
		})
	}
	sources := []string{
		"  product: windows", "  product: linux", "  product: macos", "  product: opnsense",
		"  category: some_custom_category", "  service: security", "  service: sysmon", "  service: powershell",
		"  service: taskscheduler", "  service: auth", "  product: windows\n  service: system",
		"  product: windows\n  category: process_creation", "  product: linux\n  service: sshd",
	}
	for _, ls := range sources {
		t.Run(ls, func(t *testing.T) {
			if _, err := Synthesize(mustRule(t, ruleDoc(ls, det))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSynthesizeLogsourceFieldsThatAreRealFields(t *testing.T) {
	r := mustRule(t, ruleDoc("  category: dns_query", "  selection:\n    QueryName|endswith: .example.invalid\n  condition: selection"))
	ev, err := Synthesize(r)
	if err != nil {
		t.Fatal(err)
	}
	if ev.DNS == nil || !strings.HasSuffix(ev.DNS.Question.Name, ".example.invalid") {
		t.Fatalf("%+v", ev.DNS)
	}
	r = mustRule(t, ruleDoc("  category: file_rename", "  selection:\n    SourceFilename|endswith: /old\n  condition: selection"))
	if _, err := Synthesize(r); err != nil {
		t.Fatal(err)
	}
}

func TestSynthesizeReportsRulesThatCannotFire(t *testing.T) {
	cases := map[string]string{
		"contradiction": "  a:\n    Image: /a\n  condition: a and not a",
		"both":          "  a:\n    Image: /a\n  b:\n    Image: null\n  condition: a and b",
		"empty value":   "  a:\n    Image: ''\n  condition: a",
	}
	for name, det := range cases {
		t.Run(name, func(t *testing.T) {
			if ev, err := Synthesize(mustRule(t, ruleDoc("  product: linux", det))); err == nil {
				t.Fatalf("expected a failure, got %+v", ev)
			}
		})
	}
}

func TestRegexSample(t *testing.T) {
	for _, c := range []struct{ expr, want string }{
		{`abc`, "abc"},
		{`a+b*c?`, "a"},
		{`(x|y)z`, "xz"},
		{`[0-9]{3}`, "000"},
		{`^\w+$`, "x"},
	} {
		if got := regexSample(c.expr); got != c.want {
			t.Errorf("%s: got %q want %q", c.expr, got, c.want)
		}
	}
}

func coverageEvent(platform string, category string, typ string, data map[string]any) *event.Event {
	return &event.Event{
		ID: event.NewID(), Host: event.Host{OS: &event.OS{Platform: platform}},
		Event:   event.Meta{Category: []string{category}, Type: []string{typ}},
		Process: &event.Process{Executable: "/usr/bin/sample", CommandLine: "sample"},
		Data:    data,
	}
}

func TestCoverage(t *testing.T) {
	cov := NewCoverage()
	cov.Add(coverageEvent(event.PlatformLinux, event.CategoryProcess, event.TypeStart, map[string]any{"shared": "x"}))
	cov.Add(coverageEvent(event.PlatformLinux, event.CategoryProcess, event.TypeStart, map[string]any{"second": "y"}))
	if cov.Size() != 2 {
		t.Fatal(cov.Size())
	}
	linux := "  product: linux\n  category: process_creation"
	cases := []struct {
		name, ls, det string
		seen, fire    bool
		missing       string
	}{
		{"fields present", linux, "  s:\n    Image: /nothing-like-the-sample\n    CommandLine|contains: other\n  condition: s", true, true, ""},
		{"fields in different events", linux, "  s:\n    shared: a\n    second: b\n  condition: s", true, true, ""},
		{"field missing", linux, "  s:\n    Image: /a\n    IntegrityLevel: High\n  condition: s", true, false, "IntegrityLevel"},
		{"windows only", "  product: windows\n  category: process_creation", "  s:\n    Image: /a\n  condition: s", false, false, ""},
		{"no such category", "  product: linux\n  category: image_load", "  s:\n    ImageLoaded: /a\n  condition: s", false, false, ""},
		{"either way", linux, "  a:\n    Image: /a\n  b:\n    IntegrityLevel: High\n  condition: a or b", true, true, ""},
		{"filter field ignored", linux, "  s:\n    Image: /a\n  f:\n    IntegrityLevel: High\n  condition: s and not f", true, true, ""},
		{"keywords", linux, "  k:\n    - word\n  condition: k", true, true, ""},
		{"closest way reported", linux, "  a:\n    MissingOne: x\n    MissingTwo: y\n  b:\n    MissingThree: z\n  condition: a or b", true, false, "MissingThree"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cov.Check(mustRule(t, ruleDoc(c.ls, c.det)))
			if got.SourceSeen != c.seen || got.CanFire != c.fire {
				t.Fatalf("%+v", got)
			}
			if c.missing != "" && (len(got.Missing) != 1 || got.Missing[0] != c.missing) {
				t.Fatalf("missing: %v", got.Missing)
			}
		})
	}
}
