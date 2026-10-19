package detect

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Doc is an event prepared for rule evaluation: flattened once into lowercase dotted
// paths, with Sigma field names resolved through a mapping table.
type Doc struct {
	Event *event.Event
	flat  map[string][]string
	kw    []string
}

// NewDoc flattens an event.
func NewDoc(ev *event.Event) *Doc {
	d := &Doc{Event: ev, flat: map[string][]string{}}
	b, err := json.Marshal(ev)
	if err != nil {
		return d
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if dec.Decode(&m) == nil {
		flatten("", m, d.flat)
	}
	d.synthesize()
	return d
}

func flatten(prefix string, v any, out map[string][]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			key := strings.ToLower(k)
			if prefix != "" {
				key = prefix + "." + key
			}
			flatten(key, val, out)
		}
	case []any:
		for _, item := range t {
			flatten(prefix, item, out)
		}
	case string:
		out[prefix] = append(out[prefix], t)
	case json.Number:
		out[prefix] = append(out[prefix], t.String())
	case bool:
		if t {
			out[prefix] = append(out[prefix], "true")
		} else {
			out[prefix] = append(out[prefix], "false")
		}
	case nil:
	}
}

func (d *Doc) has(cat string) bool {
	for _, c := range d.Event.Event.Category {
		if c == cat {
			return true
		}
	}
	return false
}

// synthesize adds Sysmon-style composite fields.
func (d *Doc) synthesize() {
	hashPrefix := "process.hash"
	sigPrefix := "process.code_signature"
	switch {
	case d.has(event.CategoryLibrary):
		hashPrefix, sigPrefix = "dll.hash", "dll.code_signature"
	case d.has(event.CategoryFile) && !d.has(event.CategoryProcess):
		hashPrefix, sigPrefix = "file.hash", "file.code_signature"
	case d.has(event.CategoryDriver):
		hashPrefix, sigPrefix = "file.hash", "file.code_signature"
	}
	var parts []string
	for _, h := range []string{"md5", "sha1", "sha256"} {
		if v := d.flat[hashPrefix+"."+h]; len(v) > 0 && v[0] != "" {
			parts = append(parts, strings.ToUpper(h)+"="+strings.ToUpper(v[0]))
			d.flat["sigma."+h] = v
		}
	}
	if v := d.flat[strings.TrimSuffix(hashPrefix, ".hash")+".pe.imphash"]; len(v) > 0 && v[0] != "" {
		parts = append(parts, "IMPHASH="+strings.ToUpper(v[0]))
		d.flat["sigma.imphash"] = v
	}
	if len(parts) > 0 {
		d.flat["sigma.hashes"] = []string{strings.Join(parts, ",")}
	}
	if ex := d.flat[sigPrefix+".exists"]; len(ex) > 0 {
		signed := ex[0] == "true"
		if v := d.flat[sigPrefix+".valid"]; len(v) > 0 && v[0] == "false" {
			signed = false
		}
		if signed {
			d.flat["sigma.signed"] = []string{"true"}
		} else {
			d.flat["sigma.signed"] = []string{"false"}
		}
	}
	if ev := d.Event; ev.Network != nil {
		if ev.Network.Direction == event.DirectionOutbound {
			d.flat["sigma.initiated"] = []string{"true"}
		} else if ev.Network.Direction == event.DirectionInbound {
			d.flat["sigma.initiated"] = []string{"false"}
		}
	}
}

// sigmaFields maps lowercase Sigma field names to ECS paths, tried in order. Fields not
// listed fall back to data.<name>, then to the name as an ECS path.
var sigmaFields = map[string][]string{
	"image":               {"process.executable"},
	"commandline":         {"process.command_line"},
	"parentimage":         {"process.parent.executable"},
	"parentcommandline":   {"process.parent.command_line"},
	"processid":           {"process.pid"},
	"parentprocessid":     {"process.parent.pid"},
	"processguid":         {"process.entity_id"},
	"parentprocessguid":   {"process.parent.entity_id"},
	"originalfilename":    {"process.pe.original_file_name"},
	"product":             {"process.pe.product"},
	"company":             {"process.pe.company"},
	"description":         {"process.pe.description"},
	"fileversion":         {"process.pe.file_version"},
	"user":                {"process.user.name", "user.name"},
	"parentuser":          {"process.parent.user.name"},
	"integritylevel":      {"process.integrity_level"},
	"currentdirectory":    {"process.working_directory"},
	"targetfilename":      {"file.path"},
	"sourcefilename":      {"file.old_path"},
	"sourceip":            {"source.ip"},
	"sourceport":          {"source.port"},
	"sourcehostname":      {"source.domain"},
	"destinationip":       {"destination.ip"},
	"destinationport":     {"destination.port"},
	"destinationhostname": {"destination.domain"},
	"protocol":            {"network.transport"},
	"queryname":           {"dns.question.name"},
	"queryresults":        {"dns.resolved_ip"},
	"targetobject":        {"registry.path"},
	"details":             {"registry.data.strings"},
	"eventtype":           {"event.action"},
	"imageloaded":         {"dll.path"},
	"eventid":             {"event.code"},
	"provider_name":       {"event.provider"},
	"servicename":         {"service.name"},
	"imagepath":           {"service.path"},
	"servicefilename":     {"service.path"},
	"targetusername":      {"user.target.name"},
	"targetdomainname":    {"user.target.domain"},
	"subjectusername":     {"user.name"},
	"subjectdomainname":   {"user.domain"},
	"ipaddress":           {"source.ip"},
	"computer":            {"host.name"},
	"computername":        {"host.name"},
	"hostname":            {"host.name"},
	"hashes":              {"sigma.hashes"},
	"md5":                 {"sigma.md5"},
	"sha1":                {"sigma.sha1"},
	"sha256":              {"sigma.sha256"},
	"imphash":             {"sigma.imphash"},
	"signed":              {"sigma.signed"},
	"initiated":           {"sigma.initiated"},
}

// libraryFields override PE metadata fields for image-load events, where Sysmon's fields
// describe the loaded module rather than the process.
var libraryFields = map[string][]string{
	"originalfilename": {"dll.pe.original_file_name"},
	"product":          {"dll.pe.product"},
	"company":          {"dll.pe.company"},
	"description":      {"dll.pe.description"},
	"fileversion":      {"dll.pe.file_version"},
}

// Get returns the values of a Sigma or ECS field and whether it is present (non-empty).
func (d *Doc) Get(field string) ([]string, bool) {
	key := strings.ToLower(field)
	var paths []string
	if d.has(event.CategoryLibrary) {
		paths = libraryFields[key]
	}
	if paths == nil {
		paths = sigmaFields[key]
	}
	for _, p := range paths {
		if v := d.flat[p]; nonEmpty(v) {
			return v, true
		}
	}
	if v := d.flat["data."+key]; nonEmpty(v) {
		return v, true
	}
	if v := d.flat[key]; nonEmpty(v) {
		return v, true
	}
	return nil, false
}

func nonEmpty(v []string) bool {
	for _, s := range v {
		if s != "" {
			return true
		}
	}
	return false
}

// Keywords returns the free-text values keyword searches look at.
func (d *Doc) Keywords() []string {
	if d.kw != nil {
		return d.kw
	}
	kw := []string{}
	for _, k := range []string{"message", "event.original", "process.command_line"} {
		kw = append(kw, d.flat[k]...)
	}
	for k, v := range d.flat {
		if strings.HasPrefix(k, "data.") {
			kw = append(kw, v...)
		}
	}
	d.kw = kw
	return kw
}
