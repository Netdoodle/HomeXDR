package events

import (
	"reflect"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Kind is a column's value type.
type Kind int

// Column kinds.
const (
	KString Kind = iota
	KInt
	KArray
	KTime
)

// Column is an indexed event field.
type Column struct {
	Name  string // SQL column name
	Field string // ECS path used in queries
	Kind  Kind
	Get   func(e *event.Event) any // string, int64, []string or time.Time
}

func proc(e *event.Event) *event.Process {
	if e.Process != nil {
		return e.Process
	}
	return &event.Process{}
}

func parent(e *event.Event) *event.Process {
	if e.Process != nil && e.Process.Parent != nil {
		return e.Process.Parent
	}
	return &event.Process{}
}

func str(s string) any { return s }

// Columns lists the indexed fields shared by every backend, in table order.
var Columns = []Column{
	{"id", "id", KString, func(e *event.Event) any { return e.ID }},
	{"ts", "@timestamp", KTime, func(e *event.Event) any { return e.Timestamp.UTC() }},
	{"ingested", "event.ingested", KTime, func(e *event.Event) any {
		if e.Event.Ingested != nil {
			return e.Event.Ingested.UTC()
		}
		return time.Now().UTC()
	}},
	{"host_id", "host.id", KString, func(e *event.Event) any { return e.Host.ID }},
	{"host_name", "host.name", KString, func(e *event.Event) any { return e.Host.Name }},
	{"platform", "host.os.platform", KString, func(e *event.Event) any {
		if e.Host.OS != nil {
			return e.Host.OS.Platform
		}
		return ""
	}},
	{"kind", "event.kind", KString, func(e *event.Event) any { return e.Event.Kind }},
	{"category", "event.category", KArray, func(e *event.Event) any { return nonNil(e.Event.Category) }},
	{"type", "event.type", KArray, func(e *event.Event) any { return nonNil(e.Event.Type) }},
	{"action", "event.action", KString, func(e *event.Event) any { return e.Event.Action }},
	{"module", "event.module", KString, func(e *event.Event) any { return e.Event.Module }},
	{"dataset", "event.dataset", KString, func(e *event.Event) any { return e.Event.Dataset }},
	{"provider", "event.provider", KString, func(e *event.Event) any { return e.Event.Provider }},
	{"code", "event.code", KString, func(e *event.Event) any { return e.Event.Code }},
	{"outcome", "event.outcome", KString, func(e *event.Event) any { return e.Event.Outcome }},
	{"severity", "event.severity", KInt, func(e *event.Event) any { return int64(e.Event.Severity) }},
	{"message", "message", KString, func(e *event.Event) any { return e.Message }},
	{"process_entity_id", "process.entity_id", KString, func(e *event.Event) any { return proc(e).EntityID }},
	{"process_pid", "process.pid", KInt, func(e *event.Event) any { return proc(e).PID }},
	{"process_name", "process.name", KString, func(e *event.Event) any { return proc(e).Name }},
	{"process_executable", "process.executable", KString, func(e *event.Event) any { return proc(e).Executable }},
	{"process_command_line", "process.command_line", KString, func(e *event.Event) any { return proc(e).CommandLine }},
	{"process_sha256", "process.hash.sha256", KString, func(e *event.Event) any {
		if h := proc(e).Hash; h != nil {
			return h.SHA256
		}
		return ""
	}},
	{"parent_entity_id", "process.parent.entity_id", KString, func(e *event.Event) any { return parent(e).EntityID }},
	{"parent_pid", "process.parent.pid", KInt, func(e *event.Event) any { return parent(e).PID }},
	{"parent_name", "process.parent.name", KString, func(e *event.Event) any { return parent(e).Name }},
	{"parent_executable", "process.parent.executable", KString, func(e *event.Event) any { return parent(e).Executable }},
	{"user_name", "user.name", KString, func(e *event.Event) any {
		if e.User != nil && e.User.Name != "" {
			return e.User.Name
		}
		if p := proc(e); p.User != nil {
			return p.User.Name
		}
		return ""
	}},
	{"file_path", "file.path", KString, func(e *event.Event) any {
		if e.File != nil {
			return e.File.Path
		}
		return ""
	}},
	{"file_sha256", "file.hash.sha256", KString, func(e *event.Event) any {
		if e.File != nil && e.File.Hash != nil {
			return e.File.Hash.SHA256
		}
		return ""
	}},
	{"dll_path", "dll.path", KString, func(e *event.Event) any {
		if e.DLL != nil {
			return e.DLL.Path
		}
		return ""
	}},
	{"registry_path", "registry.path", KString, func(e *event.Event) any {
		if e.Registry != nil {
			return e.Registry.Path
		}
		return ""
	}},
	{"source_ip", "source.ip", KString, func(e *event.Event) any {
		if e.Source != nil {
			return e.Source.IP
		}
		return ""
	}},
	{"source_port", "source.port", KInt, func(e *event.Event) any {
		if e.Source != nil {
			return int64(e.Source.Port)
		}
		return int64(0)
	}},
	{"destination_ip", "destination.ip", KString, func(e *event.Event) any {
		if e.Destination != nil {
			return e.Destination.IP
		}
		return ""
	}},
	{"destination_port", "destination.port", KInt, func(e *event.Event) any {
		if e.Destination != nil {
			return int64(e.Destination.Port)
		}
		return int64(0)
	}},
	{"destination_domain", "destination.domain", KString, func(e *event.Event) any {
		if e.Destination != nil {
			return e.Destination.Domain
		}
		return ""
	}},
	{"transport", "network.transport", KString, func(e *event.Event) any {
		if e.Network != nil {
			return e.Network.Transport
		}
		return ""
	}},
	{"direction", "network.direction", KString, func(e *event.Event) any {
		if e.Network != nil {
			return e.Network.Direction
		}
		return ""
	}},
	{"community_id", "network.community_id", KString, func(e *event.Event) any {
		if e.Network != nil {
			return e.Network.CommunityID
		}
		return ""
	}},
	{"dns_question", "dns.question.name", KString, func(e *event.Event) any {
		if e.DNS != nil {
			return e.DNS.Question.Name
		}
		return ""
	}},
	{"rule_name", "rule.name", KString, func(e *event.Event) any {
		if e.Rule != nil {
			return e.Rule.Name
		}
		return ""
	}},
}

// columnByField maps ECS paths (and a few aliases) to columns.
var columnByField = func() map[string]*Column {
	m := make(map[string]*Column, len(Columns)+4)
	for i := range Columns {
		m[Columns[i].Field] = &Columns[i]
	}
	m["host.hostname"] = m["host.name"]
	m["timestamp"] = m["@timestamp"]
	m["event.id"] = m["id"]
	return m
}()

// fieldAliases are Splunk and CIM-style names accepted for HomeXDR's fields.
var fieldAliases = map[string]string{
	"index": "event.module", "sourcetype": "event.dataset", "host": "host.name",
	"category": "event.category", "outcome": "event.outcome",
	"bytes": "network.bytes", "packets": "network.packets",
	"src": "source.ip", "src_ip": "source.ip", "src_port": "source.port",
	"dest": "destination.ip", "dest_ip": "destination.ip", "dest_port": "destination.port",
	"user": "user.name", "action": "event.action", "process": "process.name", "_time": "@timestamp",
}

// canonicalField maps an alias to its HomeXDR field.
func canonicalField(f string) string {
	if a, ok := fieldAliases[f]; ok {
		return a
	}
	return f
}

// topLevel are the event's top-level JSON keys.
var topLevel = func() map[string]bool {
	m := map[string]bool{}
	t := reflect.TypeOf(event.Event{})
	for i := 0; i < t.NumField(); i++ {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			m[name] = true
		}
	}
	return m
}()

// jsonPath is a field's path in the event JSON. A name without a dot that is not a
// top-level event field is looked up in data, where parsed log fields live, so
// "LogonType" finds data.LogonType.
func jsonPath(field string) []string {
	if !strings.Contains(field, ".") && !topLevel[field] {
		return []string{"data", field}
	}
	return strings.Split(field, ".")
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
