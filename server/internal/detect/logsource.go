package detect

import (
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// logsourceFilter is a cheap pre-check derived from a rule's logsource.
type logsourceFilter struct {
	category func(d *Doc) bool
	product  func(d *Doc) bool
	service  func(d *Doc) bool
}

func (f *logsourceFilter) match(d *Doc) bool {
	if f.product != nil && !f.product(d) {
		return false
	}
	if f.category != nil && !f.category(d) {
		return false
	}
	if f.service != nil && !f.service(d) {
		return false
	}
	return true
}

func hasType(d *Doc, types ...string) bool {
	for _, t := range d.Event.Event.Type {
		for _, want := range types {
			if t == want {
				return true
			}
		}
	}
	return false
}

func codeIs(codes ...string) func(d *Doc) bool {
	return func(d *Doc) bool {
		for _, c := range codes {
			if d.Event.Event.Code == c {
				return true
			}
		}
		return false
	}
}

var categoryFilters = map[string]func(d *Doc) bool{
	"process_creation":    func(d *Doc) bool { return d.has(event.CategoryProcess) && hasType(d, event.TypeStart) },
	"process_termination": func(d *Doc) bool { return d.has(event.CategoryProcess) && hasType(d, event.TypeEnd) },
	"network_connection": func(d *Doc) bool {
		return d.has(event.CategoryNetwork) && hasType(d, event.TypeConnection, event.TypeStart)
	},
	"firewall": func(d *Doc) bool { return d.Event.Observer != nil && d.Event.Observer.Type == "firewall" },
	"file_event": func(d *Doc) bool {
		return d.has(event.CategoryFile) && hasType(d, event.TypeCreation, event.TypeChange)
	},
	"file_change": func(d *Doc) bool { return d.has(event.CategoryFile) && hasType(d, event.TypeChange) },
	"file_rename": func(d *Doc) bool {
		return d.has(event.CategoryFile) && d.Event.File != nil && d.Event.File.OldPath != ""
	},
	"file_delete":  func(d *Doc) bool { return d.has(event.CategoryFile) && hasType(d, event.TypeDeletion) },
	"file_access":  func(d *Doc) bool { return d.has(event.CategoryFile) && hasType(d, event.TypeAccess) },
	"registry_set": func(d *Doc) bool { return d.has(event.CategoryRegistry) && hasType(d, event.TypeChange) },
	"registry_add": func(d *Doc) bool { return d.has(event.CategoryRegistry) && hasType(d, event.TypeCreation) },
	"registry_delete": func(d *Doc) bool {
		return d.has(event.CategoryRegistry) && hasType(d, event.TypeDeletion)
	},
	"registry_event":   func(d *Doc) bool { return d.has(event.CategoryRegistry) },
	"dns_query":        func(d *Doc) bool { return d.Event.DNS != nil && d.Event.DNS.Question.Name != "" },
	"dns":              func(d *Doc) bool { return d.Event.DNS != nil && d.Event.DNS.Question.Name != "" },
	"image_load":       func(d *Doc) bool { return d.has(event.CategoryLibrary) },
	"driver_load":      func(d *Doc) bool { return d.has(event.CategoryDriver) },
	"ps_script":        codeIs("4104"),
	"ps_module":        codeIs("4103"),
	"ps_classic_start": codeIs("400"),
	"authentication":   func(d *Doc) bool { return d.has(event.CategoryAuthentication) },
}

var serviceProviders = map[string][]string{
	"security":   {"microsoft-windows-security-auditing"},
	"sysmon":     {"microsoft-windows-sysmon"},
	"powershell": {"microsoft-windows-powershell", "powershell"},
	"windefend":  {"microsoft-windows-windows defender"},
	"system":     {"service control manager", "microsoft-windows-kernel-general", "eventlog"},
}

var serviceChannels = map[string]string{
	"security":      "security",
	"system":        "system",
	"sysmon":        "microsoft-windows-sysmon/operational",
	"powershell":    "microsoft-windows-powershell/operational",
	"windefend":     "microsoft-windows-windows defender/operational",
	"taskscheduler": "microsoft-windows-taskscheduler/operational",
	"application":   "application",
}

func compileLogsource(ls LogSource) (*logsourceFilter, error) {
	f := &logsourceFilter{}
	if p := strings.ToLower(strings.TrimSpace(ls.Product)); p != "" {
		switch p {
		case "windows", "linux":
			f.product = func(d *Doc) bool { return d.Event.Host.OS != nil && d.Event.Host.OS.Platform == p }
		case "macos":
			f.product = func(d *Doc) bool { return d.Event.Host.OS != nil && d.Event.Host.OS.Platform == event.PlatformDarwin }
		default:
			f.product = func(d *Doc) bool {
				return strings.EqualFold(d.Event.Event.Module, p) ||
					(d.Event.Observer != nil && strings.EqualFold(d.Event.Observer.Product, p))
			}
		}
	}
	if c := strings.ToLower(strings.TrimSpace(ls.Category)); c != "" {
		if fn, ok := categoryFilters[c]; ok {
			f.category = fn
		} else {
			f.category = func(d *Doc) bool { return d.has(c) || strings.EqualFold(d.Event.Event.Dataset, c) }
		}
	}
	if s := strings.ToLower(strings.TrimSpace(ls.Service)); s != "" {
		providers := serviceProviders[s]
		channel := serviceChannels[s]
		f.service = func(d *Doc) bool {
			ev := d.Event
			prov := strings.ToLower(ev.Event.Provider)
			for _, p := range providers {
				if prov == p {
					return true
				}
			}
			if channel != "" {
				if v, ok := d.Get("Channel"); ok && strings.EqualFold(v[0], channel) {
					return true
				}
			}
			if strings.EqualFold(ev.Event.Dataset, s) || strings.HasSuffix(strings.ToLower(ev.Event.Dataset), "."+s) {
				return true
			}
			return ev.Log != nil && strings.EqualFold(ev.Log.AppName, s)
		}
	}
	return f, nil
}
