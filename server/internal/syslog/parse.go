// Package syslog receives syslog over UDP and TCP and decodes OPNsense/pfSense
// filterlog, Suricata EVE JSON, Unbound and DHCP lease logs, sshd authentication lines and
// generic messages into events.
package syslog

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// Message is one parsed syslog record.
type Message struct {
	Facility  int
	Severity  int
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	Msg       string
	Raw       string
}

var errNoPRI = errors.New("syslog: missing <PRI>")

// Parse parses an RFC 5424 or RFC 3164 (BSD) message. now is used when the message has no
// usable timestamp or no year.
func Parse(raw string, now time.Time) (*Message, error) {
	raw = strings.TrimRight(raw, "\r\n\x00")
	m := &Message{Raw: raw, Timestamp: now}
	if !strings.HasPrefix(raw, "<") {
		return nil, errNoPRI
	}
	end := strings.IndexByte(raw, '>')
	if end < 2 || end > 4 {
		return nil, errNoPRI
	}
	pri, err := strconv.Atoi(raw[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return nil, errNoPRI
	}
	m.Facility, m.Severity = pri/8, pri%8
	rest := raw[end+1:]

	if strings.HasPrefix(rest, "1 ") {
		parse5424(m, rest[2:], now)
	} else {
		parse3164(m, rest, now)
	}
	return m, nil
}

func nextField(s string) (string, string) {
	s = strings.TrimLeft(s, " ")
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func parse5424(m *Message, s string, now time.Time) {
	var ts, host, app, proc, msgid string
	ts, s = nextField(s)
	host, s = nextField(s)
	app, s = nextField(s)
	proc, s = nextField(s)
	msgid, s = nextField(s)
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		m.Timestamp = t
	}
	m.Hostname, m.AppName, m.ProcID, m.MsgID = nilValue(host), nilValue(app), nilValue(proc), nilValue(msgid)
	// Structured data: "-" or one or more [..] blocks (values may contain escaped "]").
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, "-") {
		s = strings.TrimPrefix(s, "-")
	} else {
		for strings.HasPrefix(s, "[") {
			i, inQuote := 1, false
			for i < len(s) {
				c := s[i]
				if c == '\\' {
					i += 2
					continue
				}
				if c == '"' {
					inQuote = !inQuote
				} else if c == ']' && !inQuote {
					break
				}
				i++
			}
			if i >= len(s) {
				s = ""
				break
			}
			s = s[i+1:]
		}
	}
	m.Msg = strings.TrimPrefix(strings.TrimPrefix(s, " "), "\uFEFF")
}

var months = map[string]time.Month{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

func parse3164(m *Message, s string, now time.Time) {
	// "Mmm dd hh:mm:ss " (dd may be space-padded), or an RFC 3339 timestamp some
	// senders use instead.
	if len(s) >= 16 && s[3] == ' ' && s[6] == ' ' && s[9] == ':' && s[12] == ':' {
		if mon, ok := months[s[:3]]; ok {
			day, _ := strconv.Atoi(strings.TrimSpace(s[4:6]))
			hh, _ := strconv.Atoi(s[7:9])
			mm, _ := strconv.Atoi(s[10:12])
			ss, _ := strconv.Atoi(s[13:15])
			year := now.Year()
			t := time.Date(year, mon, day, hh, mm, ss, 0, time.Local)
			if t.After(now.Add(24 * time.Hour)) { // December message received in January
				t = t.AddDate(-1, 0, 0)
			}
			m.Timestamp = t
			s = s[16:]
		}
	} else if tok, rest := nextField(s); len(tok) >= 19 && tok[4] == '-' && tok[10] == 'T' {
		if t, err := time.Parse(time.RFC3339Nano, tok); err == nil {
			m.Timestamp = t
			s = rest
		}
	}
	// Optional hostname, then TAG[pid]: or TAG:
	first, rest := nextField(s)
	if !isTag(first) {
		m.Hostname = first
		first, rest = nextField(rest)
	}
	if isTag(first) {
		tag := strings.TrimSuffix(first, ":")
		if i := strings.IndexByte(tag, '['); i >= 0 {
			m.ProcID = strings.TrimSuffix(tag[i+1:], "]")
			tag = tag[:i]
		}
		m.AppName = tag
		m.Msg = rest
		return
	}
	// No tag: everything after the hostname is the message.
	if m.Hostname != "" {
		m.Msg = strings.TrimSpace(first + " " + rest)
	} else {
		m.Msg = strings.TrimSpace(s)
	}
}

func isTag(s string) bool {
	return strings.HasSuffix(s, ":") || (strings.Contains(s, "[") && strings.HasSuffix(s, "]:")) ||
		(strings.Contains(s, "[") && strings.HasSuffix(s, "]"))
}

var severityNames = []string{"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}

// SeverityName returns the syslog severity keyword.
func SeverityName(sev int) string {
	if sev >= 0 && sev < len(severityNames) {
		return severityNames[sev]
	}
	return ""
}

var facilityNames = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
	"authpriv", "ftp", "ntp", "security", "console", "solaris-cron", "local0", "local1", "local2", "local3",
	"local4", "local5", "local6", "local7"}

// FacilityName returns the syslog facility keyword.
func FacilityName(f int) string {
	if f >= 0 && f < len(facilityNames) {
		return facilityNames[f]
	}
	return ""
}
