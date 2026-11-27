package console

import (
	"context"
	"testing"
)

func TestSyslogParserBinding(t *testing.T) {
	c, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	c.Syslog.Seen("192.168.1.1", "fw", "opnsense")
	if code, body := admin.do("PUT", "/api/integrations/syslog/bindings", map[string]string{"ip": "192.168.1.1", "parser": "nope"}, true); code != 400 {
		t.Fatalf("unknown parser = %d %v", code, body)
	}
	if code, body := admin.do("PUT", "/api/integrations/syslog/bindings", map[string]string{"ip": "not-an-ip", "parser": "pfsense"}, true); code != 400 {
		t.Fatalf("bad ip = %d %v", code, body)
	}
	if code, body := admin.do("PUT", "/api/integrations/syslog/bindings", map[string]string{"ip": "::ffff:192.168.1.1", "parser": "pfsense"}, true); code != 200 || body["ip"] != "192.168.1.1" {
		t.Fatalf("bind = %d %v", code, body)
	}
	if got := c.Syslog.Binding("192.168.1.1"); got != "pfsense" {
		t.Fatalf("binding %q", got)
	}
	code, body := admin.do("GET", "/api/integrations", nil, false)
	sl, _ := body["syslog"].(map[string]any)
	srcs, _ := sl["sources"].([]any)
	parsers, _ := sl["parsers"].([]any)
	if code != 200 || len(srcs) != 1 || srcs[0].(map[string]any)["parser"] != "pfsense" || len(parsers) < 10 {
		t.Fatalf("integrations = %d %v", code, body)
	}
	// Saved, so a restart keeps it.
	c.LoadSyslogBindings(context.Background())
	if got := c.Syslog.Binding("192.168.1.1"); got != "pfsense" {
		t.Fatalf("after reload %q", got)
	}
	if code, _ := admin.do("PUT", "/api/integrations/syslog/bindings", map[string]string{"ip": "192.168.1.1", "parser": ""}, true); code != 200 {
		t.Fatalf("unbind = %d", code)
	}
	if got := c.Syslog.Binding("192.168.1.1"); got != "" {
		t.Fatalf("after unbind %q", got)
	}
}
