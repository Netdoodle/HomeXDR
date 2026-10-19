package logtail

import (
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/shared/api"
)

func TestParseSyslog(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.Local)
	p, ok := ParseSyslog("Dec 31 23:59:58 web1 sshd[812]: Accepted publickey for bob", now)
	if !ok || p.App != "sshd" || p.PID != 812 || p.Host != "web1" || p.Message != "Accepted publickey for bob" {
		t.Fatalf("%+v", p)
	}
	if p.Time.Year() != 2025 {
		t.Fatalf("December line read in January should be last year: %v", p.Time)
	}
	p, ok = ParseSyslog("2026-10-19T12:34:56.123456+00:00 web1 sudo: bob : COMMAND=/bin/id", now)
	if !ok || p.App != "sudo" || p.PID != 0 || p.Time.Unix() != time.Date(2026, 10, 19, 12, 34, 56, 0, time.UTC).Unix() {
		t.Fatalf("%+v", p)
	}
	if _, ok := ParseSyslog("not a syslog line", now); ok {
		t.Fatal("garbage parsed")
	}
}

func TestParseFormats(t *testing.T) {
	e := Parse(api.LogSource{Format: "json", Dataset: "app.json"}, "/var/log/app.log", []byte(`{"msg":"started","level":"INFO","port":8080}`))
	if e.Message != "started" || e.Log.Level != "info" || e.Data["port"] != float64(8080) || e.Event.Dataset != "app.json" || e.Log.FilePath != "/var/log/app.log" {
		t.Fatalf("%+v %+v", e, e.Log)
	}
	e = Parse(api.LogSource{}, "/x.log", []byte("plain line"))
	if e.Message != "plain line" || e.Event.Dataset != "logfile" || e.Event.Module != "logfile" {
		t.Fatalf("%+v", e)
	}
	e = Parse(api.LogSource{Format: "syslog"}, "/x.log", []byte("Oct 19 12:00:00 h nginx[5]: GET /"))
	if e.Log.AppName != "nginx" || e.Process == nil || e.Process.PID != 5 || e.Message != "GET /" {
		t.Fatalf("%+v", e)
	}
}
