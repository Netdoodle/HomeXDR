package config

import (
	"net/netip"
	"testing"
)

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{
		"": 0, "0": 0, "1048576": 1048576, "100B": 100,
		"1TB": 1e12, "1T": 1e12, "1tb": 1e12, "1.5TB": 1.5e12, "500GB": 500e9, "750G": 750e9, "10kB": 10_000,
		"1TiB": 1 << 40, "1Ti": 1 << 40, "500GiB": 500 << 30, "64MiB": 64 << 20, " 2 GiB ": 2 << 30,
	} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"TB", "1XB", "1 tera", "-1GB", "1ib", "1e9", "99999999PB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func TestLoadRetention(t *testing.T) {
	t.Setenv("HOMEXDR_RETENTION_DAYS", "0")
	t.Setenv("HOMEXDR_RETENTION_MAX_SIZE", "1TB")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RetentionDays != 0 || c.RetentionMaxBytes != 1e12 {
		t.Fatalf("retention = %d days, %d bytes", c.RetentionDays, c.RetentionMaxBytes)
	}
	t.Setenv("HOMEXDR_RETENTION_DAYS", "-1")
	if _, err := Load(); err == nil {
		t.Fatal("negative retention accepted")
	}
}

// With no allow list, only local networks may send syslog and flows.
func TestAllowDefaultsToLocalNetworks(t *testing.T) {
	t.Setenv("HOMEXDR_DATA_DIR", t.TempDir())
	t.Setenv("HOMEXDR_SYSLOG_ALLOW", "")
	t.Setenv("HOMEXDR_NETFLOW_ALLOW", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	in := func(list []netip.Prefix, ip string) bool {
		for _, p := range list {
			if p.Contains(netip.MustParseAddr(ip)) {
				return true
			}
		}
		return false
	}
	for _, list := range [][]netip.Prefix{c.SyslogAllow, c.NetFlowAllow} {
		for _, ip := range []string{"192.168.20.1", "10.1.2.3", "172.17.0.1", "127.0.0.1", "100.100.1.1", "fd00::1", "fe80::1"} {
			if !in(list, ip) {
				t.Errorf("%s is not allowed", ip)
			}
		}
		for _, ip := range []string{"8.8.8.8", "172.32.0.1", "100.128.0.1", "2001:db8::1"} {
			if in(list, ip) {
				t.Errorf("%s is allowed", ip)
			}
		}
	}
}

func TestNetFlowConfig(t *testing.T) {
	t.Setenv("HOMEXDR_DATA_DIR", t.TempDir())
	t.Setenv("HOMEXDR_SYSLOG_ALLOW", "192.168.20.1")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.NetFlowAddr != "" {
		t.Errorf("on by default: %q", c.NetFlowAddr)
	}
	if len(c.NetFlowAllow) != 1 || c.NetFlowAllow[0].String() != "192.168.20.1/32" {
		t.Errorf("allow list does not follow syslog's: %v", c.NetFlowAllow)
	}
	t.Setenv("HOMEXDR_NETFLOW_ADDR", ":2055")
	t.Setenv("HOMEXDR_NETFLOW_ALLOW", "10.0.0.0/8, 192.168.20.2")
	if c, err = Load(); err != nil {
		t.Fatal(err)
	}
	if c.NetFlowAddr != ":2055" || len(c.NetFlowAllow) != 2 || c.NetFlowAllow[1].String() != "192.168.20.2/32" {
		t.Errorf("config %q %v", c.NetFlowAddr, c.NetFlowAllow)
	}
	t.Setenv("HOMEXDR_NETFLOW_ALLOW", "not an address")
	if _, err = Load(); err == nil {
		t.Error("a bad allow list was accepted")
	}
}
