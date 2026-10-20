package config

import "testing"

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
