package config

import (
	"os"
	"strings"
	"testing"
)

func TestParseSizeAcceptsHumanUnits(t *testing.T) {
	cases := map[string]int64{
		"512M": 512 << 20, "2G": 2 << 30, `"2G"`: 2 << 30,
		"1k": 1 << 10, "1T": 1 << 40, "4096": 4096,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil {
			t.Errorf("ParseSize(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseSizeRejectsNonsense(t *testing.T) {
	for _, in := range []string{"", "2X", "abc", "-1G", "G"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) accepted a bad size", in)
		}
	}
}

func TestResourcesSectionParses(t *testing.T) {
	cfg := writeAndLoad(t, `
[sandbox]
image = "dev"

[resources]
cpus = 4
mem  = "2G"
disk = "8G"
`)
	if cfg.ResCPUs != 4 {
		t.Errorf("cpus = %d, want 4", cfg.ResCPUs)
	}
	if cfg.ResMemMiB != 2048 {
		t.Errorf("mem = %d MiB, want 2048", cfg.ResMemMiB)
	}
	if cfg.ResDiskByte != 8<<30 {
		t.Errorf("disk = %d, want %d", cfg.ResDiskByte, int64(8)<<30)
	}
	if cfg.Image != "dev" {
		t.Errorf("[sandbox] image lost: %q", cfg.Image)
	}
}

// A key in the wrong section must not silently satisfy the other one.
func TestResourcesKeysAreSectionScoped(t *testing.T) {
	if _, err := loadString(t, "[resources]\nimage = \"dev\"\n"); err == nil {
		t.Error("[resources] accepted a [sandbox] key")
	}
	if _, err := loadString(t, "[sandbox]\ncpus = 4\n"); err == nil {
		t.Error("[sandbox] accepted a [resources] key")
	}
}

func TestUnknownSectionStillRefused(t *testing.T) {
	if _, err := loadString(t, "[nonsense]\ncpus = 1\n"); err == nil {
		t.Error("unknown section accepted")
	}
}

func loadString(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := t.TempDir() + "/kelyfos.toml"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func writeAndLoad(t *testing.T, body string) *Config {
	t.Helper()
	cfg, err := loadString(t, body)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

func TestParseMemMiBKeepsBareNumbersAsMiB(t *testing.T) {
	// v0.3 command lines say --mem 512 and mean 512 MiB. Reading that as
	// 512 bytes would silently hand out a machine with no memory.
	for in, want := range map[string]int{"512": 512, "384": 384, "512M": 512, "2G": 2048, `"1G"`: 1024} {
		got, err := ParseMemMiB(in)
		if err != nil {
			t.Errorf("ParseMemMiB(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMemMiB(%q) = %d MiB, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "0", "-5", "abc", "2X"} {
		if _, err := ParseMemMiB(bad); err == nil {
			t.Errorf("ParseMemMiB(%q) accepted", bad)
		}
	}
}

// A limit that is specified but not yet enforced must refuse, not accept.
// Accepting it would leave the user believing in a limit that does nothing.
func TestUnenforcedResourceKeysRefuse(t *testing.T) {
	for _, key := range []string{"cpu_quota", "scratch", "net_mbps_rx", "net_mbps_tx",
		"disk_iops", "disk_mbps", "max_runtime", "idle_timeout"} {
		_, err := loadString(t, "[resources]\n"+key+" = \"1\"\n")
		if err == nil {
			t.Errorf("[resources] %s was accepted but nothing enforces it", key)
			continue
		}
		if !strings.Contains(err.Error(), "not enforced yet") || !strings.Contains(err.Error(), "E1-") {
			t.Errorf("%s: error should say it is unenforced and name the task, got: %v", key, err)
		}
	}
}

func TestCeilingRecordsItsLine(t *testing.T) {
	cfg := writeAndLoad(t, "[sandbox]\nimage = \"dev\"\n\n[resources]\ncpus = 2\nmem  = \"1G\"\n")
	if line, ok := cfg.Ceiling("cpus"); !ok || line != 5 {
		t.Errorf("cpus ceiling at line %d (ok=%v), want 5", line, ok)
	}
	if line, ok := cfg.Ceiling("mem"); !ok || line != 6 {
		t.Errorf("mem ceiling at line %d (ok=%v), want 6", line, ok)
	}
	if _, ok := cfg.Ceiling("disk"); ok {
		t.Error("reported a ceiling for a key that was never written")
	}
}
