package config

import (
	"os"
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
