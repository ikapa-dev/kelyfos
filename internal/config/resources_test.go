package config

import (
	"os"
	"testing"
	"time"
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

// Every key docs/resources.md specifies is now enforced, so every one of them
// must parse. This replaces the test that asserted the opposite for whichever
// keys were still outstanding: that list emptied at E1-6, and a loop over an
// empty list asserts nothing at all.
func TestEveryDocumentedResourceKeyParses(t *testing.T) {
	cfg := writeAndLoad(t, `
[resources]
cpus         = 4
mem          = "2G"
disk         = "8G"
scratch      = "512M"
cpu_quota    = "150%"
net_mbps_rx  = 10
net_mbps_tx  = 5
disk_iops    = 500
disk_mbps    = 50
max_runtime  = "30m"
idle_timeout = "5m"
`)
	for _, c := range []struct {
		key string
		ok  bool
	}{
		{"cpus", cfg.ResCPUs == 4},
		{"mem", cfg.ResMemMiB == 2048},
		{"disk", cfg.ResDiskByte == 8<<30},
		{"scratch", cfg.ResScratchByte == 512<<20},
		{"cpu_quota", cfg.ResCPUQuota == 150},
		{"net_mbps_rx", cfg.ResNetMbpsRx == 10},
		{"net_mbps_tx", cfg.ResNetMbpsTx == 5},
		{"disk_iops", cfg.ResDiskIOPS == 500},
		{"disk_mbps", cfg.ResDiskMbps == 50},
		{"max_runtime", cfg.ResMaxRuntime == 30*time.Minute},
		{"idle_timeout", cfg.ResIdleTimeout == 5*time.Minute},
	} {
		if !c.ok {
			t.Errorf("%s did not parse to the expected value", c.key)
		}
	}
}

func TestBudgetsRejectNonsense(t *testing.T) {
	for _, body := range []string{
		"[resources]\nmax_runtime = \"soon\"\n",
		"[resources]\nidle_timeout = \"0s\"\n",
		"[resources]\nmax_runtime = \"-5m\"\n",
		"[resources]\nmax_runtime = 60\n", // a bare number has no unit, so no meaning
	} {
		if _, err := loadString(t, body); err == nil {
			t.Errorf("accepted a bad budget:\n%s", body)
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

func TestCPUQuotaParses(t *testing.T) {
	cfg := writeAndLoad(t, "[resources]\ncpu_quota = \"150%\"\n")
	if cfg.ResCPUQuota != 150 {
		t.Errorf("cpu_quota = %d, want 150", cfg.ResCPUQuota)
	}
	// A bare number is ambiguous — 50 could be half a core or fifty of them.
	for _, bad := range []string{"50", "\"\"", "\"-10%\"", "\"0%\"", "\"abc%\""} {
		if _, err := loadString(t, "[resources]\ncpu_quota = "+bad+"\n"); err == nil {
			t.Errorf("cpu_quota = %s was accepted", bad)
		}
	}
}

func TestIORatesParse(t *testing.T) {
	cfg := writeAndLoad(t, `
[resources]
net_mbps_rx = 10
net_mbps_tx = 5
disk_iops   = 500
disk_mbps   = 50
`)
	for _, c := range []struct {
		key  string
		got  int
		want int
	}{
		{"net_mbps_rx", cfg.ResNetMbpsRx, 10},
		{"net_mbps_tx", cfg.ResNetMbpsTx, 5},
		{"disk_iops", cfg.ResDiskIOPS, 500},
		{"disk_mbps", cfg.ResDiskMbps, 50},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.key, c.got, c.want)
		}
	}
}

// Zero is refused rather than read as either "no limit" or "no traffic". Both
// readings are defensible, which is exactly why the file may not say it.
func TestIORateZeroAndNegativeRefused(t *testing.T) {
	for _, body := range []string{
		"[resources]\nnet_mbps_rx = 0\n",
		"[resources]\ndisk_iops = -1\n",
		"[resources]\ndisk_mbps = \"50M\"\n",
	} {
		if _, err := loadString(t, body); err == nil {
			t.Errorf("accepted a bad rate:\n%s", body)
		}
	}
}

func TestScratchParsesAsASize(t *testing.T) {
	cfg := writeAndLoad(t, "[resources]\nscratch = \"256M\"\n")
	if cfg.ResScratchByte != 256<<20 {
		t.Errorf("scratch = %d, want %d", cfg.ResScratchByte, int64(256)<<20)
	}
	// Same grammar as mem and disk: a bare byte count is a byte count.
	cfg = writeAndLoad(t, "[resources]\nscratch = 1048576\n")
	if cfg.ResScratchByte != 1<<20 {
		t.Errorf("scratch = %d, want %d", cfg.ResScratchByte, 1<<20)
	}
}
