package sandbox

import "testing"

// The percentage never reaches the kernel: E1-2 fixes the translation exactly,
// and these are the numbers it names.
func TestCPUMaxLineMapsPercentToMicroseconds(t *testing.T) {
	cases := map[int]string{
		150: "150000 100000",
		50:  "50000 100000",
		100: "100000 100000",
		25:  "25000 100000",
		400: "400000 100000",
	}
	for pct, want := range cases {
		if got := cpuMaxLine(pct); got != want {
			t.Errorf("cpuMaxLine(%d%%) = %q, want %q", pct, got, want)
		}
	}
}

func TestNewCPUSliceRejectsNonPositiveQuota(t *testing.T) {
	for _, pct := range []int{0, -1, -100} {
		if _, err := NewCPUSlice("test", pct); err == nil {
			t.Errorf("NewCPUSlice accepted %d%%", pct)
		}
	}
}

// Under systemd the quota is requested rather than written, and the request has
// to carry the same percentage the CLI was given.
func TestWrapArgvBuildsTheScopeRequest(t *testing.T) {
	s := &Slice{Percent: 150, name: "kelyfos-abc", mode: modeSystemd}
	got := s.WrapArgv([]string{"firecracker", "--api-sock", "/x"})
	want := []string{"systemd-run", "--user", "--scope", "--quiet",
		"--unit", "kelyfos-abc", "-p", "CPUQuota=150%", "--",
		"firecracker", "--api-sock", "/x"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d: got %q want %q\nfull: %v", i, got[i], want[i], got)
		}
	}
	// The direct path must not rewrite the command at all.
	d := &Slice{Percent: 150, mode: modeDirect}
	if out := d.WrapArgv([]string{"firecracker"}); len(out) != 1 || out[0] != "firecracker" {
		t.Errorf("direct path rewrote argv: %v", out)
	}
	if out := (*Slice)(nil).WrapArgv([]string{"firecracker"}); len(out) != 1 {
		t.Errorf("nil slice rewrote argv: %v", out)
	}
}
