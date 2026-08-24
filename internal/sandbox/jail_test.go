package sandbox

import (
	"strings"
	"testing"
)

// The jailer forwards everything after `--` to Firecracker verbatim, so the
// tail of this argv is the one place in KelyfOS where `--no-seccomp` or a
// `--seccomp-filter` pointing at somebody's own program could reach the VMM.
// Nothing puts them there today; this is what keeps that true, and it runs in
// `make test` with no KVM and no root.
//
// Which filter is in force follows from that absence: with neither flag,
// Firecracker installs the one compiled into the binary at build time, so the
// filter's identity is the binary's identity — and the binary is pinned by
// sha256 in dev/install-firecracker.sh (P5-2, docs/hardening.md §3).
func TestTheVMMIsNeverStartedWithoutItsFilter(t *testing.T) {
	forbidden := []string{"--no-seccomp", "--seccomp-filter"}

	cases := []struct {
		name string
		argv []string
	}{
		{"cold boot", jailArgv("abc123", &Slice{}, []string{
			"--api-sock", inJail("fc.sock"), "--config-file", inJail("config.json")})},
		{"restore", jailArgv("abc123", &Slice{}, []string{
			"--api-sock", inJail("fc.sock")})},
		{"inside a cgroup", jailArgv("abc123",
			&Slice{Percent: 150, Path: "/sys/fs/cgroup/kelyfos/abc123", mode: modeDirect},
			[]string{"--api-sock", inJail("fc.sock")})},
	}

	for _, tc := range cases {
		joined := strings.Join(tc.argv, " ")
		for _, flag := range forbidden {
			if strings.Contains(joined, flag) {
				t.Errorf("%s: the VMM command line carries %s\n  %s", tc.name, flag, joined)
			}
		}
		// An assertion that only ever looks for absence passes just as well on
		// an empty slice, so check the command line is the real one too.
		if len(tc.argv) < 2 || tc.argv[0] != "sudo" || tc.argv[1] != "-n" {
			t.Fatalf("%s: not the jailer command line at all: %v", tc.name, tc.argv)
		}
		if !strings.Contains(joined, "jailer") {
			t.Fatalf("%s: no jailer in %v", tc.name, tc.argv)
		}
	}
}

// The separator matters: the jailer reads its own arguments up to `--` and
// hands the rest to Firecracker. A Firecracker flag on the wrong side of it is
// an argument the jailer does not understand, and a jailer flag on the wrong
// side is one Firecracker does not.
func TestFirecrackersArgumentsAreOnFirecrackersSideOfTheSeparator(t *testing.T) {
	argv := jailArgv("abc123", &Slice{}, []string{
		"--api-sock", inJail("fc.sock"), "--config-file", inJail("config.json")})

	sep := -1
	for i, a := range argv {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("no `--` separator in %v", argv)
	}
	jailerSide := strings.Join(argv[:sep], " ")
	fcSide := strings.Join(argv[sep+1:], " ")

	for _, want := range []string{"--id", "--exec-file", "--uid", "--gid", "--chroot-base-dir"} {
		if !strings.Contains(jailerSide, want) {
			t.Errorf("the jailer's own %s is missing: %s", want, jailerSide)
		}
		if strings.Contains(fcSide, want) {
			t.Errorf("the jailer's %s leaked to Firecracker's side: %s", want, fcSide)
		}
	}
	for _, want := range []string{"--api-sock", "--config-file"} {
		if !strings.Contains(fcSide, want) {
			t.Errorf("Firecracker's %s is missing: %s", want, fcSide)
		}
	}
}
