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

// The jailer's --cgroup-version defaults to "1", and KelyfOS only ever runs on
// a cgroup v2 host — pickMode refuses anything else before a slice exists. So
// naming a parent cgroup without also naming the version asks the jailer to
// place the VMM using a hierarchy that is not mounted, which it does not do and
// does not complain about: the VMM stays where it started, and the quota
// KelyfOS then reads back from /proc is missing. That was the whole of the
// direct-mode half of P5-6, and it is one flag, so it is worth a test that
// keeps the two arguments together.
func TestNamingAParentCgroupAlsoNamesTheVersion(t *testing.T) {
	argv := jailArgv("abc123",
		&Slice{Percent: 150, Path: "/sys/fs/cgroup/kelyfos/abc123", mode: modeDirect},
		[]string{"--api-sock", inJail("fc.sock")})
	joined := strings.Join(argv, " ")

	if !strings.Contains(joined, "--parent-cgroup kelyfos/abc123") {
		t.Fatalf("the parent cgroup is not named, or not relative to the mount point:\n  %s", joined)
	}
	if !strings.Contains(joined, "--cgroup-version 2") {
		t.Errorf("--parent-cgroup without --cgroup-version 2 is a silent no-op on a v2 host:\n  %s", joined)
	}

	// The systemd path does not use --parent-cgroup at all: there the scope
	// created around this command line is what places the VMM, and naming a
	// parent as well would be two answers to one question.
	sysd := jailArgv("abc123", &Slice{Percent: 150, mode: modeSystemd},
		[]string{"--api-sock", inJail("fc.sock")})
	if j := strings.Join(sysd, " "); strings.Contains(j, "--parent-cgroup") {
		t.Errorf("the systemd path named a parent cgroup as well as a scope:\n  %s", j)
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
