package config

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

// P7-17/F21, second review round: privateGroup compared one group's gid
// against a different group's name.
//
//	if gid != os.Getgid() { return false }   // the FILE's gid vs the PROCESS's egid
//	u, _ := user.Current()
//	g, _ := user.LookupGroupId(u.Gid)        // the PASSWD ENTRY's gid
//	return g.Name == u.Username
//
// A comment claimed the two halves were deliberate. They were two halves of
// different groups, and they agree only while os.Getgid() == u.Gid. Under
// `newgrp staff`, `sg`, or inside a setgid directory they do not — and a file
// whose group was `staff` was then validated against the name of the user's
// PRIVATE group and accepted, which is the exact case the rule exists to refuse.
//
// No test on an ordinary machine could show that, because on an ordinary
// machine the two gids are equal. So the decision takes its inputs explicitly
// and the skew is constructed here.

// alice is a user-private-group account: uid 1000, primary gid 1000 named
// "alice". staff is gid 50, the shared group.
func aliceLookup(gid int) (string, bool) {
	switch gid {
	case 1000:
		return "alice", true
	case 50:
		return "staff", true
	}
	return "", false
}

func TestF21_TheSkewNewgrpProducesIsRefused(t *testing.T) {
	// The exact shape: alice has run `newgrp staff`, so the process's effective
	// gid is 50 and files she creates get group staff — while her passwd entry
	// still says 1000. The old code asked "is the file's gid the process's
	// egid?" (50 == 50, yes) and then "is the group named by the passwd entry
	// called alice?" (1000 -> "alice", yes) and accepted a staff-group file.
	if privateGroup(50, 1000, "alice", aliceLookup) {
		t.Error("a file in the shared group `staff` was accepted as alice's private group")
	}
	// Her own group is still her own group.
	if !privateGroup(1000, 1000, "alice", aliceLookup) {
		t.Error("alice's own user-private group was refused")
	}
}

func TestF21_APrimaryGroupNotNamedAfterTheUserIsNotPrivate(t *testing.T) {
	// bob's primary group IS staff. Same gid on both halves, but the name says
	// other people are in it, so it is not a private group.
	if privateGroup(50, 50, "bob", aliceLookup) {
		t.Error("a primary group named `staff` was accepted as bob's private group")
	}
}

func TestF21_AnUnresolvableGroupIsNotPrivate(t *testing.T) {
	// Unresolvable is not the same as safe: the question is whether other
	// people can write the file, and "the platform would not say" is not an
	// answer that means no.
	if privateGroup(4242, 4242, "alice", aliceLookup) {
		t.Error("a gid nothing resolves to was accepted as a private group")
	}
}

// And the wiring, on whatever machine this runs: isPrivateGroup must agree with
// the decision applied to the real sources — the FILE's gid resolved to a name,
// not the process's egid resolved through the passwd entry.
func TestF21_IsPrivateGroupWiresTheFilesOwnGroup(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	primary, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Skip("non-numeric primary gid")
	}
	name, ok := "", false
	if g, err := user.LookupGroupId(u.Gid); err == nil {
		name, ok = g.Name, true
	}
	want := ok && name == u.Username
	if got := isPrivateGroup(primary); got != want {
		t.Errorf("isPrivateGroup(%d) = %v; group %q, user %q, want %v", primary, got, name, u.Username, want)
	}
	// gid 0 is root's group, named "root" everywhere this runs. Unless the
	// invoking user is root it is not their private group — and the old code
	// decided this by os.Getgid() and by a different group's name.
	if u.Uid != "0" && isPrivateGroup(0) {
		t.Error("gid 0 was accepted as this user's private group")
	}
	_ = os.Getgid()
}
