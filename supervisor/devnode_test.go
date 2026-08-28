package main

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// F10 (security review of 2026-08-28) — a confined process could mknod its way
// to the raw disks.
//
// profile.go names /dev/vda and /dev/vdb as the reason /dev is not granted
// wholesale: "the list is explicit and the disks are not on it". Three facts
// together made that untrue for a process that is root, which every confined
// process in this guest is:
//
//   - writeRights granted LANDLOCK_ACCESS_FS_MAKE_CHAR and
//     LANDLOCK_ACCESS_FS_MAKE_BLOCK on every writable tree, /root included;
//   - the merged overlay that /root lives on was mounted with flags 0 — no
//     MS_NODEV, so a device node on it is a working device node;
//   - mknod and mknodat are not on the seccomp refusal list.
//
// So: read the major:minor of the workspace disk out of /proc/partitions,
// `mknod /root/disk b 254 16`, and the block device the host attached
// read-write is open for raw reads and writes, past the nosuid,nodev mount that
// guards /work. /dev/vda goes the same way for reads.
//
// Two layers close it, and both are tested here rather than one being trusted:
// Landlock refuses the creation, and nodev makes a node that somehow existed
// inert. The live proof — mknod from inside a booted guest, as root, which is
// the only place the capability check does not mask Landlock's answer — is in
// the P7-17/F10 progress row.

// landlockRightNames is the subset of the ruleset's vocabulary this test talks
// about, so a failure names the right rather than printing a bit.
var landlockRightNames = []struct {
	name string
	bit  uint64
}{
	{"MAKE_CHAR", unix.LANDLOCK_ACCESS_FS_MAKE_CHAR},
	{"MAKE_BLOCK", unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK},
	{"MAKE_FIFO", unix.LANDLOCK_ACCESS_FS_MAKE_FIFO},
	{"MAKE_SOCK", unix.LANDLOCK_ACCESS_FS_MAKE_SOCK},
	{"MAKE_DIR", unix.LANDLOCK_ACCESS_FS_MAKE_DIR},
	{"MAKE_REG", unix.LANDLOCK_ACCESS_FS_MAKE_REG},
	{"MAKE_SYM", unix.LANDLOCK_ACCESS_FS_MAKE_SYM},
	{"REFER", unix.LANDLOCK_ACCESS_FS_REFER},
	{"TRUNCATE", unix.LANDLOCK_ACCESS_FS_TRUNCATE},
	{"EXECUTE", unix.LANDLOCK_ACCESS_FS_EXECUTE},
	{"READ_FILE", unix.LANDLOCK_ACCESS_FS_READ_FILE},
	{"WRITE_FILE", unix.LANDLOCK_ACCESS_FS_WRITE_FILE},
	{"READ_DIR", unix.LANDLOCK_ACCESS_FS_READ_DIR},
	{"REMOVE_DIR", unix.LANDLOCK_ACCESS_FS_REMOVE_DIR},
	{"REMOVE_FILE", unix.LANDLOCK_ACCESS_FS_REMOVE_FILE},
}

func rightsNamed(bits uint64) []string {
	var out []string
	for _, r := range landlockRightNames {
		if bits&r.bit != 0 {
			out = append(out, r.name)
		}
	}
	return out
}

// Layer one: the profile does not let a confined process create a device node
// anywhere it can write.
func TestF10_TheProfileGrantsNoDeviceNodeCreation(t *testing.T) {
	for _, r := range []struct{ name, why string }{
		{"MAKE_CHAR", "a character device — /dev/mem's major:minor is not a secret"},
		{"MAKE_BLOCK", "a block device — mknod /root/disk b 254 16 is the raw workspace disk"},
	} {
		bit := uint64(0)
		for _, k := range landlockRightNames {
			if k.name == r.name {
				bit = k.bit
			}
		}
		if writeRights&bit != 0 {
			t.Errorf("writeRights grants %s on every writable tree, so a confined process can create %s.\n"+
				"  Granted: %s\n"+
				"  profile.go says the raw disks are withheld from every process this supervisor starts;"+
				" with this bit set they are two commands away.",
				r.name, r.why, strings.Join(rightsNamed(writeRights), " "))
		}
	}
}

// The other half of layer one, and the reason this is a removal of two bits
// rather than of the whole MAKE_ family: programs really do create these.
func TestF10_TheProfileStillGrantsWhatProgramsActuallyCreate(t *testing.T) {
	for _, r := range []struct{ name, why string }{
		{"MAKE_FIFO", "mkfifo(3), which every build system with a progress pipe uses"},
		{"MAKE_SOCK", "a unix socket, which every language server and test runner binds"},
		{"MAKE_DIR", "mkdir"},
		{"MAKE_REG", "creating a file at all"},
		{"MAKE_SYM", "ln -s"},
		{"REFER", "mv between two granted trees"},
		{"TRUNCATE", "> file"},
	} {
		bit := uint64(0)
		for _, k := range landlockRightNames {
			if k.name == r.name {
				bit = k.bit
			}
		}
		if writeRights&bit == 0 {
			t.Errorf("writeRights no longer grants %s, which breaks %s.\n"+
				"  Granted: %s\n"+
				"  F10 took out MAKE_CHAR and MAKE_BLOCK and nothing else.",
				r.name, r.why, strings.Join(rightsNamed(writeRights), " "))
		}
	}
}

// The trap: removed from what is *granted*, kept in what is *governed*.
//
// handledRights is the ruleset's Access_fs, the set of actions Landlock has an
// opinion about at all. Taking MAKE_CHAR and MAKE_BLOCK out of writeRights while
// handledRights was still `= writeRights` would have dropped device creation out
// of the ruleset's vocabulary and permitted it *everywhere*, /etc and /usr
// included — a wider hole than the one F10 reported, and identical in a diff to
// the fix. This asserts the arrangement rather than either half of it.
func TestF10_DeviceCreationIsGovernedByTheRulesetAndGrantedByNoRule(t *testing.T) {
	for _, r := range []string{"MAKE_CHAR", "MAKE_BLOCK"} {
		bit := uint64(0)
		for _, k := range landlockRightNames {
			if k.name == r {
				bit = k.bit
			}
		}
		if handledRights&bit == 0 {
			t.Errorf("handledRights does not govern %s, so Landlock ignores device creation entirely"+
				" and it is permitted on every path — which is worse than F10, not better.\n"+
				"  Governed: %s", r, strings.Join(rightsNamed(handledRights), " "))
		}
		for _, g := range []struct {
			name string
			bits uint64
		}{
			{"writeRights", writeRights},
			{"readRights", readRights},
			{"deviceRights", deviceRights},
		} {
			if g.bits&bit != 0 {
				t.Errorf("%s grants %s; no rule in the ruleset may, or the governing above buys nothing", g.name, r)
			}
		}
	}
}

// Layer two: a node that somehow got created is inert, because the filesystem
// it would live on does not interpret device nodes.
//
// The lower directory is the read-only image and the upper is a tmpfs that is
// already MS_NODEV|MS_NOSUID — but a mount's flags are its own, not inherited
// from the layers underneath it, so the merged mount needed saying separately.
// Nothing on the root filesystem is a device node (the image ships none outside
// /dev, and /dev is a devtmpfs moved across afterwards with its own flags), so
// this costs the guest nothing.
func TestF10_TheMergedOverlayRefusesDeviceNodesAndSetuid(t *testing.T) {
	for _, f := range []struct {
		name string
		bit  uintptr
		why  string
	}{
		{"MS_NODEV", unix.MS_NODEV,
			"a block node an agent created under /root would still open the raw disk"},
		{"MS_NOSUID", unix.MS_NOSUID,
			"/bin/busybox in this image is mode 4755, and the root it sits on would honour that bit"},
	} {
		if overlayFlags&f.bit == 0 {
			t.Errorf("the merged overlay is not mounted %s: %s", f.name, f.why)
		}
	}
}

// The constraint, pinned so that nobody closes F10 the tempting way.
//
// mkfifo(3) is mknodat(2) with S_IFIFO, and this filter compares syscall numbers
// only — it cannot see the mode argument. Refusing the number would refuse every
// named pipe in the guest along with every device node, which is a far larger
// break than the hole it would close, and Landlock already refuses the device
// node by type. This test exists because "add mknod to the refusal list" is the
// first thing a reader of F10 reaches for.
func TestF10_MknodStaysOffTheSeccompRefusalList(t *testing.T) {
	for _, name := range []string{"mknod", "mknodat"} {
		if slices.Contains(refusalPolicy, name) {
			t.Errorf("%s is on the seccomp refusal list.\n"+
				"  mkfifo(3) is mknodat with S_IFIFO and this filter reads the syscall number only,"+
				" so this refuses every named pipe in the guest with EPERM.\n"+
				"  Device nodes are refused by Landlock (MAKE_CHAR/MAKE_BLOCK are not granted)"+
				" and made inert by MS_NODEV, both of which see the file type.", name)
		}
	}
}
