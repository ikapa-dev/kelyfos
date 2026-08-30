package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/hostile"
	"github.com/ikapa-dev/kelyfos/internal/mcp"
)

// The hostile corpus for the guest's own file tools (P6-22, finding H-1).
//
// `write_file` and `read_file` take a path from the agent and hand it to the
// operating system. There is nothing between the two: no Clean, no IsLocal, no
// root to be beneath. The schema string says "Absolute path inside the sandbox"
// and nothing enforces the sentence.
//
// Two facts make that matter rather than merely being untidy. The supervisor is
// PID 1 and **is not confined by the profile it applies to everything it
// spawns** — `applyLandlock` and `applySeccomp` are reached only from
// `runConfined`, which is the re-exec'd helper, so the tools run with the whole
// filesystem in front of them. And the guest holds two block devices,
// `/dev/vda` and `/dev/vdb`, which the profile withholds *write* on from every
// confined child and which these tools will open for writing.
//
// One correction to the finding as it was reported, made here because a fixture
// written to the wrong sentence asserts the wrong thing: the profile does not
// withhold *reading* the disks. It grants read beneath `/` (profile.go's
// allowBeneath with readRights) and names seven writable device nodes, of which
// the disks are not two. So the claim this corpus makes is about writes.
//
// These fail until P6-24; the ledger says which.

// hostileTempCwd moves the test into a temporary directory before a relative
// path is handed to a tool.
//
// Without it, `write_file {"path":"../escape"}` writes into the repository
// itself: `go test` runs with the working directory set to the package, so the
// parent of that is the repository root. A fixture that demonstrates an escape
// by escaping into the source tree has demonstrated it a little too well.
func hostileTempCwd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "cwd")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	return dir
}

// H-1. A path the agent chose reaches the host filesystem unexamined.
func TestHostileWriteFileCannotLeaveTheSandboxsWork(t *testing.T) {
	hostileTempCwd(t)

	// The paths are chosen against the *guest's* filesystem, which is what
	// these tools address. /tmp is not among them and would have been the easy
	// mistake: it is one of the four trees a sandbox may write, so a fixture
	// pointing at a temporary directory would be asserting that a legitimate
	// write is refused.
	for _, tc := range []struct {
		key, path, why string
	}{
		{"write-file/relative-escape", "../escape",
			"a relative path, which lands wherever the supervisor happens to be standing"},
		{"write-file/absolute-outside", "/etc/kelyfos-hostile-probe",
			"an absolute path outside every tree a sandbox may write"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			arg, err := json.Marshal(map[string]string{"path": tc.path, "content": "owned by the guest\n"})
			if err != nil {
				t.Fatal(err)
			}
			res := toolWriteFile(json.RawMessage(arg))

			problem := ""
			if res != nil && !res.IsError {
				problem = fmt.Sprintf("%s: write_file accepted %q", tc.why, tc.path)
			}
			if got, err := os.ReadFile(tc.path); err == nil && strings.Contains(string(got), "owned by the guest") {
				problem = fmt.Sprintf("%s: the guest's bytes are at %s", tc.why, tc.path)
			}
			hostile.Holds(t, tc.key, problem)
		})
	}
}

// H-1. The block devices are the ones the profile withholds writes on from
// every confined child, and the tools that run unconfined will open them.
//
// The fixture does not write to a real disk — that would damage the machine
// running the tests, and a corpus that has to be trusted not to is not a corpus
// anybody will run. It asks the narrower question the code can answer honestly:
// does anything refuse the path *before* it reaches the operating system? A
// tool that reaches open(2) on /dev/vdb has already lost, whatever open(2) then
// says on a laptop that has no such device.
func TestHostileWriteFileRefusesTheBlockDevicesBeforeOpening(t *testing.T) {
	hostileTempCwd(t)

	for _, dev := range []string{"/dev/vda", "/dev/vdb"} {
		t.Run(strings.TrimPrefix(strings.ReplaceAll(dev, "/", "-"), "-"), func(t *testing.T) {
			arg, err := json.Marshal(map[string]string{"path": dev, "content": "x"})
			if err != nil {
				t.Fatal(err)
			}
			res := toolWriteFile(json.RawMessage(arg))

			// The test cannot ask whether the disk was written: the machine
			// running it has no /dev/vdb, and one that did must not have this
			// test write to it. So it asks the question the code can answer on
			// any machine — did the tool refuse on its own account?
			//
			// An error is not enough. On a machine without the device, open(2)
			// returns ENOENT and the message names the path, which would let
			// "no such file or directory" pass for a refusal and make the
			// fixture green everywhere except where it matters. The refusal has
			// to state a reason of the tool's own.
			problem := ""
			switch text := resultText(res); {
			case res == nil || !res.IsError:
				problem = fmt.Sprintf("write_file did not refuse %s", dev)
			case !mentionsAny(text, "not allowed", "outside", "refuse", "device", "block"):
				problem = fmt.Sprintf("write_file failed on %s, but from the operating system rather than"+
					" from a rule of its own: %q", dev, text)
			}
			hostile.Holds(t, "write-file/block-device", problem)
		})
	}
}

// F1. A symlink planted inside a tree the sandbox may write, pointing at
// something it may not, was a way around every check above: the tree check's
// prefix comparison and write_file's own os.WriteFile both take the name at
// face value and let open(2) resolve it. Creating the symlink costs a confined
// exec nothing beyond what it already has — LANDLOCK_ACCESS_FS_MAKE_SYM is
// granted on every tree write is — so "ln -s /dev/vda /work/escape" followed
// by write_file("/work/escape", …) reached the raw disk behind the read-only
// root without ever naming it.
//
// /dev/vda itself is not the target here, on purpose: this process runs
// unconfined, the same way the supervisor does, so a bug in the fix would make
// the write actually land rather than merely fail differently, and a fixture
// that can reach the disk behind the guest's own root filesystem is not one to
// run on a shared machine. /var/tmp stands in for it — outside every tree
// writableEverywhere lists, and safe to lose if the guard does not hold.
func TestHostileWriteFileRefusesASymlinkPlantedInsideAWritableTree(t *testing.T) {
	hostileTempCwd(t)

	victimDir, err := os.MkdirTemp("/var/tmp", "kelyfos-hostile-symlink-victim-*")
	if err != nil {
		t.Fatalf("could not stage the escape target under /var/tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(victimDir) })
	victim := filepath.Join(victimDir, "owned")

	// /tmp is one of the trees writableEverywhere names, so a write that lands
	// beneath it — rather than through the symlink planted in it — is the
	// ordinary, permitted case this fixture must not also break.
	writableDir, err := os.MkdirTemp("/tmp", "kelyfos-hostile-symlink-tree-*")
	if err != nil {
		t.Fatalf("could not stage the writable tree under /tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(writableDir) })
	escape := filepath.Join(writableDir, "escape")
	if err := os.Symlink(victim, escape); err != nil {
		t.Fatalf("could not plant the symlink: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func(path string) *mcp.CallToolResult
	}{
		{"write_file", func(path string) *mcp.CallToolResult {
			arg, err := json.Marshal(map[string]string{"path": path, "content": "owned by the guest\n"})
			if err != nil {
				t.Fatal(err)
			}
			return toolWriteFile(json.RawMessage(arg))
		}},
		{"upload", func(path string) *mcp.CallToolResult {
			arg, err := json.Marshal(map[string]string{
				"path": path,
				"data": base64.StdEncoding.EncodeToString([]byte("owned by the guest\n")),
			})
			if err != nil {
				t.Fatal(err)
			}
			return toolUpload(json.RawMessage(arg))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.call(escape)

			problem := ""
			switch text := resultText(res); {
			case res == nil || !res.IsError:
				problem = fmt.Sprintf("%s wrote through the symlink at %s instead of refusing it", tc.name, escape)
			case !mentionsAny(text, "symlink"):
				problem = fmt.Sprintf("%s refused %s, but not because it is a symlink: %q", tc.name, escape, text)
			}
			if got, err := os.ReadFile(victim); err == nil && strings.Contains(string(got), "owned by the guest") {
				problem = fmt.Sprintf("%s: the guest's bytes reached %s, through the symlink at %s",
					tc.name, victim, escape)
			}
			hostile.Holds(t, "write-file/symlink-escape-"+tc.name, problem)
		})
	}
}

// Reading is deliberately NOT confined, and this is the guard that says so.
//
// The corpus first carried a case asserting that read_file could not reach
// outside a tree. That was wrong, and it was wrong in the way this project
// treats as worse than a missing test: it asserted a boundary the product never
// claimed. The profile grants read beneath / to every confined child —
// allowBeneath(rules, "/", readRights) — so anything read_file reaches, a
// spawned process reaches too, and restricting it would make the tool weaker
// than the thing it serves while closing nothing.
//
// What is left is a guard in the other direction: reads keep working. Somebody
// tightening write_file could easily tighten read_file beside it and break
// reading /etc/os-release and /proc, which is how an agent learns what machine
// it is on.
func TestReadingIsNotConfinedAndMustKeepWorking(t *testing.T) {
	root := hostileTempCwd(t)
	readable := filepath.Join(root, "outside-every-writable-tree")
	const contents = "the guest may read this\n"
	if err := os.WriteFile(readable, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	arg, err := json.Marshal(map[string]string{"path": readable})
	if err != nil {
		t.Fatal(err)
	}
	res := toolReadFile(json.RawMessage(arg))
	if res != nil && res.IsError {
		t.Errorf("read_file was confined to the writable trees; the profile does not confine reads, "+
			"and this breaks reading /etc/os-release and /proc: %s", resultText(res))
	}
	if !mentions(resultText(res), "the guest may read this") {
		t.Errorf("read_file did not return the file's contents: %s", resultText(res))
	}
}

func resultText(res any) string {
	b, err := json.Marshal(res)
	if err != nil {
		return ""
	}
	return string(b)
}

func mentions(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func mentionsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if mentions(haystack, n) {
			return true
		}
	}
	return false
}
