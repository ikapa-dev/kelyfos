package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
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
	cases := []struct {
		key, path, why string
	}{
		{"write-file/relative-escape", "../escape",
			"a relative path climbing out of the working directory"},
		{"write-file/absolute-outside", "", // filled in below: a real path outside
			"an absolute path to somewhere the agent has no business"},
	}

	root := hostileTempCwd(t)
	// The second case needs a real location outside the working directory, and
	// a canary there so the test can tell "refused" from "wrote somewhere else".
	outside := filepath.Join(root, "outside.conf")
	if err := os.WriteFile(outside, []byte("the sandbox's own configuration\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases[1].path = outside

	for _, tc := range cases {
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

// H-1. Reading is the same absence, and it reaches further than the disks.
func TestHostileReadFileCannotReachTheWholeFilesystem(t *testing.T) {
	root := hostileTempCwd(t)
	secret := filepath.Join(root, "not-for-the-guest")
	const contents = "a host secret the sandbox was never given\n"
	if err := os.WriteFile(secret, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	arg, err := json.Marshal(map[string]string{"path": secret})
	if err != nil {
		t.Fatal(err)
	}
	res := toolReadFile(json.RawMessage(arg))

	problem := ""
	if res != nil && !res.IsError && mentions(resultText(res), "a host secret") {
		problem = fmt.Sprintf("read_file returned the contents of %s", secret)
	}
	hostile.Holds(t, "read-file/outside", problem)
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
