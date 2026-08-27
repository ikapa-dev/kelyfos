package config

import "testing"

// Fuzz target for the policy parser (P6-3).
//
// `kelyfos.toml` is on the trust boundary for a reason the product's own design
// creates: the README tells you to commit it "the way you commit a
// .devcontainer", so a policy file arrives with a repository you cloned. Reading
// a stranger's project should not be able to crash the tool that is supposed to
// contain that stranger's code — and the file being parsed is the file that
// says what the sandbox is allowed to do.
//
// The parser is hand-rolled and deliberately small (F-D16), which is exactly the
// kind of parser worth fuzzing: no library is absorbing the malformed input on
// its behalf.

func FuzzConfigParse(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("[sandbox]\nimage = \"dev\"\n"))
	f.Add([]byte("image = \"dev\"\nallow = [\"github.com\"]\n"))
	f.Add([]byte("[resources]\ncpus = 2\nmem = \"2G\"\ncpu_quota = \"150%\"\nmax_runtime = \"30m\"\n"))
	f.Add([]byte("[team]\nname = \"t\"\n[[team.agent]]\nname = \"a\"\ncount = 4\n[[team.edge]]\nfrom = \"a\"\nto = \"a-*\"\n"))
	// F4: a count large enough that host/teamplan.go's expandCount would abort
	// the process allocating a slice with that capacity, before any topology or
	// budget check ran. count must be refused with this shape in the corpus, not
	// just in the unit test, because the fuzz harness is what would have caught
	// the missing ceiling in the first place.
	f.Add([]byte("[[team.agent]]\nname = \"a\"\ncount = 999999999999\n"))
	f.Add([]byte("[[plugin]]\nname = \"p\"\ncommand = \"x\"\n"))
	f.Add([]byte("[resources]\nmem = \"999999999999999999999G\"\n"))
	f.Add([]byte("[unclosed\n"))
	f.Add([]byte("= value\n"))
	f.Add([]byte("key =\n"))
	f.Add([]byte("[resources]\ncpus = -1\n"))
	f.Add([]byte("allow = [\n"))
	f.Add([]byte("# comment only\n"))
	f.Add([]byte("\x00\x00\x00\n"))

	f.Fuzz(func(t *testing.T, blob []byte) {
		cfg, err := parse(blob, "fuzz.toml")
		if err != nil {
			return
		}
		if cfg == nil {
			t.Fatal("parse returned no config and no error")
		}
		// A policy that parses must be one the rest of the product can reason
		// about. These are the invariants other packages take for granted
		// rather than re-check: a negative cap would be compared against a
		// requested value and silently win.
		if cfg.ResCPUs < 0 || cfg.ResMemMiB < 0 || cfg.ResDiskByte < 0 || cfg.ResScratchByte < 0 {
			t.Fatalf("accepted a negative resource ceiling: cpus=%d mem=%d disk=%d scratch=%d",
				cfg.ResCPUs, cfg.ResMemMiB, cfg.ResDiskByte, cfg.ResScratchByte)
		}
		if cfg.ResCPUQuota < 0 || cfg.ResNetMbpsRx < 0 || cfg.ResNetMbpsTx < 0 ||
			cfg.ResDiskIOPS < 0 || cfg.ResDiskMbps < 0 {
			t.Fatalf("accepted a negative rate or quota: quota=%d rx=%d tx=%d iops=%d mbps=%d",
				cfg.ResCPUQuota, cfg.ResNetMbpsRx, cfg.ResNetMbpsTx, cfg.ResDiskIOPS, cfg.ResDiskMbps)
		}
		if cfg.ResMaxRuntime < 0 {
			t.Fatalf("accepted a negative max_runtime: %v", cfg.ResMaxRuntime)
		}
		// F4: a parsed count past this ceiling is a config the rest of the
		// product cannot safely act on — host/teamplan.go's expandCount turns it
		// straight into a slice of that capacity before anything else runs.
		if cfg.Team != nil {
			for _, a := range cfg.Team.Agents {
				if a.Count > maxAgentCount {
					t.Fatalf("accepted count = %d, over the ceiling of %d", a.Count, maxAgentCount)
				}
			}
		}
	})
}
