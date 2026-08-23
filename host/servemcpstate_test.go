package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// The state tools are the ones that can create a machine out of something that
// was frozen under different rules, so most of what is worth testing here is
// what they refuse. None of these tests boots anything: every refusal below
// happens before a machine is built, which is the point of putting it there.

// writeSnapshot puts a snapshot's metadata where the tools will look for it,
// under a cache root belonging to this test alone.
func writeSnapshot(t *testing.T, name string, meta sandbox.SnapshotMeta) {
	t.Helper()
	if err := sandbox.WriteSnapshotMeta(mkdirSnapshot(t, name), meta); err != nil {
		t.Fatal(err)
	}
}

func mkdirSnapshot(t *testing.T, name string) string {
	t.Helper()
	dir := snapshotDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A snapshot name becomes a directory, and this one arrives from a model.
func TestSnapshotNamesCannotWalkOut(t *testing.T) {
	for _, bad := range []string{"", "..", "../evil", "a/b", "/etc/passwd", ".hidden",
		strings.Repeat("x", 65), "with space", "semi;colon"} {
		if err := validSnapshotName(bad); err == nil {
			t.Errorf("%q was accepted as a snapshot name", bad)
		}
	}
	for _, good := range []string{"default", "before-the-migration", "v1.2_final", "a"} {
		if err := validSnapshotName(good); err != nil {
			t.Errorf("%q is a reasonable name and was refused: %v", good, err)
		}
	}
}

// P3-2's rule reaches this door unchanged, and says so rather than producing N
// machines that each believe they are the same host.
func TestForkRefusesANetworkedSnapshot(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	writeSnapshot(t, "netty", sandbox.SnapshotMeta{
		Arch: "x86_64", Flavor: "dev", VcpuCount: 2, MemMiB: 512,
		HasNetwork: true, Allow: []string{"example.com"},
	})
	res := s.toolFork(json.RawMessage(`{"name":"netty","count":2}`))
	if !res.IsError {
		t.Fatal("a networked snapshot was forked")
	}
	for _, want := range []string{"vsock-only", "sandbox_restore", "example.com"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.Content[0].Text)
		}
	}
}

// The fleet limit is checked against the whole ask, not one machine at a time:
// finding out at fork three of five is finding out too late.
func TestForkCountMustFitTheLimit(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	writeSnapshot(t, "quiet", sandbox.SnapshotMeta{Arch: "x86_64", Flavor: "dev", VcpuCount: 2, MemMiB: 512})
	res := s.toolFork(json.RawMessage(`{"name":"quiet","count":99}`))
	if !res.IsError {
		t.Fatal("99 forks were accepted under a limit of 4")
	}
	if !strings.Contains(res.Content[0].Text, "max_sandboxes") {
		t.Errorf("the refusal does not name the limit:\n%s", res.Content[0].Text)
	}
	if res := s.toolFork(json.RawMessage(`{"name":"quiet","count":0}`)); !res.IsError {
		t.Error("a fork of zero machines was accepted")
	}
}

func TestForkNeedsASnapshotThatExists(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	res := s.toolFork(json.RawMessage(`{"name":"never-taken","count":1}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "never-taken") {
		t.Errorf("a missing snapshot did not say so:\n%s", res.Content[0].Text)
	}
}

// A restore may narrow what the frozen machine could reach and never widen it —
// not past the snapshot's own list, and not past the project's.
func TestRestoreAllowHasTwoCeilings(t *testing.T) {
	s := serverWith(t, policy) // permits api.github.com, example.com
	frozen := &sandbox.SnapshotMeta{HasNetwork: true, Allow: []string{"example.com"}}

	if got, err := s.restoreAllow("snap", nil, frozen); err != nil {
		t.Errorf("the snapshot's own list was refused: %v", err)
	} else if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("allow = %v, want the snapshot's own list", got)
	}

	// api.github.com is in the policy but was not in the frozen machine's list.
	_, err := s.restoreAllow("snap", []string{"api.github.com"}, frozen)
	if err == nil {
		t.Fatal("a restore widened the frozen machine's allowlist")
	}
	if !strings.Contains(err.Error(), "never widen") {
		t.Errorf("the refusal does not say what the rule is:\n%v", err)
	}

	// And a snapshot taken under some other policy does not bring its own
	// permission with it.
	wide := &sandbox.SnapshotMeta{HasNetwork: true, Allow: []string{"evil.example.net"}}
	_, err = s.restoreAllow("snap", nil, wide)
	if err == nil {
		t.Fatal("a snapshot's allowlist outranked the project's")
	}
	for _, want := range []string{"evil.example.net", "kelyfos.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// Firecracker takes vcpu and memory from the state file, so a restore cannot
// shrink a machine to fit a ceiling. The only honest answers are to allow it or
// to refuse it, and an unknown size is refused.
func TestRestoreHoldsAFrozenMachineToTheCeiling(t *testing.T) {
	s := serverWith(t, policy) // cpus = 2, mem = 512M

	if err := s.checkSnapshotFits("ok", &sandbox.SnapshotMeta{VcpuCount: 2, MemMiB: 512}); err != nil {
		t.Errorf("a machine exactly at the ceiling was refused: %v", err)
	}
	big := &sandbox.SnapshotMeta{VcpuCount: 8, MemMiB: 512}
	err := s.checkSnapshotFits("big", big)
	if err == nil {
		t.Fatal("an 8 vcpu machine was restored under a 2 vcpu ceiling")
	}
	for _, want := range []string{"8 vcpu", "cpus = 2", "kelyfos.toml:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if err := s.checkSnapshotFits("fat", &sandbox.SnapshotMeta{VcpuCount: 1, MemMiB: 4096}); err == nil {
		t.Error("a 4 GiB machine was restored under a 512 MiB ceiling")
	}

	// An older snapshot does not say how large it is, and a ceiling cannot be
	// checked against nothing.
	err = s.checkSnapshotFits("ancient", &sandbox.SnapshotMeta{})
	if err == nil {
		t.Fatal("a snapshot of unknown size was waved through a ceiling")
	}
	if !strings.Contains(err.Error(), "take the snapshot again") {
		t.Errorf("the refusal does not say how to fix it:\n%v", err)
	}

	// With no ceiling set there is nothing to check and nothing to refuse.
	none := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	if err := none.checkSnapshotFits("ancient", &sandbox.SnapshotMeta{}); err != nil {
		t.Errorf("with no policy there is no ceiling, but: %v", err)
	}
}

// Every tool that acts on one machine has to be told which, for the reason
// sandbox_exec is: there is no "current" sandbox to guess at.
func TestStateAndFileToolsNeedASandbox(t *testing.T) {
	s := serverWith(t, policy)
	for _, tc := range []struct {
		name string
		res  *mcp.CallToolResult
	}{
		{"sandbox_read_file", s.toolReadFile(json.RawMessage(`{"path":"/etc/hostname"}`))},
		{"sandbox_write_file", s.toolWriteFile(json.RawMessage(`{"path":"/tmp/x","content":"hi"}`))},
		{"sandbox_snapshot", s.toolSnapshot(json.RawMessage(`{"name":"whatever"}`))},
	} {
		if !tc.res.IsError {
			t.Errorf("%s ran without a sandbox id", tc.name)
			continue
		}
		if !strings.Contains(tc.res.Content[0].Text, "sandbox") {
			t.Errorf("%s does not say what is missing: %s", tc.name, tc.res.Content[0].Text)
		}
	}
}
