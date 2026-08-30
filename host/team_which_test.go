package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Everything downstream of selectTeam (P7-16, D79).
//
// These exist because an adversarial review mutation-tested the fix and found
// five call sites where reverting the change broke nothing: `team down`
// clearing its own state file, serve-mcp's `team_ps` and `team_up` answering
// about the team that server raised, `teamMemberHint` searching every team, and
// `kelyfos watch`'s lane sampling the session it is tailing. selectTeam itself
// was well covered and every one of its own mutations went red; the gap was
// entirely on the far side of it. A test that passes whether or not the code is
// right is worse than no test, and five of them is a fix nobody is checking.
//
// Each of these was written by breaking the production line it names and
// confirming it goes red before it was allowed to go green.

// deadPID is a process id that certainly exists in no process table: a child
// this test started and reaped. Made rather than guessed, because a number
// picked out of the air is one the kernel may have handed to somebody by the
// time the test runs — and this one is handed to syscall.Kill.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a child to take a pid from: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	return pid
}

// `team down` on a team whose process is gone clears THAT team's state, and
// nothing else's. The removal is the one line that reaches into the shared
// directory with an effect, and it takes the path from a file's own contents.
func TestTeamDownClearsItsOwnStateAndNoOtherTeams(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	gone := deadPID(t)
	writeTeamState(t, teamState{Name: "crashed", Session: "0901977d", PID: gone, Owner: ownerCLI})
	writeTeamState(t, teamState{Name: "held", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})

	// Named, because with two teams up `team down` refuses to guess — which is
	// its own assertion, in TestTeamDownRefusesToGuessBetweenTeams.
	err := teamDown([]string{"--team", "crashed"})
	if err == nil || !strings.Contains(err.Error(), "is gone") {
		t.Fatalf("`team down` on a team whose process is gone said: %v", err)
	}
	if _, serr := os.Stat(teamStatePathFor("0901977d")); !os.IsNotExist(serr) {
		t.Error("the crashed team's own state file was not cleared")
	}
	if _, serr := os.Stat(teamStatePathFor("3f9a1c22")); serr != nil {
		t.Errorf("clearing one team's state removed another team's: %v", serr)
	}
	st, serr := selectTeam("")
	if serr != nil || st.Name != "held" {
		t.Errorf("after clearing the crashed team, the live one is not the only one: %v, %v", st, serr)
	}
}

// `kelyfos team down` with no --team must not resolve past an ambiguous roster
// by liveness, however tempting: the failure it would buy is stopping five
// machines somebody else raised, with no undo and no warning beyond a line
// naming a team you did not start.
//
// This is the difference between selectTeam and selectTeamToStop, so it is
// asserted as a difference rather than as one function's behaviour.
func TestOnlyAReadNarrowsToTheLiveTeam(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	gone := deadPID(t)
	writeTeamState(t, teamState{Name: "mine-crashed", Session: "0901977d", PID: gone, Owner: ownerCLI})
	writeTeamState(t, teamState{Name: "theirs", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})

	// A read may prefer the one team still being held.
	st, err := selectTeam("")
	if err != nil || st.Name != "theirs" {
		t.Fatalf("a read did not narrow to the live team: %v, %v", st, err)
	}
	// A stop may not.
	if _, err := selectTeamToStop(""); err == nil {
		t.Fatal("`team down` with no --team picked a team out of an ambiguous roster")
	} else {
		for _, want := range []string{"--team", "mine-crashed", "theirs", "0901977d", "3f9a1c22"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q:\n%v", want, err)
			}
		}
	}
	// And through the command itself, which is where it matters: nothing is
	// signalled and nothing is cleared.
	if err := teamDown(nil); err == nil || !strings.Contains(err.Error(), "--team") {
		t.Errorf("`team down` did not refuse: %v", err)
	}
	for _, id := range []string{"0901977d", "3f9a1c22"} {
		if _, serr := os.Stat(teamStatePathFor(id)); serr != nil {
			t.Errorf("a refused `team down` removed %s: %v", id, serr)
		}
	}
}

// serve-mcp answers about the team THAT SERVER raised. Falling through to "the
// team running on this host" would report a stranger's roster — agent names,
// sandbox ids, allowlists — as this server's own, the moment a second team
// appears, which is now an ordinary state rather than a refused one.
func TestServeMCPAnswersAboutItsOwnTeam(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "ours", Session: "0901977d",
		PID: os.Getpid(), Owner: ownerServeMCP})
	writeTeamState(t, teamState{Name: "a-strangers", Session: "3f9a1c22",
		PID: os.Getpid(), Owner: ownerCLI})

	s := serverWith(t, policy)
	s.team = &teamRig{session: "0901977d"}

	st, err := s.ownTeamState()
	if err != nil || st.Name != "ours" {
		t.Fatalf("the server did not answer about its own team: %v, %v", st, err)
	}
	res := s.toolTeamPS()
	if res.IsError {
		t.Fatalf("team_ps failed: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, "ours") {
		t.Errorf("team_ps does not name this server's team:\n%s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "a-strangers") {
		t.Errorf("team_ps reported a team this server did not raise:\n%s", res.Content[0].Text)
	}
	sc, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("team_ps returned no structured content: %T", res.StructuredContent)
	}
	if got := sc["team"]; got != "ours" {
		t.Errorf("structuredContent names team %v, want ours", got)
	}

	// With no team of its own the fallback stands, and with two on the host it
	// names them rather than picking one — which is what docs/mcp-surface.md
	// says and what the tool description promises.
	s.team = nil
	res = s.toolTeamPS()
	if !res.IsError {
		t.Fatalf("a server with no team of its own picked one of two:\n%s", res.Content[0].Text)
	}
	for _, want := range []string{"ours", "a-strangers"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not list %q:\n%s", want, res.Content[0].Text)
		}
	}
}

// team_down through the server, when the server raised nothing: the teams on
// the host are named rather than acted on, and the one-team message keeps the
// name and pid it always carried.
func TestServeMCPTeamDownNamesTheTeamsItWillNotStop(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "first", Session: "0901977d", PID: 424242, Owner: ownerCLI})
	writeTeamState(t, teamState{Name: "second", Session: "3f9a1c22", PID: 424243, Owner: ownerCLI})

	s := serverWith(t, policy)
	res := s.toolTeamDown()
	if !res.IsError {
		t.Fatal("a server that raised no team retired one anyway")
	}
	for _, want := range []string{"first", "second", "0901977d", "3f9a1c22", "--team"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.Content[0].Text)
		}
	}
	// Nothing was cleared by a refusal.
	for _, id := range []string{"0901977d", "3f9a1c22"} {
		if _, err := os.Stat(teamStatePathFor(id)); err != nil {
			t.Errorf("a refused team_down removed %s: %v", id, err)
		}
	}
}

// An id handed to a sandbox tool belongs to whichever team owns it, and saying
// "no such machine" because a stranger's team owns it is the refusal this hint
// exists to replace.
func TestTeamMemberHintReachesEveryTeamOnTheHost(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	agent := func(name, sb string) struct {
		Name    string `json:"name"`
		Sandbox string `json:"sandbox"`
		Via     string `json:"via,omitempty"`
	} {
		return struct {
			Name    string `json:"name"`
			Sandbox string `json:"sandbox"`
			Via     string `json:"via,omitempty"`
		}{name, sb, "cold"}
	}
	first := teamState{Name: "first", Session: "0901977d", PID: os.Getpid(), Owner: ownerCLI}
	first.Agents = append(first.Agents, agent("master", "aaaaaaaa"))
	second := teamState{Name: "second", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI}
	second.Agents = append(second.Agents, agent("worker", "bbbbbbbb"))
	writeTeamState(t, first)
	writeTeamState(t, second)

	// The second team's machine: a search that stopped at "the running team"
	// would find nothing for it.
	hint := teamMemberHint("bbbbbbbb")
	if !strings.Contains(hint, "worker") || !strings.Contains(hint, "second") {
		t.Errorf("the hint does not name the agent and its team:\n%s", hint)
	}
	if h := teamMemberHint("aaaaaaaa"); !strings.Contains(h, "first") {
		t.Errorf("the hint does not reach the first team either:\n%s", h)
	}
	if h := teamMemberHint("cccccccc"); h != "" {
		t.Errorf("an id belonging to no team produced a hint: %s", h)
	}
}

// `kelyfos watch` samples the team whose chain it is tailing. Asking the host
// which team is running would put a stranger's cgroup and a stranger's machines
// into this session's own lanes the moment a second team came up.
func TestWatchSamplesTheTeamItIsTailing(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "watched", Session: "0901977d",
		PID: os.Getpid(), Owner: ownerCLI, CGroup: "/sys/fs/cgroup/watched", CPUQuota: 100})
	writeTeamState(t, teamState{Name: "other", Session: "3f9a1c22",
		PID: os.Getpid(), Owner: ownerCLI, CGroup: "/sys/fs/cgroup/other", CPUQuota: 400})

	msg, ok := sampleTeam("0901977d")().(teamUsageMsg)
	if !ok {
		t.Fatal("sampling the watched team produced no usage message")
	}
	if msg.cgroup != "/sys/fs/cgroup/watched" || msg.quota != 100 {
		t.Fatalf("the lane sampled cgroup %q quota %d — that is the other team's",
			msg.cgroup, msg.quota)
	}
	// And the other one, so the test cannot pass by always reading the first
	// file in the directory.
	msg, ok = sampleTeam("3f9a1c22")().(teamUsageMsg)
	if !ok {
		t.Fatal("sampling the second team produced no usage message")
	}
	if msg.cgroup != "/sys/fs/cgroup/other" || msg.quota != 400 {
		t.Fatalf("the lane sampled cgroup %q quota %d for the second team", msg.cgroup, msg.quota)
	}
	// A team that has stopped has no state file, and the lane falls back to the
	// chain rather than to somebody else's counters.
	if m := sampleTeam("deadbeef")(); m != nil {
		t.Errorf("a stopped team's lane sampled something: %v", m)
	}
}

// A file whose name and contents disagree is not a team. `team down` takes the
// path it removes and polls from the file's own `session` field, so a file that
// names another team's session would clear or wait on that team's path — and a
// crafted one would leave the directory entirely.
func TestAStateFileMustAgreeWithItsOwnName(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "real", Session: "0901977d", PID: os.Getpid(), Owner: ownerCLI})

	// A copy under another name — which is what restoring one by hand produces,
	// and D70's own report has a reviewer doing exactly that.
	blob, err := os.ReadFile(teamStatePathFor("0901977d"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(teamStatePathFor("backup1"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	teams, unusable, err := liveTeams()
	if err != nil {
		t.Fatalf("liveTeams: %v", err)
	}
	if len(teams) != 1 || teams[0].Session != "0901977d" {
		t.Fatalf("a copy of a state file became a second team: %d teams", len(teams))
	}
	if len(unusable) != 1 || !strings.Contains(unusable[0], "backup1") {
		t.Fatalf("the copy was not named as unusable: %v", unusable)
	}
	// The real team is still nameable past it.
	if st, err := selectTeam("real"); err != nil || st.Session != "0901977d" {
		t.Errorf("the real team could not be selected past the copy: %v, %v", st, err)
	}

	// And a session that would leave the directory is refused the same way,
	// rather than reaching os.Remove.
	escape := teamState{Name: "escape", Session: "../../../../tmp/kelyfos-escape",
		PID: os.Getpid(), Owner: ownerCLI}
	writeTeamStateAt(t, "innocent", escape)
	_, unusable, err = liveTeams()
	if err != nil {
		t.Fatalf("liveTeams: %v", err)
	}
	if len(unusable) != 2 {
		t.Fatalf("a state file naming a session outside this directory was accepted: %v", unusable)
	}
}
