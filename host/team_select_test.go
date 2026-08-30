package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// Which team a command means, now that more than one can be running (P7-16,
// D79). The rule is sandbox.Load's, one level up: the only one, and a refusal
// that lists rather than a guess.
//
// These drive selectTeam directly because it is the whole decision — `team ps`,
// `team down` and the two serve-mcp doors each ask it exactly once and do as
// they are told.
func TestSelectTeamNamesOneOrRefusesToGuess(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())

	if _, err := selectTeam(""); err == nil || !strings.Contains(err.Error(), "no team is running") {
		t.Fatalf("with nothing running, selectTeam said: %v", err)
	}

	// One team, which is the common case and must read exactly as it always
	// did: no flag, no ambiguity, no mention of any of this.
	writeTeamState(t, teamState{Name: "solo", Session: "0901977d", PID: os.Getpid(), Owner: ownerCLI})
	st, err := selectTeam("")
	if err != nil {
		t.Fatalf("one team running and selectTeam refused: %v", err)
	}
	if st.Name != "solo" {
		t.Fatalf("selectTeam picked %q, want solo", st.Name)
	}

	// A second team, differently named. Neither is the obvious one, so nothing
	// is picked and the refusal is the roster.
	writeTeamState(t, teamState{Name: "other", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})
	_, err = selectTeam("")
	if err == nil {
		t.Fatal("two teams running and selectTeam picked one anyway")
	}
	for _, want := range []string{"--team", "solo", "other", "0901977d", "3f9a1c22"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// Named, either way round.
	if st, err := selectTeam("other"); err != nil || st.Session != "3f9a1c22" {
		t.Errorf("selectTeam(\"other\") = %v, %v", st, err)
	}
	if st, err := selectTeam("0901977d"); err != nil || st.Name != "solo" {
		t.Errorf("selectTeam by session id = %v, %v", st, err)
	}
	if _, err := selectTeam("nobody"); err == nil || !strings.Contains(err.Error(), "no running team is called") {
		t.Errorf("an unknown name was not refused by name: %v", err)
	}
}

// Two worktrees of one project raise two teams with one name — which is the
// reproduction P7-16 was opened on, so the name alone cannot be the answer.
func TestSelectTeamSeparatesTwoTeamsOfOneName(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "review", Session: "0901977d", PID: os.Getpid(), Owner: ownerCLI})
	writeTeamState(t, teamState{Name: "review", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})

	_, err := selectTeam("review")
	if err == nil {
		t.Fatal("two teams of one name and the name picked one of them")
	}
	for _, want := range []string{"session id", "0901977d", "3f9a1c22"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if st, err := selectTeam("3f9a1c22"); err != nil || st.Session != "3f9a1c22" {
		t.Errorf("the session id did not separate them: %v, %v", st, err)
	}
}

// A crashed team leaves its file behind, and its machines may still be up — so
// the file is not deleted out from under an operator. What it must not do is
// make a live team ambiguous, which is the whole reason liveness is consulted
// at all.
func TestACrashedTeamDoesNotMakeALiveOneAmbiguous(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	// PID 0 is never a process; teamProcessAlive refuses it without signalling
	// anything, which is what makes this safe to assert in a unit test.
	writeTeamState(t, teamState{Name: "crashed", Session: "0901977d", PID: 0, Owner: ownerCLI})
	writeTeamState(t, teamState{Name: "held", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})

	st, err := selectTeam("")
	if err != nil {
		t.Fatalf("a leftover file made the one live team ambiguous: %v", err)
	}
	if st.Name != "held" {
		t.Fatalf("selectTeam picked %q, want the live team", st.Name)
	}

	// It is still nameable, because `team down` on it is how it gets cleared.
	if st, err := selectTeam("crashed"); err != nil || st.Session != "0901977d" {
		t.Errorf("the crashed team could not be named: %v, %v", st, err)
	}
	// And it is still listed, said to be gone rather than quietly dropped.
	teams, bad, err := liveTeams()
	if err != nil || len(teams) != 2 || len(bad) != 0 {
		t.Fatalf("liveTeams() = %d teams, %d unreadable, %v; want both and none",
			len(teams), len(bad), err)
	}
	if !strings.Contains(teamRoster(teams), "its process is gone") {
		t.Errorf("the roster does not say which team nobody is holding:\n%s", teamRoster(teams))
	}
}

// The flag reaches the decision. `team down` in particular must never signal a
// process on a guess.
func TestTeamDownRefusesToGuessBetweenTeams(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "a", Session: "0901977d", PID: os.Getpid(), Owner: ownerCLI})
	writeTeamState(t, teamState{Name: "b", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})

	err := teamDown(nil)
	if err == nil {
		t.Fatal("`team down` with two teams up signalled something")
	}
	if !strings.Contains(err.Error(), "--team") {
		t.Errorf("the refusal does not say how to name one:\n%v", err)
	}
	// Named, it gets as far as the owner check rather than the ambiguity one —
	// which is what says the flag reached selectTeam.
	writeTeamState(t, teamState{Name: "served", Session: "beefcafe",
		PID: os.Getpid(), Owner: ownerServeMCP})
	err = teamDown([]string{"--team", "served"})
	if err == nil || !strings.Contains(err.Error(), "serve-mcp") {
		t.Errorf("--team did not select the named team: %v", err)
	}
}

// A team's state file is rewritten every time an agent joins or leaves, and a
// `team ps` beside it is a reader. os.WriteFile truncates and then writes, so a
// reader landing in that window got a parse error on a file that is good a
// millisecond later — a flake nobody can reproduce on demand, and one that only
// became reachable once two teams on a host were ordinary. The write publishes
// by rename instead.
//
// The concurrent half of this is a smoke test and is honest about it: rename
// makes the window not exist, so a loop cannot prove its absence, only fail to
// find it. What is deterministic is the second half — the temporary file is
// dot-prefixed, liveTeams skips it, and nothing is left behind.
func TestATeamStateIsPublishedWhole(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	r := &roster{plan: &teamPlan{name: "busy"}, session: "0901977d", owner: ownerCLI}
	if err := r.write(); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			r.add(&agentRig{name: "w", sb: &sandbox.Sandbox{}}, "busy -> w")
			_ = r.write()
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	reads := 0
loop:
	for time.Now().Before(deadline) {
		if _, err := teamStateOf(r.session); err != nil {
			t.Fatalf("a reader could not read a live team's state: %v", err)
		}
		reads++
		// Every team on the host, which is the path `team ps` and `team down`
		// take: a temporary file left in this directory would be a second team
		// as far as either of them is concerned.
		teams, bad, err := liveTeams()
		if err != nil || len(bad) != 0 {
			t.Fatalf("liveTeams: %d unreadable, %v", len(bad), err)
		}
		if len(teams) != 1 {
			t.Fatalf("a rewrite made this host hold %d teams", len(teams))
		}
		select {
		case <-done:
			break loop
		default:
		}
	}
	<-done
	if reads == 0 {
		t.Fatal("the reader never ran")
	}

	entries, err := os.ReadDir(teamStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "0901977d.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the state directory holds %v, want one file named for the session", names)
	}
}

// A directory shared between teams is where this fix could have re-created the
// defect it exists to close. A file that will not parse is somebody's problem,
// and the question is whose.
//
// Refusing every answer because a stranger's file is damaged would mean one
// broken team stops the others from being stopped, which is the collision one
// layer out. Skipping it silently is the other wrong answer: if the damaged
// file is your own team's, an unqualified `team ps` would then confidently
// describe somebody else's team as yours. So an unqualified question is refused
// while any file is unreadable, and a named one is answered.
func TestAnUnreadableTeamFileNeitherHidesNorBlocksTheOthers(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "held", Session: "3f9a1c22", PID: os.Getpid(), Owner: ownerCLI})
	if err := os.WriteFile(filepath.Join(teamStateDir(), "0901977d.json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	teams, bad, err := liveTeams()
	if err != nil {
		t.Fatalf("one damaged file made the whole directory unreadable: %v", err)
	}
	if len(teams) != 1 || len(bad) != 1 {
		t.Fatalf("liveTeams() = %d teams, %d unreadable; want 1 and 1", len(teams), len(bad))
	}

	// Unqualified: refused, and it says what it could not read.
	_, err = selectTeam("")
	if err == nil {
		t.Fatal("an unqualified `team ps` answered while a state file was unreadable")
	}
	for _, want := range []string{"cannot be read", "--team", "0901977d.json", "held"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// Named: answered. A damaged file belonging to somebody else must not stop
	// this team being read or stopped.
	st, err := selectTeam("held")
	if err != nil || st.Session != "3f9a1c22" {
		t.Fatalf("a named team could not be selected past a damaged file: %v, %v", st, err)
	}

	// And a name that matches nothing says both things: what is running, and
	// what could not be read.
	_, err = selectTeam("nobody")
	if err == nil || !strings.Contains(err.Error(), "0901977d.json") {
		t.Errorf("a miss does not name the unreadable file:\n%v", err)
	}
}
