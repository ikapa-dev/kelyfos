package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// P7-16 (D70, D79): two teams on one host used to share one state file.
//
// `run/team.json` was a single path, and `raiseTeam` refused to start when it
// existed — a Stat taken tens of seconds before the matching write, so two
// `kelyfos team up` invocations that both passed it went on to boot, and the
// second's write replaced the first's state. After that `team ps` described the
// wrong team, `team down` signalled the wrong process, and the first team's own
// teardown deleted the second team's file. Two adversarial reviews in separate
// worktrees on one development VM hit it unprompted, and one of them restored
// the file by hand.
//
// This is deliberately written against the *state a team leaves on this host*
// rather than against the function that names the path, so that it compiles and
// runs on the parent commit as well as on this one — which is how it was proven
// to fail there rather than asserted to.
func TestTwoTeamsOnOneHostDoNotShareOneStateFile(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())

	alpha := &roster{plan: &teamPlan{name: "review-a"}, session: "0901977d", owner: ownerCLI}
	// The same name, because that is the reproduction: two checkouts of one
	// project, whose kelyfos.toml names the team once.
	beta := &roster{plan: &teamPlan{name: "review-a"}, session: "3f9a1c22", owner: ownerCLI}

	if err := alpha.write(); err != nil {
		t.Fatalf("the first team could not record itself: %v", err)
	}
	if got := stateOfSession(t, alpha.session); got == nil {
		t.Fatal("the first team recorded nothing at all")
	}

	// The second team comes up beside the first. Nothing about the first has
	// changed, so everything this host knows about it must still be there.
	if err := beta.write(); err != nil {
		t.Fatalf("the second team could not record itself: %v", err)
	}
	first := stateOfSession(t, alpha.session)
	if first == nil {
		t.Fatal("a second team came up and the first team's state was gone: " +
			"`team ps` now describes the wrong team and `team down` signals the wrong process")
	}
	if first.Session != alpha.session || first.PID != os.Getpid() {
		t.Fatalf("the first team's state is not the first team's: %+v", first)
	}
	second := stateOfSession(t, beta.session)
	if second == nil {
		t.Fatal("the second team recorded nothing this host can find")
	}

	// And the other direction: one team's teardown removes one team's file.
	path := statePathOfSession(t, beta.session)
	if path == "" {
		t.Fatal("the second team's state file cannot be located to remove")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := stateOfSession(t, alpha.session); got == nil {
		t.Fatal("tearing the second team down took the first team's state with it")
	}
	if got := stateOfSession(t, beta.session); got != nil {
		t.Fatalf("the torn-down team is still on this host: %+v", got)
	}
}

// stateOfSession is what this host knows about one team, found by searching
// rather than by naming a path.
//
// The search is the point. This test has to run against the commit before the
// fix, where every team's state is one file at run/team.json, and against this
// one, where it is run/teams/<session>.json — so it asks the question the
// product asks ("what does this host hold for this team") instead of the
// question the layout answers.
func stateOfSession(t *testing.T, session string) *teamState {
	t.Helper()
	path := statePathOfSession(t, session)
	if path == "" {
		return nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st teamState
	if json.Unmarshal(blob, &st) != nil {
		return nil
	}
	return &st
}

func statePathOfSession(t *testing.T, session string) string {
	t.Helper()
	var found string
	root := filepath.Join(sandbox.Root(), "run")
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		blob, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var st teamState
		if json.Unmarshal(blob, &st) != nil {
			return nil
		}
		if st.Session == session {
			found = path
		}
		return nil
	})
	return found
}
