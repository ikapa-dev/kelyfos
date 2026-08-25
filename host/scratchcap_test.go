package main

import (
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
)

// A scratch cap larger than the machine's RAM is not a generous limit, it is no
// limit: the tmpfs it sizes lives in that same RAM and can never reach it.
// `kelyfos run` and the E2B shim have always refused it. A team and serve-mcp's
// sandbox_run accepted it, handed it to the machine, and produced exactly the
// inert cap the refusal exists to prevent — a file that says the agent is
// bounded and nothing bounding it (docs/resources.md).

func TestAnAgentsScratchMustFitInTheMachineItLivesIn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		res     config.AgentResources
		refused bool
	}{
		{"a scratch above the agent's mem", config.AgentResources{MemMiB: 512, ScratchByte: 2 << 30}, true},
		{"a scratch below it", config.AgentResources{MemMiB: 512, ScratchByte: 256 << 20}, false},
		// Exactly the machine's RAM is a cap that can be reached, if only just,
		// so it is a cap. The refusal is for the ones that cannot.
		{"a scratch of exactly mem", config.AgentResources{MemMiB: 512, ScratchByte: 512 << 20}, false},
		// An agent that wrote no `mem` still gets a machine, and the cap has to
		// be compared against that machine rather than against the zero that
		// means "the file said nothing" — in both directions.
		{"a scratch above the default mem", config.AgentResources{ScratchByte: 2 << 30}, true},
		{"a scratch below the default mem", config.AgentResources{ScratchByte: 64 << 20}, false},
		{"no scratch at all", config.AgentResources{MemMiB: 512}, false},
	} {
		err := scratchWithinMem("agent worker", tc.res)
		switch {
		case tc.refused && err == nil:
			t.Errorf("%s: accepted, and it is a cap that can never be reached", tc.name)
		case !tc.refused && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.refused:
			for _, want := range []string{"worker", "can never be reached"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: the refusal does not mention %q:\n%v", tc.name, want, err)
				}
			}
		}
	}
}

// A budget's caps are as much a limit as an agent's own, and an inert one in a
// budget is worse for being discovered later — at the moment some agent decides
// to spawn a worker, rather than when the file was read.
func TestASpawnBudgetsScratchIsCheckedWithTheAgentThatCarriesIt(t *testing.T) {
	plan, err := planTeam(&config.Config{Path: "kelyfos.toml", Image: "dev",
		Team: &config.Team{
			Name: "t",
			Agents: []config.TeamAgent{{Name: "master", Count: 1,
				Spawn: &config.SpawnBudget{Max: 2, Images: []string{"dev"},
					Resources: config.AgentResources{MemMiB: 256, ScratchByte: 1 << 30}}}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	err = checkTeamScratch(plan)
	if err == nil {
		t.Fatal("a spawn budget whose scratch can never be reached was accepted")
	}
	if !strings.Contains(err.Error(), "spawn budget of master") {
		t.Errorf("the refusal does not say which budget it is:\n%v", err)
	}
}

// Through the door, because that is where it went wrong: the comparison existed
// and `team up` was simply not making it. Refused before the recorder is opened
// and before any machine starts, the way a bad `-p` is refused at the command
// line rather than after something is already running.
func TestTeamUpRefusesAnInertScratchBeforeAnythingBoots(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, `[sandbox]
image = "dev"

[team]
name = "inert"

[[team.agent]]
name = "worker"

  [team.agent.resources]
  mem     = "512M"
  scratch = "2G"
`)
	res := s.toolTeamUp()
	if !res.IsError {
		t.Fatal("a team whose scratch cap can never be reached was raised")
	}
	for _, want := range []string{"scratch", "worker", "512 MiB", "can never be reached"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.Content[0].Text)
		}
	}
	if _, err := readTeamState(); err == nil {
		t.Error("a refused team left a team.json behind, so something was raised after all")
	}
}

// sandbox_run is the other door that was not making the comparison, and the
// easiest one to reach it through: the project writes one `scratch` for a
// machine of the project's `mem`, and a call is allowed to ask for less memory
// than that.
func TestSandboxRunRefusesAScratchTheMachineCannotHold(t *testing.T) {
	const withScratch = `[sandbox]
image = "dev"

[resources]
cpus    = 2
mem     = "512M"
scratch = "512M"
`
	s := serverWith(t, withScratch)
	if _, err := s.resolve(&runArgs{}); err != nil {
		t.Fatalf("a scratch that fits the project's own mem was refused: %v", err)
	}
	_, err := s.resolve(&runArgs{Mem: "256M"})
	if err == nil {
		t.Fatal("a call narrowed mem below the project's scratch and got a cap that does nothing")
	}
	for _, want := range []string{"scratch", "kelyfos.toml:", "256 MiB", "can never be reached"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// And the plain case the command line has always refused, reached through
	// this door instead.
	s = serverWith(t, `[sandbox]
image = "dev"

[resources]
mem     = "512M"
scratch = "2G"
`)
	if _, err := s.resolve(&runArgs{}); err == nil {
		t.Error("a project whose scratch is larger than its mem was accepted here " +
			"and refused by `kelyfos run`")
	}
}
