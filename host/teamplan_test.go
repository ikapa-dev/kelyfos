package main

import (
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
)

func planFrom(t *testing.T, tm *config.Team) (*teamPlan, error) {
	t.Helper()
	return planTeam(&config.Config{Path: "kelyfos.toml", Image: "dev", Team: tm})
}

// count = 3 becomes three named agents before anything boots, so an edge to
// worker-* can be checked against names that exist.
func TestCountBecomesNamedAgentsBeforeAnythingBoots(t *testing.T) {
	plan, err := planFrom(t, &config.Team{
		Name: "reviewers",
		Agents: []config.TeamAgent{
			{Name: "master", Count: 1},
			{Name: "worker", Count: 3},
		},
		Edges: []config.TeamEdge{{From: "master", To: "worker-*", Bidirectional: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range plan.agents {
		names = append(names, a.name)
	}
	want := "master worker-1 worker-2 worker-3"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("agents = %q, want %q", got, want)
	}
	// A single agent keeps its bare name: "master-1" in a team with one master
	// is noise nobody asked for.
	if plan.agents[0].name != "master" {
		t.Errorf("a count of one was numbered: %q", plan.agents[0].name)
	}
	// The star resolved to pairs, which is what a reader of `ps` wants.
	if len(plan.edgeText) != 6 {
		t.Errorf("edges resolved to %d pairs, want 6: %v", len(plan.edgeText), plan.edgeText)
	}
}

// A typo in an edge is a refusal before any machine starts, not a message that
// mysteriously never arrives an hour in.
func TestAnEdgeToNowhereStopsTheTeamBeforeItBoots(t *testing.T) {
	_, err := planFrom(t, &config.Team{
		Name:   "t",
		Agents: []config.TeamAgent{{Name: "master", Count: 1}},
		Edges:  []config.TeamEdge{{From: "master", To: "wroker-*"}},
	})
	if err == nil {
		t.Fatal("a team with an edge to nowhere was planned successfully")
	}
	if !strings.Contains(err.Error(), "kelyfos.toml") {
		t.Errorf("the refusal does not name the file: %v", err)
	}
}

func TestATeamNeedsANameAndAtLeastOneAgent(t *testing.T) {
	if _, err := planFrom(t, &config.Team{Agents: []config.TeamAgent{{Name: "a", Count: 1}}}); err == nil {
		t.Error("a team with no name was accepted")
	}
	if _, err := planFrom(t, &config.Team{Name: "t"}); err == nil {
		t.Error("a team with no agents was accepted")
	}
}

func TestDuplicateAgentNamesAreRefused(t *testing.T) {
	_, err := planFrom(t, &config.Team{
		Name: "t",
		Agents: []config.TeamAgent{
			{Name: "worker", Count: 2},
			{Name: "worker-1", Count: 1},
		},
	})
	if err == nil {
		t.Error("a count group and a bare name collided without complaint")
	}
}

// An agent with no image of its own inherits the file's, and failing that the
// base flavor — the same defaulting a single run does.
func TestAgentImageDefaultsLikeARun(t *testing.T) {
	plan, err := planFrom(t, &config.Team{
		Name:   "t",
		Agents: []config.TeamAgent{{Name: "a", Count: 1}, {Name: "b", Count: 1, Image: "base"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.agents[0].image != "dev" {
		t.Errorf("agent a took image %q, want the file's dev", plan.agents[0].image)
	}
	if plan.agents[1].image != "base" {
		t.Errorf("agent b's own image was overridden: %q", plan.agents[1].image)
	}
}

// The store's rules are validated against the team that will use them, before
// anything boots.
func TestStoreRulesAreCheckedAtPlanTime(t *testing.T) {
	base := func(keys []config.TeamStoreKey) *config.Team {
		return &config.Team{
			Name:   "t",
			Agents: []config.TeamAgent{{Name: "master", Count: 1}, {Name: "worker", Count: 2}},
			Store:  &config.TeamStore{Enabled: true, Keys: keys},
		}
	}
	if _, err := planFrom(t, base([]config.TeamStoreKey{{Name: "k", Read: []string{"worker-*"}}})); err != nil {
		t.Errorf("a valid store rule was refused: %v", err)
	}
	if _, err := planFrom(t, base([]config.TeamStoreKey{{Name: "k", Read: []string{"nobody"}}})); err == nil {
		t.Error("a store rule naming no agent was accepted")
	}
	if _, err := planFrom(t, base([]config.TeamStoreKey{{Read: []string{"master"}}})); err == nil {
		t.Error("a store rule with no key name was accepted")
	}
	// A team without an enabled store gets no store at all, rather than an
	// empty one that would answer "not found" where it should answer "none".
	plan, err := planFrom(t, &config.Team{Name: "t", Agents: []config.TeamAgent{{Name: "a", Count: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.storeEnabled {
		t.Error("a team with no [team.store] got one anyway")
	}
}
