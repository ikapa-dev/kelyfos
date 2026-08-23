package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

// Everything [[team.agent]] declares must reach the agent. These four keys were
// parsed and then silently dropped for a whole release, which is the failure
// this project refuses everywhere else — so the plan now carries them, and
// refuses the combinations the host cannot honour.
func TestPerAgentPolicyReachesThePlan(t *testing.T) {
	plan, err := planFrom(t, &config.Team{
		Name: "t",
		Agents: []config.TeamAgent{{
			Name: "master", Count: 1,
			Allow:     []string{"api.github.com"},
			Secrets:   []string{"GITHUB_TOKEN@api.github.com"},
			Workspace: "/tmp/ws",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := plan.agents[0]
	if len(a.allow) != 1 || a.allow[0] != "api.github.com" {
		t.Errorf("allow did not reach the plan: %v", a.allow)
	}
	if len(a.secrets) != 1 {
		t.Errorf("secrets did not reach the plan: %v", a.secrets)
	}
	if a.workspace != "/tmp/ws" {
		t.Errorf("workspace did not reach the plan: %q", a.workspace)
	}
}

// A credential bound to a domain the agent may not reach can never be spent.
// That is a policy mistake, so it is refused at the file rather than discovered
// as a connection that is simply never allowed.
func TestASecretOutsideItsAgentsAllowlistIsRefused(t *testing.T) {
	_, err := planFrom(t, &config.Team{
		Name: "t",
		Agents: []config.TeamAgent{{
			Name: "master", Count: 1,
			Allow:   []string{"example.com"},
			Secrets: []string{"GITHUB_TOKEN@api.github.com"},
		}},
	})
	if err == nil {
		t.Fatal("a secret bound outside the agent's allowlist was accepted")
	}
	for _, want := range []string{"api.github.com", "allow list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	// A subdomain of an allowed domain is reachable, so binding to it is fine —
	// the same suffix rule the proxy enforces.
	if _, err := planFrom(t, &config.Team{
		Name: "t",
		Agents: []config.TeamAgent{{
			Name: "master", Count: 1,
			Allow:   []string{"github.com"},
			Secrets: []string{"GITHUB_TOKEN@api.github.com:basic"},
		}},
	}); err != nil {
		t.Errorf("a secret on a subdomain of an allowed domain was refused: %v", err)
	}
}

// Two machines writing one host directory back is a race whose loser's work
// disappears, so the declaration is refused rather than the sync.
func TestOneWorkspaceCannotBackACountGroup(t *testing.T) {
	_, err := planFrom(t, &config.Team{
		Name:   "t",
		Agents: []config.TeamAgent{{Name: "worker", Count: 3, Workspace: "/tmp/shared"}},
	})
	if err == nil {
		t.Fatal("three agents were given one workspace directory")
	}
	if !strings.Contains(err.Error(), "workspace") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
}

// idle_timeout has no per-agent activity signal inside a team yet (F-D20), so
// it is refused by name and line rather than accepted and ignored. max_runtime
// is well defined per agent and is not.
func TestIdleTimeoutIsRefusedPerAgentAndMaxRuntimeIsNot(t *testing.T) {
	_, err := planFrom(t, &config.Team{
		Name: "t",
		Agents: []config.TeamAgent{{
			Name: "a", Count: 1,
			Resources: config.AgentResources{IdleTimeout: 30 * time.Second},
		}},
	})
	if err == nil {
		t.Fatal("idle_timeout was accepted per agent")
	}
	if !strings.Contains(err.Error(), "F-D20") {
		t.Errorf("the refusal does not cite the decision: %v", err)
	}
	plan, err := planFrom(t, &config.Team{
		Name: "t",
		Agents: []config.TeamAgent{{
			Name: "a", Count: 1,
			Resources: config.AgentResources{MaxRuntime: 30 * time.Second},
		}},
	})
	if err != nil {
		t.Fatalf("max_runtime was refused per agent: %v", err)
	}
	if plan.agents[0].res.MaxRuntime != 30*time.Second {
		t.Errorf("max_runtime did not reach the plan: %v", plan.agents[0].res.MaxRuntime)
	}
}

// An agent cannot be given more CPU time than the team it runs in. The parent
// slice would hold it anyway, but a ceiling written above another ceiling and
// then quietly ignored is a number a reader will later trust.
func TestAnAgentCannotOutgrowItsTeam(t *testing.T) {
	tm := &config.Team{
		Name:    "t",
		Budget:  config.TeamBudget{CPUQuota: 200},
		ResLine: map[string]int{"cpu_quota": 4},
		Agents: []config.TeamAgent{{
			Name: "master", Count: 1, Line: 14,
			Resources: config.AgentResources{CPUQuota: 250},
		}},
	}
	_, err := planFrom(t, tm)
	if err == nil {
		t.Fatal("an agent was given more CPU time than its whole team")
	}
	for _, want := range []string{"250%", "200%", "kelyfos.toml:14", "kelyfos.toml:4"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	// A spawn budget's template is checked the same way: a worker the master is
	// allowed to create cannot be bigger than the team either.
	tm.Agents[0].Resources.CPUQuota = 100
	tm.Agents[0].Spawn = &config.SpawnBudget{Max: 2, Resources: config.AgentResources{CPUQuota: 400}}
	if _, err := planFrom(t, tm); err == nil {
		t.Error("a spawn budget was allowed to outgrow the team")
	}
}

// The sum is deliberately not checked. Five agents at 100% under a team cap of
// 200% is the configuration worth writing: each may burst to its own ceiling
// while the others idle, and the parent holds the total (F-D21). This test is
// the decision — without it someone will later "fix" the missing arithmetic.
func TestPerAgentQuotasMayOversubscribeTheTeam(t *testing.T) {
	agents := make([]config.TeamAgent, 0, 5)
	for i := 0; i < 5; i++ {
		agents = append(agents, config.TeamAgent{
			Name: fmt.Sprintf("a%d", i), Count: 1,
			Resources: config.AgentResources{CPUQuota: 100},
		})
	}
	if _, err := planFrom(t, &config.Team{
		Name: "t", Budget: config.TeamBudget{CPUQuota: 200}, Agents: agents,
	}); err != nil {
		t.Fatalf("five agents at 100%% under a 200%% team cap were refused: %v", err)
	}
}

// A team that declared no CPU number anywhere gets no cgroup machinery, so it
// runs on a host with no systemd user session and no delegated cgroup.
func TestATeamWithNoCPUNumbersNeedsNoSlice(t *testing.T) {
	plain, err := planFrom(t, &config.Team{
		Name: "t", Agents: []config.TeamAgent{{Name: "a", Count: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plain.needsSlice() {
		t.Error("a team with no cpu_quota anywhere asked for a cgroup")
	}
	for what, tm := range map[string]*config.Team{
		"a team budget": {Name: "t", Budget: config.TeamBudget{CPUQuota: 200},
			Agents: []config.TeamAgent{{Name: "a", Count: 1}}},
		"one agent's quota": {Name: "t", Agents: []config.TeamAgent{
			{Name: "a", Count: 1, Resources: config.AgentResources{CPUQuota: 50}}}},
		"a spawn budget's quota": {Name: "t", Agents: []config.TeamAgent{
			{Name: "a", Count: 1, Spawn: &config.SpawnBudget{
				Max: 1, Resources: config.AgentResources{CPUQuota: 50}}}}},
	} {
		p, err := planFrom(t, tm)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !p.needsSlice() {
			t.Errorf("%s did not ask for a cgroup", what)
		}
	}
}
