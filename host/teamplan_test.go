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

// An agent granted egress cannot be forked — the guest's address lives inside
// the memory image every fork would share (F-D17, F-D19). An agent granted none
// can, and a workspace disqualifies one for a different reason entirely.
func TestOnlyAgentsWithNothingBakedInAreForkable(t *testing.T) {
	cases := map[string]struct {
		a    config.TeamAgent
		fork bool
	}{
		"no egress, no workspace": {config.TeamAgent{Name: "w", Count: 1}, true},
		"granted egress":          {config.TeamAgent{Name: "w", Count: 1, Allow: []string{"example.com"}}, false},
		"given a host directory":  {config.TeamAgent{Name: "w", Count: 1, Workspace: "/tmp/x"}, false},
		"egress and a workspace":  {config.TeamAgent{Name: "w", Count: 1, Allow: []string{"a.com"}, Workspace: "/tmp/x"}, false},
	}
	for what, c := range cases {
		plan, err := planFrom(t, &config.Team{Name: "t", Agents: []config.TeamAgent{c.a}})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got := plan.agents[0].forkable(); got != c.fork {
			t.Errorf("%s: forkable = %v, want %v", what, got, c.fork)
		}
	}
}

// A template is only shareable by agents whose machines are identical. cpu_quota
// is the deliberate exception: it is a host-side cgroup, not part of the image.
func TestTheForkKeyCoversWhatIsBakedInAndNothingElse(t *testing.T) {
	base := config.AgentResources{CPUs: 2, MemMiB: 512, ScratchByte: 1 << 20}
	plan, err := planFrom(t, &config.Team{Name: "t", Agents: []config.TeamAgent{
		{Name: "a", Count: 1, Resources: base},
		{Name: "b", Count: 1, Resources: base},
		{Name: "c", Count: 1, Resources: func() config.AgentResources {
			r := base
			r.CPUQuota = 150 // host-side: must NOT split the group
			return r
		}()},
		{Name: "d", Count: 1, Resources: func() config.AgentResources {
			r := base
			r.MemMiB = 1024 // baked in: must split the group
			return r
		}()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key := func(name string) string {
		for _, a := range plan.agents {
			if a.name == name {
				return a.forkKey()
			}
		}
		t.Fatalf("no agent %q", name)
		return ""
	}
	if key("a") != key("b") {
		t.Error("two identical agents did not share a template")
	}
	if key("a") != key("c") {
		t.Error("a different cpu_quota split a template; it is a host cgroup, not part of the image")
	}
	if key("a") == key("d") {
		t.Error("a different mem shared a template; mem is the machine's hardware")
	}
}

// The saving starts at two: a template costs a boot and a snapshot, so forking
// one agent is strictly slower than booting it.
func TestAGroupOfOneColdBoots(t *testing.T) {
	plan, err := planFrom(t, &config.Team{Name: "t", Agents: []config.TeamAgent{
		{Name: "master", Count: 1, Allow: []string{"example.com"}},
		{Name: "solo", Count: 1, Resources: config.AgentResources{MemMiB: 256}},
		{Name: "worker", Count: 4, Resources: config.AgentResources{MemMiB: 384}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	groups, cold := plan.forkPlan()
	if len(groups) != 1 {
		t.Fatalf("got %d fork groups, want 1 (the four workers)", len(groups))
	}
	for _, idx := range groups {
		if len(idx) != 4 {
			t.Errorf("the fork group has %d members, want 4", len(idx))
		}
	}
	var coldNames []string
	for _, i := range cold {
		coldNames = append(coldNames, plan.agents[i].name)
	}
	if got := strings.Join(coldNames, " "); got != "master solo" {
		t.Errorf("cold-booted %q, want the egress-granted master and the lone worker", got)
	}
	// Every agent is accounted for exactly once, or a team would come up short.
	seen := len(cold)
	for _, idx := range groups {
		seen += len(idx)
	}
	if seen != len(plan.agents) {
		t.Errorf("the boot plan covers %d of %d agents", seen, len(plan.agents))
	}
}

// The plan covers every agent exactly once and the cold list is stable, because
// the order the terminal prints is the order the file declares.
func TestForkPlanIsStableAndComplete(t *testing.T) {
	plan, err := planFrom(t, &config.Team{Name: "t", Agents: []config.TeamAgent{
		{Name: "master", Count: 1, Allow: []string{"a.com"}},
		{Name: "alpha", Count: 3, Resources: config.AgentResources{MemMiB: 256}},
		{Name: "beta", Count: 2, Resources: config.AgentResources{MemMiB: 512}},
		{Name: "keeper", Count: 1, Workspace: "/tmp/k"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		groups, cold := plan.forkPlan()
		if len(groups) != 2 {
			t.Fatalf("got %d groups, want two (three alphas, two betas)", len(groups))
		}
		var names []string
		for _, i := range cold {
			names = append(names, plan.agents[i].name)
		}
		if got := strings.Join(names, " "); got != "master keeper" {
			t.Fatalf("cold list = %q, want a stable \"master keeper\"", got)
		}
		seen := len(cold)
		for _, idx := range groups {
			seen += len(idx)
		}
		if seen != len(plan.agents) {
			t.Fatalf("the plan covers %d of %d agents", seen, len(plan.agents))
		}
	}
}

// A key the file accepts and nothing enforces is worse than one it refuses: the
// user believes a limit is in force and it is not. These two were exactly that
// until F-D33, so they are refused now, and the refusal has to say what to
// write instead.
func TestSpawnBudgetRefusesTheKeysNothingEnforced(t *testing.T) {
	for _, tc := range []struct {
		key   string
		set   func(*config.SpawnBudget)
		wants string
	}{
		{"idle_timeout", func(b *config.SpawnBudget) { b.Resources.IdleTimeout = 5 * time.Minute }, "lifetime"},
		{"max_runtime", func(b *config.SpawnBudget) { b.Resources.MaxRuntime = 30 * time.Minute }, "lifetime"},
	} {
		budget := &config.SpawnBudget{Max: 1, Images: []string{"dev"}}
		tc.set(budget)
		_, err := planFrom(t, &config.Team{
			Name:   "t",
			Agents: []config.TeamAgent{{Name: "master", Count: 1, Spawn: budget}},
		})
		if err == nil {
			t.Errorf("%s in a spawn budget was accepted, and nothing enforces it", tc.key)
			continue
		}
		if !strings.Contains(err.Error(), tc.key) {
			t.Errorf("the refusal does not name %s: %v", tc.key, err)
		}
		if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("the refusal for %s does not say what to use instead (%q): %v",
				tc.key, tc.wants, err)
		}
	}
}
