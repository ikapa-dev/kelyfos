package main

import (
	"fmt"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/team"
)

// teamPlan is a [team] section turned into the things that boot it: the agents
// that will exist, the topology their edges resolve to, and the store their
// rules describe.
//
// Resolving before booting is the point. `count = 3` becomes three named
// agents here, so an edge to `worker-*` can be checked against names that
// exist — and a typo in an edge is a refusal before any machine starts rather
// than a message that mysteriously never arrives an hour in.
type teamPlan struct {
	name     string
	capture  bool
	agents   []plannedAgent
	topo     *team.Topology
	edgeText []string

	// storeRules is kept rather than a built store, because a store records
	// every access and the recorder does not exist yet when the plan is made.
	// The rules are still *validated* here, before anything boots — a rule
	// naming an agent that does not exist should stop a team the same way an
	// edge to nowhere does.
	storeEnabled bool
	storeRules   []team.Rule
}

type plannedAgent struct {
	name  string
	image string
	res   config.AgentResources
	spawn *config.SpawnBudget

	// The three things that make an agent a machine of its own rather than a
	// name in a graph: what it may reach, what credentials it may spend there,
	// and which host directory is its /work. All three are per agent by
	// design — there is deliberately no team-wide allowlist (docs/teams.md
	// §1.2), because a shared list hands the least trusted agent the most
	// trusted agent's network.
	allow     []string
	secrets   []string
	workspace string
}

func planTeam(cfg *config.Config) (*teamPlan, error) {
	t := cfg.Team
	if t.Name == "" {
		return nil, fmt.Errorf("%s: [team] needs a name", cfg.Path)
	}
	if len(t.Agents) == 0 {
		return nil, fmt.Errorf("%s: a team with no [[team.agent]] has nothing to run", cfg.Path)
	}

	plan := &teamPlan{name: t.Name, capture: t.RecordPayloads}
	seen := map[string]bool{}
	for _, a := range t.Agents {
		if a.Name == "" {
			return nil, fmt.Errorf("%s:%d: an agent with no name cannot be addressed", cfg.Path, a.Line)
		}
		if a.Image == "" {
			a.Image = cfg.Image
		}
		if a.Image == "" {
			a.Image = "base"
		}
		if err := checkAgentPolicy(cfg.Path, a); err != nil {
			return nil, err
		}
		for _, name := range expandCount(a.Name, a.Count) {
			if seen[name] {
				return nil, fmt.Errorf("%s:%d: two agents are both called %q", cfg.Path, a.Line, name)
			}
			seen[name] = true
			plan.agents = append(plan.agents, plannedAgent{
				name: name, image: a.Image, res: a.Resources, spawn: a.Spawn,
				allow: a.Allow, secrets: a.Secrets, workspace: a.Workspace})
		}
	}

	names := make([]string, 0, len(plan.agents))
	for _, a := range plan.agents {
		names = append(names, a.name)
	}

	edges := make([]team.Edge, 0, len(t.Edges))
	for _, e := range t.Edges {
		if e.From == "" || e.To == "" {
			return nil, fmt.Errorf("%s:%d: an edge needs both from and to", cfg.Path, e.Line)
		}
		edges = append(edges, team.Edge{From: e.From, To: e.To, Bidirectional: e.Bidirectional})
		arrow := " -> "
		if e.Bidirectional {
			arrow = " <-> "
		}
		plan.edgeText = append(plan.edgeText, e.From+arrow+e.To)
	}

	topo, err := team.NewTopology(names, edges)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.Path, err)
	}
	plan.topo = topo

	// The edge text above is the file's wording; this is what it resolved to,
	// which is what `ps` should show. A star written as one line becomes four
	// pairs, and a reader looking for "may this worker reach that one" wants
	// the pairs.
	plan.edgeText = plan.edgeText[:0]
	for _, from := range topo.Agents() {
		for _, to := range topo.PeersOf(from) {
			plan.edgeText = append(plan.edgeText, from+" -> "+to)
		}
	}

	if t.Store != nil && t.Store.Enabled {
		rules := make([]team.Rule, 0, len(t.Store.Keys))
		for _, k := range t.Store.Keys {
			if k.Name == "" {
				return nil, fmt.Errorf("%s:%d: a store rule needs a key name", cfg.Path, k.Line)
			}
			rules = append(rules, team.Rule{Name: k.Name, Read: k.Read, Write: k.Write})
		}
		if _, err := team.NewStore(topo, rules, nil); err != nil {
			return nil, fmt.Errorf("%s: %w", cfg.Path, err)
		}
		plan.storeEnabled, plan.storeRules = true, rules
	}
	return plan, nil
}

// checkAgentPolicy refuses, before anything boots, the combinations this host
// cannot honour. Every one of them was previously accepted and then silently
// dropped, which is the failure mode this project refuses everywhere else: a
// policy file whose keys do nothing is worse than one that will not load.
func checkAgentPolicy(path string, a config.TeamAgent) error {
	where := fmt.Sprintf("%s:%d", path, a.Line)

	// A secret is only useful for a domain this agent may reach at all, and the
	// check belongs here rather than at the proxy: an agent whose credential
	// can never be sent is a policy mistake, not a runtime condition.
	for _, spec := range a.Secrets {
		name, domain, ok := strings.Cut(strings.SplitN(spec, ":", 2)[0], "@")
		if !ok || name == "" || domain == "" {
			return fmt.Errorf("%s: secrets must be NAME@domain, got %q", where, spec)
		}
		if !containsDomain(a.Allow, domain) {
			return fmt.Errorf("%s: agent %q binds %s to %s, which is not in its allow list\n"+
				"    add %q to this agent's allow, or drop the secret",
				where, a.Name, name, domain, domain)
		}
	}

	// Two machines writing one host directory back is not a workspace, it is a
	// race whose loser's work disappears. Refuse the declaration rather than
	// discover it at sync-back.
	if a.Workspace != "" && a.Count > 1 {
		return fmt.Errorf("%s: agent %q has count = %d and one workspace directory (%s)\n"+
			"    give each replica its own agent block, or drop the workspace",
			where, a.Name, a.Count, a.Workspace)
	}

	// idle_timeout needs an answer to "has *this agent* done anything lately",
	// and inside a team the only activity signal the host has is one shared
	// flight recorder that every agent writes into (F-D20). max_runtime is
	// well defined per agent and is honoured.
	if a.Resources.IdleTimeout > 0 {
		return fmt.Errorf("%s: idle_timeout is not available per agent yet (F-D20)\n"+
			"    a team shares one flight recorder, so the host cannot yet tell which agent went quiet;\n"+
			"    use max_runtime, which is per agent and does work",
			where)
	}
	return nil
}

// spawnResources is the caps a worker spawned by this agent gets: the budget's
// template, never the spawner's own. An agent that could spawn copies of itself
// would multiply its own caps, which is the one thing a budget exists to stop.
func (p *teamPlan) spawnResources(spawner string) config.AgentResources {
	for _, a := range p.agents {
		if a.name == spawner && a.spawn != nil {
			return a.spawn.Resources
		}
	}
	return config.AgentResources{}
}

// expandCount turns one [[team.agent]] with count = N into N names. A count of
// one keeps the bare name, because "master-1" in a team with one master is
// noise the user did not ask for.
func expandCount(name string, count int) []string {
	if count <= 1 {
		return []string{name}
	}
	out := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		out = append(out, fmt.Sprintf("%s-%d", name, i))
	}
	return out
}
