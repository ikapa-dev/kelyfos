package main

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
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
	budget   config.TeamBudget
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
	if err := checkTeamFileScope(cfg); err != nil {
		return nil, err
	}

	plan := &teamPlan{name: t.Name, capture: t.RecordPayloads, budget: t.Budget}
	if err := checkTeamBudget(cfg); err != nil {
		return nil, err
	}
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
		// Relative to the policy file, not the working directory: the file
		// describes its own project, wherever it is invoked from. The same rule
		// `kelyfos run` applies to [sandbox] workspace and packPlugins applies
		// to a plugin directory — this call site was written without it and was
		// the only workspace path in the product still resolved against the
		// process (finding L-5).
		//
		// Both doors reach it and both are wrong in the same way. `team up`
		// walks up for its policy the way git does, so running it from a
		// subdirectory found the project's file and then packed the
		// subdirectory's `data`; serve-mcp is launched by a client from a
		// directory nobody chose, which is why --policy exists at all. Resolved
		// here rather than in bootAgent because this is the choke point: the
		// plan is what every consumer reads.
		ws := a.Workspace
		if ws != "" && !filepath.IsAbs(ws) {
			ws = filepath.Join(filepath.Dir(cfg.Path), ws)
		}
		for _, name := range expandCount(a.Name, a.Count) {
			if seen[name] {
				return nil, fmt.Errorf("%s:%d: two agents are both called %q", cfg.Path, a.Line, name)
			}
			seen[name] = true
			plan.agents = append(plan.agents, plannedAgent{
				name: name, image: a.Image, res: a.Resources, spawn: a.Spawn,
				allow: a.Allow, secrets: a.Secrets, workspace: ws})
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

// checkTeamFileScope refuses two keys a team's own kelyfos.toml may also
// carry that a team boot does not wire in: [[plugin]] and [[forward]] are
// both file-level, both parse next to a perfectly ordinary [team] section,
// and neither has ever done anything there. packPlugins is called from
// `kelyfos run` and from serve-mcp's single-sandbox door; resolveForwards is
// called from `kelyfos run` alone. Neither is ever reached from raiseTeam, so
// a plugin or a forward written beside [team] loads, is silently dropped, and
// the person who wrote it has no way to discover that short of reading this
// file (P7-4).
//
// Refused rather than wired in, because refusing is the smaller change and
// is strictly better than the silence it replaces — the same ruling
// checkAgentPolicy already made for idle_timeout and a spawn budget's dead
// keys, just above. Checked before a single agent is resolved, so a file
// naming either is refused the same way `kelyfos team graph` refuses it
// (P7-7), with nothing booted yet, through this exact function.
func checkTeamFileScope(cfg *config.Config) error {
	if len(cfg.Plugins) > 0 {
		return fmt.Errorf("%s:%d: [[plugin]] has no effect inside a team\n"+
			"    a team boot does not launch plugin servers yet, so this block would parse "+
			"and then silently do nothing\n"+
			"    drop it — `kelyfos run` and `serve-mcp` still launch it fine, from this exact "+
			"file, [team] and all; `kelyfos team up` and `kelyfos team graph` both refuse a file "+
			"combining the two. `kelyfos team up` has no --policy flag, so the block has to leave "+
			"this file; `kelyfos team graph --policy` can point at a team-only copy instead",
			cfg.Path, cfg.Plugins[0].Line)
	}
	if len(cfg.Forwards) > 0 {
		return fmt.Errorf("%s:%d: [[forward]] has no effect inside a team\n"+
			"    a team boot does not open forwarded ports yet, so this block would parse "+
			"and then silently do nothing\n"+
			"    drop it here and use `kelyfos run -p %d:%d` instead — a command-line -p "+
			"replaces the file's [[forward]] list entirely, so it works even against this file",
			cfg.Path, cfg.Forwards[0].Line, cfg.Forwards[0].Host, cfg.Forwards[0].Guest)
	}
	return nil
}

// checkTeamBudget refuses an agent that asks for more CPU time than the team it
// runs in. The parent slice would hold it anyway — that is what a hierarchy is
// for — but a ceiling written above another ceiling and quietly ignored is the
// kind of number a reader will later trust.
//
// The *sum* is deliberately not checked. Five agents at 100% under a team cap of
// 200% is legal and is the configuration worth writing: each may burst to its
// own ceiling while the others idle, and the parent holds the total. Refusing
// oversubscription would forbid the only reason a shared budget exists (F-D21).
func checkTeamBudget(cfg *config.Config) error {
	limit := cfg.Team.Budget.CPUQuota
	if limit <= 0 {
		return nil
	}
	teamLine, _ := cfg.Team.Ceiling("cpu_quota")
	for _, a := range cfg.Team.Agents {
		for _, ask := range []struct {
			what string
			pct  int
		}{
			{"cpu_quota", a.Resources.CPUQuota},
			{"spawn budget's cpu_quota", spawnQuota(a)},
		} {
			if ask.pct > limit {
				return fmt.Errorf("%s:%d: agent %q asks for %s = %q, more than the team's "+
					"cpu_quota = %q set at %s:%d\n"+
					"    an agent cannot be given more CPU time than the team it runs in",
					cfg.Path, a.Line, a.Name, ask.what, pct(ask.pct), pct(limit), cfg.Path, teamLine)
			}
		}
	}
	return nil
}

func spawnQuota(a config.TeamAgent) int {
	if a.Spawn == nil {
		return 0
	}
	return a.Spawn.Resources.CPUQuota
}

func pct(n int) string { return fmt.Sprintf("%d%%", n) }

// needsSlice reports whether this team has any CPU number at all. A team that
// declared none gets no cgroup machinery, so it can run on a host with no
// systemd user session and no delegated cgroup — which is most containers.
func (p *teamPlan) needsSlice() bool {
	if p.budget.CPUQuota > 0 {
		return true
	}
	for _, a := range p.agents {
		if a.res.CPUQuota > 0 {
			return true
		}
		if a.spawn != nil && a.spawn.Resources.CPUQuota > 0 {
			return true
		}
	}
	return false
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
		// The package that owns the grammar parses it. This used to be a fourth
		// hand-rolled reading — everything after the first "@" taken as the
		// domain — which a path-scoped binding would have turned into a domain
		// that is a path, refused with a fix line naming something the user
		// could not add to an allow list (P6-4).
		parsed, err := egress.ParseSecretSpec(spec)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		name, domain := parsed.Name, parsed.Host
		if !containsDomain(a.Allow, domain) {
			return fmt.Errorf("%s: agent %q binds %s to %s, which is not in its allow list\n"+
				"    add %q to this agent's allow, or drop the secret",
				where, a.Name, name, domain, domain)
		}
	}

	// Two machines writing one host directory back is not a workspace.
	//
	// The loser is not silently lost — Commit re-fingerprints immediately before
	// the rename and diverts on a mismatch (P6-21), so the second writer's work
	// lands beside the directory rather than on top of it. But a `count` group
	// whose members all divert is a group where the declaration promised
	// something the run cannot give, and finding that out at sync-back is
	// finding it out after the work. Refuse the declaration instead.
	//
	// This refusal covers one directory behind a `count` group. Two *distinct*
	// agents naming the same directory, or one naming a parent of another's, is
	// not refused here — see docs/teams.md §4.
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

	// The same two keys under a spawn budget were accepted and then enforced by
	// nothing, which is the failure F-D10 and F-D20 both exist to prevent: a
	// limits file whose limit is inert is worse than one that has no limit in
	// it. Refusing is also the correct answer rather than merely the cheap one
	// (F-D33). idle_timeout is unenforceable here for exactly F-D20's reason,
	// and max_runtime is a second name for a key the budget already has —
	// `lifetime` is how long a spawned worker lives, and two timers with one
	// meaning is a way to disagree with yourself.
	if a.Spawn != nil {
		if a.Spawn.Resources.IdleTimeout > 0 {
			return fmt.Errorf("%s: idle_timeout is not available in a spawn budget (F-D20, F-D33)\n"+
				"    a team shares one flight recorder, so the host cannot tell which agent went quiet;\n"+
				"    use [team.agent.spawn] lifetime, which bounds how long a spawned worker lives",
				where)
		}
		if a.Spawn.Resources.MaxRuntime > 0 {
			return fmt.Errorf("%s: max_runtime in a spawn budget is [team.agent.spawn] lifetime "+
				"under another name (F-D33)\n"+
				"    write lifetime = %q in [team.agent.spawn]; it is the key that bounds how long\n"+
				"    a spawned worker lives, and it is enforced",
				where, a.Spawn.Resources.MaxRuntime.String())
		}
	}
	return nil
}

// forkable reports whether this agent can be started as a fork of a shared
// template instead of booted from cold (F-D19).
//
// The thing a fork cannot carry is a network identity: the guest's address and
// default route live inside the memory image every fork shares, so N networked
// forks would be N machines that believe they are the same host — which is what
// F-D17 recorded and why `kelyfos fork` refuses a networked snapshot. An agent
// its policy granted no egress has no such identity to collide with, and that
// is the whole of the ruling.
//
// A workspace disqualifies an agent for a different reason: a fork gets a copy
// of the template's disk, and the template's disk would be whichever agent's
// directory happened to be packed into it. Handing agent B a copy of agent A's
// files is worse than a slower boot.
func (a plannedAgent) forkable() bool {
	return len(a.allow) == 0 && a.workspace == ""
}

// forkKey identifies agents that can share one template: everything baked into
// a memory image, and nothing else.
//
// cpu_quota is deliberately absent. It is a host-side cgroup on the VMM process
// rather than anything inside the machine, so two agents with different quotas
// can still be forks of one snapshot — each gets its own slice at restore.
func (a plannedAgent) forkKey() string {
	return fmt.Sprintf("%s|%d|%d|%d|%d|%d|%d|%d|%t",
		a.image, a.res.CPUs, a.res.MemMiB, a.res.ScratchByte,
		a.res.NetMbpsRx, a.res.NetMbpsTx, a.res.DiskIOPS, a.res.DiskMbps,
		a.spawn != nil)
}

// forkPlan splits the team into the agents that *could* share a template,
// grouped by the shape they share, and the ones that certainly cannot.
//
// It answers only the question it can answer from the policy file. Whether a
// group is actually forked depends on whether a template for its shape is
// already cached, which is a fact about the disk rather than the file, and is
// decided by the caller (F-D26).
//
// A group of one is sent to the cold list on purpose: a template exists to be
// copied, and copying it once is not a saving.
func (p *teamPlan) forkPlan() (groups map[string][]int, cold []int) {
	groups = map[string][]int{}
	for i, a := range p.agents {
		if a.forkable() {
			groups[a.forkKey()] = append(groups[a.forkKey()], i)
		} else {
			cold = append(cold, i)
		}
	}
	for k, idx := range groups {
		if len(idx) < 2 {
			cold = append(cold, idx...)
			delete(groups, k)
		}
	}
	sort.Ints(cold)
	return groups, cold
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
