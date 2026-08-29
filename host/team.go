package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/exitcode"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sessionpolicy"
	"github.com/p4r4n0rm4l/KelyfOS/internal/team"
)

const teamUsage = `usage: kelyfos team up | ps | down | graph

  up     boot the team declared in kelyfos.toml and hold it until Ctrl-C
  ps     show the running team: agents, edges, and what each is consuming
         --graph draws the topology instead (see graph, below)
         --json emits structured data instead of a table (P7-10)
  down   stop a running team, syncing every workspace on the way out
  graph  draw the topology declared in kelyfos.toml, with nothing booted —
         a pre-flight lint, not a monitor (P7-7); --json emits it structured

A team is several sandboxes on one host with the paths between them written
down. No guest has a network path to any other guest: every message travels the
host, is checked against the edge list, and lands in one audit record.
See docs/teams.md.
`

func teamCmd(argv []string) error {
	if len(argv) == 0 {
		fmt.Fprint(os.Stderr, teamUsage)
		return fmt.Errorf("team needs a subcommand")
	}
	switch argv[0] {
	case "up":
		return teamUp(argv[1:])
	case "ps":
		return teamPS(argv[1:])
	case "down":
		return teamDown(argv[1:])
	case "graph":
		return teamGraphCmd(argv[1:])
	case "-h", "--help", "help":
		fmt.Print(teamUsage)
		return nil
	}
	fmt.Fprint(os.Stderr, teamUsage)
	return fmt.Errorf("unknown team subcommand %q", argv[0])
}

// teamState is what `ps` and `down` read: written by `up` when the graph is
// running, removed when it stops. It lives beside the run directories because
// it describes the same thing they do — machines that exist right now.
type teamState struct {
	Name      string    `json:"name"`
	PID       int       `json:"pid"`
	Session   string    `json:"session"`
	StartedAt time.Time `json:"started_at"`
	Agents    []struct {
		Name    string `json:"name"`
		Sandbox string `json:"sandbox"`
		// Via is how this machine started: "cold" or "fork" (F-D19).
		Via string `json:"via,omitempty"`
	} `json:"agents"`
	Edges []string `json:"edges"`
	// CGroup is the team's parent slice, when it has one. omitempty and read
	// tolerantly, so a team.json written by an older binary still parses.
	CGroup   string `json:"cgroup,omitempty"`
	CPUQuota int    `json:"cpu_quota_percent,omitempty"`
	// Owner is which door raised the team: the command line, or serve-mcp. A
	// team.json written before this field existed has none, which reads as the
	// command line and is what it was.
	Owner string `json:"owner,omitempty"`
}

func teamStatePath() string { return filepath.Join(sandbox.Root(), "run", "team.json") }

func teamUp(argv []string) error {
	fs := flag.NewFlagSet("kelyfos team up", flag.ExitOnError)
	arch := fs.String("arch", sandbox.HostArch(), "guest architecture (aarch64|x86_64)")
	timeout := fs.Duration("ready-timeout", 60*time.Second, "how long to wait for each guest")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	cfg, err := loadPolicy()
	if err != nil {
		return err
	}
	if cfg != nil {
		// What this file reaches, before any of the team's machines boot
		// (P7-17/F21).
		printPolicyReach(os.Stdout, cfg)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rig, err := raiseTeam(ctx, teamOptions{
		cfg: cfg, arch: *arch, timeout: *timeout, argv: os.Args, owner: ownerCLI, out: os.Stdout,
	})
	if err != nil {
		return err
	}
	defer rig.down()

	fmt.Println("\nCtrl-C to stop the team.")
	// A team has one recorder for the whole rig, so a failure there means what
	// it means for a single sandbox: every machine in it is running unrecorded.
	// The bare wait became a select for that (P7-17/F13(b)).
	//
	// The two per-agent goroutines — the spawn lifetime at :418 and the
	// max_runtime at :614 — need nothing of their own. Both select on ctx.Done,
	// both exist only to stop one agent early, and rig.down() cancels that
	// context before it tears the rig down; whichever of them is still waiting
	// returns on the next line rather than doing work for a machine that is
	// already stopping. Their own rec.Append calls are no-ops on a broken
	// recorder, by the latch's own rule.
	select {
	case <-ctx.Done():
		fmt.Println("\nstopping...")
	case <-rig.rec.Broken():
		recorderFailed(rig.rec, os.Stderr)
		rig.down()
		return &exitError{exitcode.Fail}
	}
	return nil
}

// teamOptions is everything raiseTeam needs that differs between the two doors
// a team can be raised through.
type teamOptions struct {
	cfg     *config.Config
	arch    string
	timeout time.Duration
	// argv goes into the record's session.start, so the transcript says what
	// asked for this team rather than always naming the command line.
	argv []string
	// reason goes into the record's session.start. serve-mcp names its own
	// session here, so a team's transcript points back at the conversation that
	// asked for it, the way a sandbox's does (E4-4).
	reason string
	owner  string
	// out is where progress goes. The command line passes os.Stdout; serve-mcp
	// must not, because there stdout is the protocol.
	out io.Writer
}

// teamRig is a running team: the plan it came from, the machines, the broker
// that carries messages between them, the collective cgroup, and the one
// recorder they all write to.
//
// It exists because a team outlives the call that raised it. `kelyfos team up`
// holds one until Ctrl-C; serve-mcp holds one until team_down or until the
// server stops. Both need the same thing raised the same way, and neither can
// have it built inside a function that only knows how to block (E4-3).
type teamRig struct {
	plan      *teamPlan
	crew      *roster
	rec       *recorder.Recorder
	broker    *team.Broker
	slice     *sandbox.TeamSlice
	session   string
	summary   string
	cancel    context.CancelFunc
	teardown  func()
	endRecord func()
	once      sync.Once
}

// down stops everything the team owns, in the order the command line's defers
// used to unwind it: the machines first, then the record that watched them. It
// is safe to call twice, because the two doors both defend against the case
// where the other already did it.
func (t *teamRig) down() {
	t.once.Do(func() {
		t.cancel()
		t.teardown()
		t.endRecord()
	})
}

// Who is holding a team up, recorded in team.json so `kelyfos team down` knows
// whether signalling the owning process is the right thing to do.
const (
	ownerCLI      = "cli"
	ownerServeMCP = "serve-mcp"
)

// defaultAgentMemMiB is the RAM a member gets when its block names none. It is
// the same number sandbox.New falls back to, restated here because the check
// below has to compare a scratch cap against the machine that will exist rather
// than against the zero that means "the file said nothing" — comparing against
// that zero would refuse every scratch written by an agent with no `mem`.
const defaultAgentMemMiB = 512

// checkTeamScratch refuses a team in which any member's scratch cap is larger
// than the RAM the tmpfs it sizes has to live in.
//
// `kelyfos run` and the E2B shim have always made this comparison before they
// boot anything, and a team was the door that let an inert limit through: the
// cap was accepted, handed to the machine, and could never be reached, which is
// the outcome the refusal exists to prevent. A limits file whose limit does
// nothing is worse than one with no limit in it, because the file says the
// agent is bounded and nothing bounds it (docs/resources.md).
//
// It runs over the plan rather than at each boot so that the whole team is
// refused before a single machine starts — the same reason a bad `-p` is
// refused at the command line rather than after something is already running. A
// spawn budget is checked with the agent that carries it for the same reason:
// the budget is in the file, the file is being read now, and discovering it at
// the moment an agent spawns a worker is discovering it too late.
func checkTeamScratch(plan *teamPlan) error {
	for _, a := range plan.agents {
		if err := scratchWithinMem("agent "+a.name, a.res); err != nil {
			return err
		}
		if a.spawn != nil {
			if err := scratchWithinMem("the spawn budget of "+a.name, a.spawn.Resources); err != nil {
				return err
			}
		}
	}
	return nil
}

// scratchWithinMem is the comparison itself, kept apart from the walk so the
// rule can be checked without a team to run it against.
func scratchWithinMem(who string, res config.AgentResources) error {
	mem := res.MemMiB
	if mem <= 0 {
		mem = defaultAgentMemMiB
	}
	if res.ScratchByte <= 0 || res.ScratchByte <= int64(mem)<<20 {
		return nil
	}
	return fmt.Errorf("scratch = %d bytes for %s is larger than the %d MiB that machine has\n"+
		"    the scratch tmpfs lives in that memory, so a cap above it can never be reached",
		res.ScratchByte, who, mem)
}

func raiseTeam(parent context.Context, opt teamOptions) (*teamRig, error) {
	cfg, arch, timeout, out := opt.cfg, opt.arch, opt.timeout, opt.out
	if cfg == nil || cfg.Team == nil {
		return nil, fmt.Errorf("no [team] section in this project's %s — see docs/teams.md", config.FileName)
	}
	if _, err := os.Stat(teamStatePath()); err == nil {
		return nil, fmt.Errorf("a team is already running; stop it with `kelyfos team down`")
	}

	plan, err := planTeam(cfg)
	if err != nil {
		return nil, err
	}
	if err := checkTeamScratch(plan); err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "team %s: %d agents, %d edges\n", plan.name, len(plan.agents), len(plan.edgeText))

	// One flight recorder for the whole team, so a team produces one verifiable
	// transcript rather than five that have to be correlated afterwards. The
	// session is named for the team, not for any one machine in it.
	sessionID, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	rec, err := recorder.Open(sandbox.Root(), sessionID)
	if err != nil {
		return nil, err
	}
	// The rig's own context, so down() can stop the goroutines a team keeps —
	// spawn lifetimes, max_runtime timers, a template still being cached — and
	// so a caller that cancels its own context stops them too.
	ctx, cancel := context.WithCancel(parent)

	endRecord := func() {
		reason := "shutdown"
		if seq, ferr := rec.Failure(); ferr != nil {
			reason = fmt.Sprintf("recorder failed at seq %d", seq)
		}
		endSession(rec, reason, nil)
	}
	// Until this call succeeds the record is closed on the way out of any
	// failure; afterwards it belongs to the rig, and rig.down() closes it.
	raised := false
	defer func() {
		if !raised {
			endRecord()
			cancel()
		}
	}()
	_ = rec.Append(recorder.Event{Type: recorder.TypeSessionStart, Arch: arch,
		Kelyfos: Version, Argv: opt.argv, Reason: opt.reason})

	// The broker records on whichever goroutine delivered the message, and the
	// recorder takes an exclusive lock per append, which is exactly the
	// contract internal/team documents.
	record := func(e team.Event) { _ = rec.Append(e.Record()) }
	broker := team.New(plan.topo, plan.capture, record)
	if plan.storeEnabled {
		// Built here rather than in the plan, because every store access is an
		// event and the recorder is what receives it. A store constructed
		// before the recorder existed would have silently kept its accesses to
		// itself — which is exactly what the first live run of a team showed.
		store, err := team.NewStore(plan.topo, plan.storeRules, record)
		if err != nil {
			return nil, err
		}
		broker.Store = store
	}

	// The collective cap, built before any agent so that every agent is inside
	// it from the instant it exists — a budget that arrives after the machines
	// is a budget with a hole in it. A team that declared no CPU numbers at all
	// gets no cgroup machinery, and so needs neither systemd nor a delegated
	// cgroup to run (E2-6).
	var teamSlice *sandbox.TeamSlice
	if plan.needsSlice() {
		teamSlice, err = sandbox.NewTeamSlice(plan.name, plan.budget.CPUQuota)
		if err != nil {
			return nil, err
		}
	}

	crew := &roster{plan: plan, session: sessionID, edges: plan.edgeText,
		slice: teamSlice, owner: opt.owner}
	// Declared before teardown because teardown waits on it: a fork template
	// may still be building in the background when the team is stopped.
	var templates sync.WaitGroup
	// The shapes this team-up found no template for, one representative agent
	// each. Filled when the boot plan is made, used after the team is up.
	var toBuild []int
	teardown := func() {
		// Reverse order, so the agent booted last is stopped first — the same
		// order a single run's defers would have taken. Spawned workers are in
		// this list too, and are the last in, so they are the first out. Each
		// one syncs its own workspace on the way past, which is what `down`
		// promises: all VMs gone, all workspaces written back.
		running := crew.snapshot()
		for i := len(running) - 1; i >= 0; i-- {
			if err := running[i].stop(10*time.Second, out); err != nil {
				fmt.Fprintf(os.Stderr, "kelyfos: %s: %v\n", running[i].name, err)
			}
		}
		// A template being built in the background is stopped with the team:
		// its context is the team's, and waiting here is what keeps a
		// half-built one from outliving the process that started it.
		templates.Wait()
		// The parent goes last and its failure is reported: rmdir refuses a
		// populated cgroup, so a teardown in the wrong order would otherwise
		// leak one directory per run and say nothing at all.
		if err := teamSlice.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: %v\n", err)
		}
		_ = os.Remove(teamStatePath())
	}
	defer func() {
		if !raised {
			teardown()
		}
	}()

	// Spawn: the broker decides whether a worker may exist and what it is
	// called; this decides how to start one. The split is the point — the
	// budget is policy and belongs where the edge list is, and booting a
	// machine is a thing only the host can do (E2-5).
	for _, a := range plan.agents {
		if a.spawn != nil {
			broker.GrantSpawn(a.name, team.Budget{
				Max: a.spawn.Max, Images: a.spawn.Images, Lifetime: a.spawn.Lifetime,
			})
		}
	}
	broker.OnSpawn = func(req team.SpawnRequest) error {
		// A spawned worker gets the budget's caps and nothing else: no egress,
		// no secrets, no workspace. The budget template has no place to declare
		// them, and inventing an inheritance rule would let an agent hand its
		// own network to a machine the user never wrote down (E2-5).
		res := plan.spawnResources(req.Spawner)
		// req.Lifetime, not res.MaxRuntime, is the wall-clock ceiling actually
		// enforced for a spawned worker: the goroutine a few lines down calls
		// Despawn/stop after req.Lifetime elapses, the same role the
		// declared-agent max_runtime goroutine plays above for plan.agents[i]
		// .res.MaxRuntime — but nothing plays that role for res.MaxRuntime
		// here, because a spawn budget's optional [resources] sub-block has no
		// equivalent enforcement loop of its own. Left alone, agentPolicyEvent
		// would record whatever res.MaxRuntime happens to hold (typically
		// zero, since operators write the ceiling as `lifetime` on the spawn
		// budget) while staying silent about the ceiling genuinely in force —
		// the same "a wall with nothing in the record saying so" shape P7-2
		// exists to close, reappearing at the one door P7-0's own review (F2)
		// already flagged it at once (F4, the review that reopened P7-2).
		if req.Lifetime > 0 {
			res.MaxRuntime = req.Lifetime
		}
		rig, err := bootAgent(ctx, plannedAgent{name: req.Name, image: req.Image, res: res},
			broker, rec, teamSlice, arch, timeout)
		if err != nil {
			return err
		}
		rig.via = "cold"
		sb := rig.sb
		// A spawned worker is a machine in this chain like any other, and gets
		// the same session.ready/WithPosture/session.policy pair a declared
		// agent's ready loop already writes. Before P7-2 this path called the
		// recorder nowhere at all, so a spawned worker's own posture (jailed,
		// profile) went unrecorded — the exact P5-1 shape this phase exists
		// to close, found in the one door P5-1 itself never reached
		// (docs/policy-record.md §4.2).
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionReady, Agent: rig.name,
			Image: req.Image, Via: rig.via, BootMS: sb.State.BootReadyMS}.
			WithPosture(sb.State.Jailed, sb.State.Profile))
		_ = rec.Append(agentPolicyEvent(rig, plannedAgent{name: req.Name, image: req.Image, res: res}, arch))
		crew.add(rig, req.Spawner+" -> "+req.Name, req.Name+" -> "+req.Spawner)
		fmt.Fprintf(out, "  %-12s %s spawned by %s, ready in %d ms\n",
			req.Name, sb.State.ID, req.Spawner, sb.State.BootReadyMS)

		// A lifetime is part of the budget, so it is enforced here rather than
		// trusted to the agent that asked for the worker.
		if req.Lifetime > 0 {
			go func() {
				select {
				case <-time.After(req.Lifetime):
				case <-ctx.Done():
					return
				}
				fmt.Fprintf(out, "  %-12s reached its %s lifetime; stopping it\n", req.Name, req.Lifetime)
				broker.Despawn(req.Name)
				crew.remove(req.Name)
				_ = rig.stop(10*time.Second, out)
			}()
		}
		return nil
	}

	// Cold-first, fork-warm (F-D26).
	//
	// Every agent boots cold unless a template for its exact machine already
	// exists. Building one costs a memory-image write, and the reference
	// environment measured that write at 927 ms against a 109 ms cold boot: a
	// fast path that builds its own template on the spot is a slow path. What
	// pays is paying the write once — so a group whose template is cached forks
	// from it, a group whose is not boots cold and has one built in the
	// background afterwards, and the next team-up of that shape is the fast one.
	//
	// An agent its policy granted egress is in neither group: a fork cannot
	// carry a network identity, because the guest's address lives inside the
	// memory image every fork would share (F-D17).
	started := time.Now()
	candidates, cold := plan.forkPlan()
	groups := map[string][]int{}
	// groupOf is EvAgent.Group (P7-3, docs/policy-record.md §7): the
	// template *key* an agent forked from, keyed by its index into
	// plan.agents. Kept separately from groups above, which maps to the
	// template's on-disk dir — team.topology needs the content hash
	// (templateKey's own return value), never a filesystem path, the same
	// distinction the field's own doc comment draws.
	groupOf := map[int]string{}
	for _, idx := range candidates {
		key, err := templateKey(plan.agents[idx[0]], arch)
		if err != nil {
			// No manifest, no key — and a template that cannot be identified
			// must never be served. Cold-boot rather than guess.
			cold = append(cold, idx...)
			continue
		}
		if dir, ok := lookupTemplate(key); ok {
			groups[dir] = idx
			for _, i := range idx {
				groupOf[i] = key
			}
			continue
		}
		cold = append(cold, idx...)
		toBuild = append(toBuild, idx[0])
	}
	sort.Ints(cold)
	type booted struct {
		i   int
		rig *agentRig
		err error
	}
	results := make(chan booted, len(plan.agents))
	var wg sync.WaitGroup
	for _, i := range cold {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rig, err := bootAgent(ctx, plan.agents[i], broker, rec, teamSlice, arch, timeout)
			if rig != nil {
				rig.via = "cold"
			}
			results <- booted{i, rig, err}
		}(i)
	}
	for dir, idx := range groups {
		wg.Add(1)
		go func(dir string, idx []int) {
			defer wg.Done()
			// No template is built here. This group is only a group because one
			// already existed (F-D26); a group whose template was missing was
			// sent to the cold list above and will have one built afterwards.
			fmt.Fprintf(out, "  %-12s %s, forking %d from a cached template\n",
				"template", plan.agents[idx[0]].image, len(idx))
			var fwg sync.WaitGroup
			for _, i := range idx {
				fwg.Add(1)
				go func(i int) {
					defer fwg.Done()
					rig, err := forkAgent(ctx, plan.agents[i], dir, broker, rec,
						teamSlice, arch, timeout)
					results <- booted{i, rig, err}
				}(i)
			}
			fwg.Wait()
		}(dir, idx)
	}
	wg.Wait()
	// Stopped here, at the moment the last agent answered. That is when the
	// team is up and it is what the user waited for; a template still powering
	// itself off in the background is not something anybody is waiting for, and
	// counting it would be measuring our own tidying up.
	total := time.Since(started)
	close(results)

	// Collected in declaration order, so the output reads like the file and a
	// failure names the agent the user wrote rather than whichever lost a race.
	order := make([]*agentRig, len(plan.agents))
	var bootErr error
	for r := range results {
		if r.err != nil {
			if bootErr == nil {
				bootErr = fmt.Errorf("%s: %w", plan.agents[r.i].name, r.err)
			}
			continue
		}
		order[r.i] = r.rig
	}
	for _, rig := range order {
		if rig != nil {
			crew.add(rig)
		}
	}
	if bootErr != nil {
		return nil, bootErr
	}
	for i, rig := range order {
		how := ""
		if rig.via == "fork" {
			how = "  (forked)"
		}
		fmt.Fprintf(out, "  %-12s %s ready in %d ms%s\n",
			plan.agents[i].name, rig.sb.State.ID, rig.sb.State.BootReadyMS, how)
		if d := describeAgent(plan.agents[i], rig, plan.budget.CPUQuota > 0); d != "" {
			fmt.Fprintf(out, "  %-12s %s\n", "", d)
		}
		// Which path a machine took is a fact about that machine, so it belongs
		// in the record beside everything else about it rather than only in the
		// terminal that happened to be watching (F-D19).
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionReady, Agent: rig.name,
			Image: plan.agents[i].image, Via: rig.via, BootMS: rig.sb.State.BootReadyMS}.
			WithPosture(rig.sb.State.Jailed, rig.sb.State.Profile))
		_ = rec.Append(agentPolicyEvent(rig, plan.agents[i], arch))
	}
	summary := fmt.Sprintf("team up in %d ms  (%d cold)", total.Milliseconds(), len(cold))
	if forked := len(plan.agents) - len(cold); forked > 0 {
		summary = fmt.Sprintf("team up in %d ms  (%d forked from %d cached template(s), %d cold)",
			total.Milliseconds(), forked, len(groups), len(cold))
	}
	fmt.Fprintln(out, summary)

	// On the systemd path the parent's directory is systemd's to choose, so it
	// is learned from where a child actually landed rather than predicted; then
	// the cap is read back rather than assumed to have been applied (F-D11).
	if teamSlice != nil {
		for _, rig := range order {
			teamSlice.Resolve(rig.sb.State.CGroupPath)
		}
		if err := teamSlice.Confirm(); err != nil {
			return nil, err
		}
		if plan.budget.CPUQuota > 0 {
			fmt.Fprintf(out, "  %-12s %d%% of one core's CPU time for the whole team, divided by equal weight\n",
				"team cap", plan.budget.CPUQuota)
		}
		fmt.Fprintf(out, "  %-12s %s\n", "cgroup", teamSlice.Path)
	}

	// team.topology (P7-3, docs/policy-record.md §3, §6): the resolved shape
	// of the team, written once, here — after the loop above wrote every
	// agent's own session.ready/session.policy pair, so every sandbox id is
	// actually known, and after teamSlice just above resolved the collective
	// cgroup's own cap. A runtime spawn's later attach and detach are already
	// covered by team.spawn (§3), so nothing here needs to anticipate one.
	agents := make([]recorder.EvAgent, len(order))
	for i, rig := range order {
		agents[i] = recorder.EvAgent{Name: plan.agents[i].name, Sandbox: rig.sb.State.ID, Group: groupOf[i]}
	}
	storeKeys := make([]recorder.EvStoreKey, len(plan.storeRules))
	for i, r := range plan.storeRules {
		storeKeys[i] = recorder.EvStoreKey{Name: r.Name, Read: r.Read, Write: r.Write}
	}
	capture := plan.capture
	_ = rec.Append(recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: agents, Edges: plan.edgeText, StoreKeys: storeKeys,
		CPUQuota: plan.budget.CPUQuota, RecordPayloads: &capture,
	}))

	// A max_runtime is a host-side cap on one agent's wall clock, enforced here
	// for the same reason the spawn lifetime is: the budget is the user's, and
	// an agent asked to police its own deadline is not a limit (E1-6, F-D2).
	for i, rig := range order {
		limit := plan.agents[i].res.MaxRuntime
		if limit <= 0 {
			continue
		}
		go func(rig *agentRig, limit time.Duration) {
			select {
			case <-time.After(limit):
			case <-ctx.Done():
				return
			}
			_ = rec.Append(recorder.Event{Type: recorder.TypeResourceTimeout,
				Agent: rig.name, Budget: "max_runtime", BudgetMS: limit.Milliseconds(),
				ElapsedMS: limit.Milliseconds()})
			fmt.Fprintf(os.Stderr, "\nkelyfos: %s reached its max_runtime of %s; stopping it\n",
				rig.name, limit)
			crew.remove(rig.name)
			_ = rig.stop(10*time.Second, out)
		}(rig, limit)
	}

	// The cache fills behind the team, not in front of it. A shape that had no
	// template when this team booted gets one built now, in the background,
	// under the team's own context — so the next team-up of that shape forks
	// instead of cold-booting, and this one paid nothing for it (F-D26).
	for _, i := range toBuild {
		a := plan.agents[i]
		key, err := templateKey(a, arch)
		if err != nil {
			continue
		}
		templates.Add(1)
		go func(a plannedAgent, key string) {
			defer templates.Done()
			if err := storeTemplate(ctx, a, sessionID, arch, key, timeout); err != nil {
				if ctx.Err() == nil {
					fmt.Fprintf(os.Stderr,
						"kelyfos: could not cache a fork template for %s (the team is unaffected): %v\n",
						a.image, err)
				}
				return
			}
			fmt.Fprintf(out, "cached a fork template for %s; the next team of this shape will fork\n", a.image)
		}(a, key)
	}

	if err := crew.write(); err != nil {
		return nil, err
	}
	raised = true
	return &teamRig{
		plan: plan, crew: crew, rec: rec, broker: broker, slice: teamSlice,
		session: sessionID, summary: summary, cancel: cancel,
		teardown: teardown, endRecord: endRecord,
	}, nil
}

// agentRig is one team member and everything the host built around it: the
// egress path its own policy granted, the workspace it was given, and the
// cgroup slice that caps its CPU time.
//
// It exists because an agent in a team is a whole sandbox, not a name in a
// graph — `kelyfos run` builds exactly this much machinery for one, and a team
// that built less would be handing its agents a weaker version of the product.
type agentRig struct {
	name  string
	sb    *sandbox.Sandbox
	net   *sandbox.Network
	proxy *egress.Proxy
	ws    *sandbox.Workspace
	slice *sandbox.Slice
	rec   *recorder.Recorder
	// via is how this machine started: "cold" or "fork". F-D19 asks for the
	// two paths to be visible rather than inferred, so it travels into
	// team.json, into `team ps`, and into the transcript.
	via string
	// parentSession is the session a forked member's memory image came from
	// (SnapshotMeta.SourceSession, P7-2), read once in forkAgent so the ready
	// loop does not have to re-open the template's meta.json. Empty for a
	// cold-booted member, which has no ancestor.
	parentSession string

	// stop can be reached from two directions at once, so it is allowed to
	// happen exactly once. A max_runtime timer and a spawn lifetime each stop
	// their own member from a goroutine nobody waits for, and teardown stops
	// everything the roster still holds; the two are serialised by nothing, and
	// a timer already past its select does not see the team's context close.
	// Both call this. Doing it twice would shut one machine down twice, put two
	// resource receipts for one agent in the team's chain, and — the part that
	// costs the user something — run two sync-backs over one host directory,
	// where the second's removal of the .kelyfos-previous backup deletes the
	// project directory the first had just renamed into it (finding M-4).
	//
	// teamRig, the team-level object, has had exactly this guard since it was
	// written; the per-member object was never given it.
	once    sync.Once
	stopErr error
}

// stop unwinds one member in the reverse of the order it was built. The machine
// goes first, because everything after it is plumbing the machine is still
// using; the workspace is written back last, once nothing can still be writing
// into the disk it came from.
// out is where the write-back line goes. It is a parameter rather than
// os.Stdout because a team can be raised through serve-mcp, where this
// process's stdout is the protocol and a stray line of prose corrupts it. That
// is not a hypothetical: it is what the first live run of team_down did (E4-3).
func (r *agentRig) stop(timeout time.Duration, out io.Writer) error {
	// Once, whoever gets here first; a second caller waits for the first and is
	// told what it found rather than being told nothing went wrong.
	r.once.Do(func() {
		// The receipt is taken immediately before the shutdown, because every
		// counter it reads belongs to a process that is about to stop existing
		// (E1-7). In a team there is one per agent, in the team's chain, named
		// by the agent it is about.
		if u, err := r.sb.State.Sample(); err == nil {
			_ = r.rec.Append(recorder.Event{
				Type: recorder.TypeResourceSummary, Agent: r.name,
				CPUSeconds: u.CPUSeconds, PeakRSSKiB: u.PeakRSSKiB,
				NetInBytes: u.NetInBytes, NetOutBytes: u.NetOutBytes,
				DiskReadBytes: u.DiskReadBytes, DiskWriteBytes: u.DiskWriteBytes,
				MemMiB: r.sb.State.MemMiB, VcpuCount: r.sb.State.VcpuCount,
				CPUQuota:       r.sb.State.CPUQuota,
				BlockedPackets: blockedPackets(r.net),
			})
		}
		r.stopErr = r.sb.Shutdown(timeout)
		if r.proxy != nil {
			r.proxy.Close()
		}
		if r.net != nil {
			r.net.Down()
		}
		r.slice.Close()
		if r.ws != nil {
			dest, diverted, syncErr := r.ws.SyncBack()
			switch {
			case syncErr != nil:
				fmt.Fprintf(os.Stderr, "kelyfos: %s: workspace sync-back failed: %v\n", r.name, syncErr)
			case diverted:
				fmt.Fprintf(out, "  %-12s host directory changed while the team ran; results written to %s\n",
					r.name, dest)
			default:
				fmt.Fprintf(out, "  %-12s workspace written back to %s\n", r.name, dest)
			}
			_ = os.Remove(r.ws.ImagePath)
		}
	})
	return r.stopErr
}

// memberOptions is everything about a team member's machine that is the same
// whether that machine cold-boots or is forked from a template: who it is,
// whose record it writes into, what it may ask the broker, and the handler that
// carries what its guest reports into that record.
//
// It is one function rather than a literal at each boot site because a forked
// member quietly lost the last of those. bootAgent installed a guest-event
// handler, forkAgent built its options without one, and the sandbox drops the
// frame when the handler is nil — so a fork's OOM kills and plugin calls
// reached nobody. Forking is reserved for agents with no egress, which makes
// the members that lost them exactly the replica workers a `count` group
// creates: the ones most likely to hit a memory cap and the ones whose absence
// from the transcript is hardest to notice. A member is a member however its
// machine started, and the way to keep that true is to build it once.
func memberOptions(a plannedAgent, id, arch string, broker *team.Broker,
	rec *recorder.Recorder) sandbox.Options {

	return sandbox.Options{
		ID: id, Arch: arch, Flavor: a.image, Agent: a.name, MaySpawn: a.spawn != nil,
		// Everything this machine does is recorded in the team's chain, not its
		// own — including the commands `kelyfos exec` runs against it, which is
		// a different process and would otherwise open a different file (E2-7).
		Session:   rec.Session(),
		VcpuCount: a.res.CPUs, MemMiB: a.res.MemMiB, ScratchBytes: a.res.ScratchByte,
		Quiet: true,
		// The agent name comes from here and not from the frame the guest
		// sends: a guest that could name itself could name someone else.
		OnTeamRequest: func(req proto.TeamRequest) proto.TeamResponse {
			return broker.Serve(a.name, req)
		},
		// An OOM kill inside a team member is the RAM cap being reached by one
		// machine, and without this it would be the one thing that happened in
		// the team nobody could see afterwards (E1-4). The recorder write is
		// guestEventRecorder, shared with every other door that resumes a
		// machine (F3); the stderr line stays here because it names the member.
		OnGuestEvent: func(ev proto.GuestEvent) {
			guestEventRecorder(rec, a.name, a.res.MemMiB)(ev)
			if ev.Type == proto.GuestEventOOM {
				fmt.Fprintf(os.Stderr,
					"\nkelyfos: %s ran out of memory and killed %s (pid %d, %s resident of a %d MiB machine)\n",
					proto.SafeText(a.name), proto.SafeText(ev.Comm), ev.PID,
					report.HumanKiB(ev.RSSKiB), a.res.MemMiB)
			}
		},
	}
}

// bootAgent brings up one member of a team: its own network, its own caps, its
// own workspace, and a team channel wired to the shared broker.
//
// Everything it builds is torn down by the returned rig, including on the paths
// out of this function that fail — a half-built member with a live TAP and no
// machine on the end of it is worse than none.
func bootAgent(ctx context.Context, a plannedAgent, broker *team.Broker, rec *recorder.Recorder,
	slice *sandbox.TeamSlice, arch string, timeout time.Duration) (*agentRig, error) {

	id, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	rig := &agentRig{name: a.name, rec: rec}
	ok := false
	defer func() {
		if ok {
			return
		}
		// The machine first, then the plumbing it was using — the reverse of
		// the order this function builds them, and the order rig.stop uses.
		//
		// It was missing here, and bootAgent is the one caller of sandbox.New
		// whose failure the process survives: OnSpawn hands this error back to
		// the broker and the team keeps running, so a Start that failed left a
		// jail directory, three unix listeners and their accept goroutines
		// behind for the life of the host, once per failed spawn (finding L-7).
		//
		// This is deliberately not rig.stop — but not because the member never
		// got as far as running. This defer covers every failure return below
		// it, and the last of them is reached with a machine that is up:
		// an agent that has both a workspace and a secret arrives at
		// InstallTrustAnchor with a guest that has already answered WaitReady
		// and a packed /work attached to it, and the refusal there lands here.
		//
		// The reason is what rig.stop would do with such a member. It writes a
		// resource receipt into the team's chain for one the roster never held,
		// and it syncs the workspace back — which, over a host directory nothing
		// has touched since it was packed, means renaming the user's project to
		// .kelyfos-previous, on top of whatever recoverable copy an earlier run
		// left under that name, to put the disk of a machine whose boot is being
		// declared failed in its place. A boot that failed should leave the
		// directory exactly as it found it, so the image is discarded below.
		if rig.sb != nil {
			_ = rig.sb.Shutdown(5 * time.Second)
		}
		if rig.proxy != nil {
			rig.proxy.Close()
		}
		if rig.net != nil {
			rig.net.Down()
		}
		rig.slice.Close()
		if rig.ws != nil {
			_ = os.Remove(rig.ws.ImagePath)
		}
	}()

	opts := memberOptions(a, id, arch, broker, rec)
	// The I/O rates are the one thing a cold boot supplies that a fork does not:
	// they are Firecracker rate limiters on the devices this machine is about to
	// be given, and a restored machine already carries the ones its template was
	// booted with.
	opts.IO = sandbox.IOLimits{NetMbpsRx: a.res.NetMbpsRx, NetMbpsTx: a.res.NetMbpsTx,
		DiskIOPS: a.res.DiskIOPS, DiskMbps: a.res.DiskMbps}

	// The CPU quota is a host-side cap on the VMM process, exactly as a single
	// run applies it (E1-2, F-D11) — but inside the team's slice, so the two
	// ceilings compose in the kernel rather than in arithmetic here. Every agent
	// gets a child, including one with no quota of its own: being inside the
	// collective cap is the point, and a child with no cpu.max is exactly
	// "bounded only by the team" (E2-6).
	switch {
	case slice != nil:
		child, err := slice.Agent(id, a.res.CPUQuota, sandbox.DefaultCPUWeight)
		if err != nil {
			return nil, err
		}
		rig.slice = child
		opts.CPUSlice = child
	case a.res.CPUQuota > 0:
		child, err := sandbox.NewCPUSlice(id, a.res.CPUQuota)
		if err != nil {
			return nil, fmt.Errorf("cpu_quota: %w", err)
		}
		rig.slice = child
		opts.CPUSlice = child
	}

	// Egress is per agent and opt-in, built in the same order `run` builds it:
	// the TAP, then the proxy bound on it, then the firewall that makes the
	// proxy the only reachable destination, and only then a machine that can
	// send a packet anywhere (docs/networking.md). An agent with no `allow`
	// gets no interface at all — not a filtered one.
	var ca *egress.CA
	if len(a.allow) > 0 {
		rig.net, err = sandbox.NewNetwork(id)
		if err != nil {
			return nil, err
		}
		policy := egress.Policy{Allow: a.allow}
		for _, spec := range a.secrets {
			sec, err := egress.ParseSecret(spec)
			if err != nil {
				return nil, err
			}
			policy.Secrets = append(policy.Secrets, sec)
		}
		if len(policy.Secrets) > 0 {
			if ca, err = egress.NewCA(); err != nil {
				return nil, err
			}
		}
		rig.proxy = &egress.Proxy{Policy: policy, CA: ca, Peer: rig.net.GuestAddr()}
		port, err := rig.proxy.Listen(rig.net.HostIP.String() + ":0")
		if err != nil {
			return nil, err
		}
		if err := rig.net.Restrict(port); err != nil {
			return nil, err
		}
		// One record for the whole team, so an egress attempt and the message
		// that prompted it sit in the same chain. `agent` is what says which
		// machine it came from — `sandbox` names the team's session.
		wireProxyAudit(rig.proxy, rec, a.name, newBlockedOnce(os.Stderr))
		go rig.proxy.Serve()
		opts.Allow = a.allow
		opts.Net = rig.net
	}

	// A workspace is a copy in and a copy out rather than a mount, because
	// Firecracker has no shared-filesystem device. Packing happens before boot
	// because the image has to exist to be attached.
	if a.workspace != "" {
		ws, err := sandbox.PackWorkspace(a.workspace,
			filepath.Join(sandbox.Root(), "workspaces", id+".ext4"), a.res.DiskByte)
		if err != nil {
			return nil, err
		}
		rig.ws = ws
		opts.Workspace = ws
	}

	sb, err := sandbox.New(opts)
	if err != nil {
		return nil, err
	}
	rig.sb = sb
	if err := sb.Start(ctx); err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := sb.WaitReady(readyCtx); err != nil {
		_ = sb.Shutdown(5 * time.Second)
		return nil, fmt.Errorf("never became ready: %w", err)
	}
	// The guest must trust the per-run CA before anything inside it tries to
	// use the proxy for a terminated domain (D6).
	if ca != nil {
		if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			_ = sb.Shutdown(5 * time.Second)
			return nil, err
		}
	}
	ok = true
	return rig, nil
}

// bootTemplate boots the machine a group of agents will be forked from, and
// returns the snapshot directory holding it. The template itself does not
// survive: it is a mould, it is never in the roster, it never appears in the
// transcript as an agent, and it is stopped as soon as its image is on disk.
//
// It is booted with no team channel and no cgroup on purpose. It has no work to
// do and nothing to say to the broker; giving it either would put a machine in
// the team that the user never declared.
//
// That it is safe rests on one property, written down here because it is
// load-bearing and easy to break: the guest dials its team channel *lazily*, on
// the first team tool call, and nothing calls one on a template. If the guest
// ever dialled at boot instead, the failed connection would be frozen into the
// memory image and inherited by every fork made from it. The template is given
// a real agent's name for a narrower reason — the guest lists its team tools at
// all only when `kelyfos.agent` is set, and a fork must come up with them.
func bootTemplate(ctx context.Context, a plannedAgent, sessionID, arch string,
	timeout time.Duration) (tmpl *sandbox.Sandbox, snapDir string, boot, snap time.Duration, err error) {

	// Structural rather than incidental: forkable() already excludes an agent
	// with a workspace, and if that ever changes this is where the damage would
	// start — every fork would get a copy of one agent's files.
	if a.workspace != "" {
		return nil, "", 0, 0, fmt.Errorf("internal: %s has a workspace and cannot be a fork template", a.name)
	}
	id, err := sandbox.NewID()
	if err != nil {
		return nil, "", 0, 0, err
	}
	sb, err := sandbox.New(sandbox.Options{
		ID: id, Arch: arch, Flavor: a.image, Agent: a.name, MaySpawn: a.spawn != nil,
		VcpuCount: a.res.CPUs, MemMiB: a.res.MemMiB, ScratchBytes: a.res.ScratchByte,
		IO: sandbox.IOLimits{NetMbpsRx: a.res.NetMbpsRx, NetMbpsTx: a.res.NetMbpsTx,
			DiskIOPS: a.res.DiskIOPS, DiskMbps: a.res.DiskMbps},
		Quiet: true,
	})
	if err != nil {
		return nil, "", 0, 0, err
	}
	// Stopped synchronously only on the paths that fail, where correctness
	// matters and nothing is waiting. On the path that works the caller stops
	// it, off the critical path — see below.
	stopNow := func() { _ = sb.Shutdown(5 * time.Second) }
	started := time.Now()
	if err := sb.Start(ctx); err != nil {
		stopNow()
		return nil, "", 0, 0, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := sb.WaitReady(readyCtx); err != nil {
		stopNow()
		return nil, "", 0, 0, fmt.Errorf("the fork template never became ready: %w", err)
	}
	boot = time.Since(started)
	snapped := time.Now()
	// Through snapshotDir like every other snapshot path, rather than joining
	// the directory by hand — which is what this line did until P7-17/F7, and
	// is the shape the finding is about. Every component here is host-minted
	// (a literal, the session id, sandbox.NewID's hex), so this cannot fail
	// today; it is routed through the gate so that it still cannot on the day
	// one of them stops being host-minted.
	snapDir, err = snapshotDir("team-" + sessionID + "-" + id)
	if err != nil {
		stopNow()
		return nil, "", 0, 0, err
	}
	if _, _, err := sb.Snapshot(snapDir); err != nil {
		stopNow()
		_ = os.RemoveAll(snapDir)
		return nil, "", 0, 0, fmt.Errorf("snapshot the fork template: %w", err)
	}
	if err := sandbox.WriteSnapshotMeta(snapDir, sandbox.SnapshotMeta{
		Arch: arch, Flavor: a.image,
		VcpuCount: sb.State.VcpuCount, MemMiB: sb.State.MemMiB,
		// The team's own session, not the template's — the template never
		// appears in the transcript as an agent (this function's own doc
		// comment), so it has no session of its own to name. A member forked
		// from this template within the *same* team-up leaves parent_session
		// empty regardless (§3: it is the same chain, not a prior one); a
		// later team-up that forks from this cached template is a genuinely
		// different chain, and that is the case this field is for.
		SourceSession: sessionID,
	}); err != nil {
		stopNow()
		_ = os.RemoveAll(snapDir)
		return nil, "", 0, 0, err
	}
	// The template is handed back running. Everything the forks need is now on
	// disk, and asking a machine to power itself off takes as long as it takes:
	// on the reference runner it was five seconds, and it was five seconds
	// spent between "the image exists" and "the first fork starts" — the whole
	// team's spawn time paying for a machine nobody is waiting for (E2-9).
	return sb, snapDir, boot, time.Since(snapped), nil
}

// forkAgent restores one member from a template's snapshot.
//
// Everything that makes this machine *this agent* is supplied here rather than
// read out of the image: its name, the session it records into, its own cgroup
// slice, and its own team channel bound to its own name. The image is shared;
// the identity is not, and the host is the side that holds it.
func forkAgent(ctx context.Context, a plannedAgent, snapDir string, broker *team.Broker,
	rec *recorder.Recorder, slice *sandbox.TeamSlice, arch string,
	timeout time.Duration) (*agentRig, error) {

	// A Ctrl-C during a fan-out should stop the fan-out, not be discovered
	// four machines later.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	rig := &agentRig{name: a.name, rec: rec, via: "fork"}
	ok := false
	defer func() {
		if !ok {
			rig.slice.Close()
		}
	}()
	// The same options a cold-booted member gets, including the guest-event
	// handler: a restored machine binds its events channel exactly as a fresh
	// one does, so a fork whose handler was missing was a machine reporting its
	// OOM kills to a host that threw them away.
	opts := memberOptions(a, id, arch, broker, rec)
	// Inside the team's slice, exactly as a cold-booted agent is. A fork that
	// created its own top-level cgroup would be capped individually and bounded
	// by nothing — the collective cap would hold a tree with nobody in it, and
	// would say so while being wrong (E2-6).
	switch {
	case slice != nil:
		child, err := slice.Agent(id, a.res.CPUQuota, sandbox.DefaultCPUWeight)
		if err != nil {
			return nil, err
		}
		rig.slice = child
		opts.CPUSlice = child
	case a.res.CPUQuota > 0:
		child, err := sandbox.NewCPUSlice(id, a.res.CPUQuota)
		if err != nil {
			return nil, fmt.Errorf("cpu_quota: %w", err)
		}
		rig.slice = child
		opts.CPUSlice = child
	}
	sb, _, err := sandbox.Restore(snapDir, opts)
	if err != nil {
		return nil, err
	}
	rig.sb = sb
	// Best-effort: a template snapshot with no meta.json (predating this
	// field) leaves parentSession empty, the same as a cold-booted member.
	if meta, err := sandbox.ReadSnapshotMeta(snapDir); err == nil {
		rig.parentSession = meta.SourceSession
	}
	ok = true
	return rig, nil
}

// agentPolicyEvent is session.policy's one shared build point for a team
// member (P7-2, docs/policy-record.md §5), used identically by a declared
// agent's ready loop and by a runtime-spawned worker (broker.OnSpawn) — the
// same reason NewSessionPolicy is one constructor rather than an Event
// literal at each call site, one level up: a caps struct built two ways for
// two kinds of team member is exactly how one of them ends up missing a
// field the other has.
//
// No plugins, no forwards: neither is ever set for a team member today
// (host/plugins.go, host/forward.go — packPlugins and resolveForwards are
// called from `run` and `serve-mcp` alone), so recording an empty list here
// is the accurate value, not an omission. tools is the CLI vocabulary: a
// team member is driven with --sandbox <id>, the same as a standalone run.
func agentPolicyEvent(rig *agentRig, a plannedAgent, arch string) recorder.Event {
	var secrets []*egress.Secret
	if rig.proxy != nil {
		secrets = rig.proxy.Policy.Secrets
	}
	rootfsSHA, kernelSHA := sessionpolicy.Digests(sandbox.ImageDir(arch))
	return recorder.NewSessionPolicy(rig.name, recorder.PolicyFields{
		VcpuCount: a.res.CPUs, MemMiB: a.res.MemMiB, CPUQuota: a.res.CPUQuota,
		DiskBytes: a.res.DiskByte, ScratchBytes: a.res.ScratchByte,
		NetMbpsRx: a.res.NetMbpsRx, NetMbpsTx: a.res.NetMbpsTx,
		DiskIOPS: a.res.DiskIOPS, DiskMbps: a.res.DiskMbps,
		MaxRuntimeMS: a.res.MaxRuntime.Milliseconds(), IdleTimeoutMS: a.res.IdleTimeout.Milliseconds(),
		Allow: a.allow, Ports: sessionpolicy.Ports(a.allow),
		Secrets:       sessionpolicy.Secrets(secrets),
		Workspace:     a.workspace,
		RootfsSHA256:  rootfsSHA,
		KernelSHA256:  kernelSHA,
		Tools:         sessionpolicy.ToolsForCLI(false),
		ParentSession: rig.parentSession,
	})
}

// describeAgent is the one-line summary `up` prints under each member: what it
// was given, said in the same words `kelyfos run` uses for a single sandbox.
// Silence would read as "nothing was applied", which is exactly the mistake
// this whole change exists to stop.
func describeAgent(a plannedAgent, rig *agentRig, teamCapped bool) string {
	var parts []string
	if rig.net != nil {
		parts = append(parts, "egress "+strings.Join(a.allow, ","))
		for _, sec := range rig.proxy.Policy.Secrets {
			parts = append(parts, "secret "+sec.Name+"->"+sec.Domain)
		}
	}
	switch {
	case rig.slice != nil && rig.slice.Percent > 0:
		parts = append(parts, fmt.Sprintf("cpu %d%%", rig.slice.Percent))
	case rig.slice != nil && teamCapped:
		// Not "cpu 0%", which reads as no CPU at all. This agent has no ceiling
		// of its own and is bounded by the team's.
		parts = append(parts, "cpu bounded by the team")
	}
	if rig.ws != nil {
		parts = append(parts, "workspace "+a.workspace)
	}
	if a.res.MaxRuntime > 0 {
		parts = append(parts, "max_runtime "+a.res.MaxRuntime.String())
	}
	return strings.Join(parts, " · ")
}

// roster is the set of machines this team has right now: the declared agents
// and whatever workers they have been allowed to spawn. It is the only writer
// of team.json, so `ps` shows the team that exists rather than the one the
// policy file declared before anybody spawned anything.
type roster struct {
	mu      sync.Mutex
	plan    *teamPlan
	session string
	started time.Time
	running []*agentRig
	edges   []string
	slice   *sandbox.TeamSlice
	// owner records which door raised this team, so `kelyfos team down` knows
	// whether signalling the owning process is the right way to stop it.
	owner string
}

func (r *roster) add(rig *agentRig, edges ...string) {
	r.mu.Lock()
	r.running = append(r.running, rig)
	r.edges = append(r.edges, edges...)
	written := !r.started.IsZero()
	r.mu.Unlock()
	// Before the team is up there is no state file to keep current; the first
	// write happens once, when every declared agent is ready.
	if written {
		_ = r.write()
	}
}

func (r *roster) remove(name string) {
	r.mu.Lock()
	kept := r.running[:0]
	for _, rig := range r.running {
		if rig.name != name {
			kept = append(kept, rig)
		}
	}
	r.running = kept
	edges := r.edges[:0]
	for _, e := range r.edges {
		if from, to, ok := strings.Cut(e, " -> "); !ok || (from != name && to != name) {
			edges = append(edges, e)
		}
	}
	r.edges = edges
	r.mu.Unlock()
	_ = r.write()
}

func (r *roster) snapshot() []*agentRig {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*agentRig(nil), r.running...)
}

func (r *roster) write() error {
	r.mu.Lock()
	if r.started.IsZero() {
		r.started = time.Now()
	}
	st := teamState{Name: r.plan.name, PID: os.Getpid(), Session: r.session,
		StartedAt: r.started, Edges: append([]string(nil), r.edges...), Owner: r.owner}
	if r.slice != nil {
		st.CGroup, st.CPUQuota = r.slice.Path, r.slice.Percent
	}
	for _, rig := range r.running {
		st.Agents = append(st.Agents, struct {
			Name    string `json:"name"`
			Sandbox string `json:"sandbox"`
			Via     string `json:"via,omitempty"`
		}{rig.name, rig.sb.State.ID, rig.via})
	}
	r.mu.Unlock()

	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(teamStatePath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(teamStatePath(), blob, 0o600)
}

// teamMember is one row of `team ps`, as data.
//
// The command line renders these as a table and serve-mcp hands them back as
// structuredContent, which is the machine-readable form the table never was
// (E4-3, docs/mcp-surface.md §2.2). One function produces both, so the two can
// never disagree about what a team is doing.
type teamMember struct {
	Name    string `json:"agent"`
	Sandbox string `json:"sandbox"`
	// Via is how this machine started: "cold" or "fork" (F-D19).
	Via string `json:"via,omitempty"`
	// Alive is false when the sandbox behind the name is gone. Everything after
	// it is then unfilled rather than zero, and a reader can tell the
	// difference.
	Alive bool `json:"alive"`
	// Sampled is whether the live usage figures below could be read at all.
	// Without it a genuinely idle agent and one whose sample failed would both
	// render as zeroes, which are two different facts.
	Sampled    bool     `json:"sampled"`
	CPUSeconds float64  `json:"cpu_seconds,omitempty"`
	CPUQuota   int      `json:"cpu_quota_percent,omitempty"`
	Vcpus      int      `json:"vcpus,omitempty"`
	RSSKiB     int64    `json:"rss_kib,omitempty"`
	MemMiB     int      `json:"mem_mib,omitempty"`
	DiskBytes  int64    `json:"disk_write_bytes,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	Reaches    []string `json:"reaches,omitempty"`
}

// teamBudget is the collective figure, read from the parent slice's own
// accounting rather than summed from the agents: the parent is what the cap is
// on, so it is the only number that cannot disagree with the limit it is
// measured against (E2-6).
type teamBudget struct {
	CGroup       string  `json:"cgroup"`
	CPUQuota     int     `json:"cpu_quota_percent,omitempty"`
	UsedSeconds  float64 `json:"used_seconds"`
	ThrottledSec float64 `json:"throttled_seconds,omitempty"`
}

// teamPSJSON is `kelyfos team ps --json`'s shape (P7-10) — deliberately
// identical to what the team_ps MCP tool already returns as
// StructuredContent (docs/mcp-surface.md §2.2's Teams section,
// toolTeamPS in host/servemcpteam.go), so a script reading one has read
// the other and docs/teams.md documents the pair once rather than twice.
type teamPSJSON struct {
	Team      string       `json:"team"`
	Session   string       `json:"session"`
	Owner     string       `json:"owner"`
	StartedAt string       `json:"started_at"`
	Edges     []string     `json:"edges"`
	Budget    *teamBudget  `json:"budget"`
	Agents    []teamMember `json:"agents"`
}

// printJSON is the one place `kelyfos team ps --json`, `kelyfos team graph
// --json` and `kelyfos team ps --graph --json` each write their output —
// indented the same way `kelyfos bench --json` already does, so every
// --json-carrying command in this product formats the same way.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func teamMembers(st *teamState) []teamMember {
	out := make([]teamMember, 0, len(st.Agents))
	for _, a := range st.Agents {
		m := teamMember{Name: a.Name, Sandbox: a.Sandbox, Via: a.Via, Reaches: reaches(st, a.Name)}
		state, err := sandbox.Load(a.Sandbox)
		if err == nil {
			m.Alive = true
			m.CPUQuota, m.Vcpus, m.MemMiB = state.CPUQuota, state.VcpuCount, state.MemMiB
			m.Allow = state.Allow
			if u, err := state.Sample(); err == nil {
				m.Sampled = true
				m.CPUSeconds, m.RSSKiB, m.DiskBytes = u.CPUSeconds, u.RSSKiB, u.DiskWriteBytes
			}
		}
		out = append(out, m)
	}
	return out
}

func readTeamBudget(st *teamState) *teamBudget {
	if st.CGroup == "" {
		return nil
	}
	b := &teamBudget{CGroup: st.CGroup, CPUQuota: st.CPUQuota}
	if stat, err := sandbox.CPUStatAt(st.CGroup); err == nil {
		b.UsedSeconds = float64(stat["usage_usec"]) / 1e6
		b.ThrottledSec = float64(stat["throttled_usec"]) / 1e6
	}
	return b
}

func teamPS(argv []string) error {
	fs := flag.NewFlagSet("kelyfos team ps", flag.ExitOnError)
	showGraph := fs.Bool("graph", false,
		"draw the topology this team was declared with at boot (P7-7) instead of the table below")
	asJSON := fs.Bool("json", false,
		"emit structured data instead of a table — the same shape the team_ps MCP tool already returns (P7-10)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	st, err := readTeamState()
	if err != nil {
		return err
	}
	if *showGraph {
		return teamPSGraph(st, *asJSON)
	}
	if *asJSON {
		return printJSON(teamPSJSON{
			Team: st.Name, Session: st.Session, Owner: st.Owner,
			StartedAt: st.StartedAt.UTC().Format(time.RFC3339),
			Edges:     st.Edges, Budget: readTeamBudget(st), Agents: teamMembers(st),
		})
	}
	fmt.Printf("team %s — up %s, session %s\n\n", st.Name,
		time.Since(st.StartedAt).Truncate(time.Second), st.Session)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "AGENT\tSANDBOX\tBOOT\tCPU/CAP\tMEM/CAP\tDISK WRITTEN\tEGRESS\tREACHES")
	for _, m := range teamMembers(st) {
		cpu, mem, disk := "—", "—", "—"
		// "none" rather than a blank: an agent with no network interface is a
		// deliberate state and reads differently from a column that failed to
		// fill in, which is what "—" means everywhere else in this table.
		out := "?"
		if m.Alive {
			if m.Sampled {
				// Consumption beside the cap it was consumed under. A figure
				// without its ceiling is half a figure, and joining the two
				// later means trusting that nothing changed in between (E1-7).
				cpu = fmt.Sprintf("%.1fs", m.CPUSeconds)
				switch {
				case m.CPUQuota > 0:
					cpu += fmt.Sprintf("/%d%%", m.CPUQuota)
				case m.Vcpus > 0:
					cpu += fmt.Sprintf("/%dc", m.Vcpus)
				}
				mem = report.HumanKiB(m.RSSKiB)
				if m.MemMiB > 0 {
					mem += fmt.Sprintf("/%dM", m.MemMiB)
				}
				disk = humanBytes(m.DiskBytes)
			}
			out = "none"
			if len(m.Allow) > 0 {
				out = strings.Join(m.Allow, ",")
			}
		}
		via := m.Via
		if via == "" {
			via = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			m.Name, m.Sandbox, via, cpu, mem, disk, out, strings.Join(m.Reaches, " "))
	}
	_ = w.Flush()

	if b := readTeamBudget(st); b != nil {
		cap := "no collective cap"
		if b.CPUQuota > 0 {
			cap = fmt.Sprintf("cap %d%% of one core", b.CPUQuota)
		}
		used := fmt.Sprintf("%.1fs used", b.UsedSeconds)
		if b.ThrottledSec > 0 {
			used += fmt.Sprintf(", %.1fs throttled", b.ThrottledSec)
		}
		fmt.Printf("\nteam budget  %s \u00b7 %s\n  %s\n", cap, used, b.CGroup)
	}

	fmt.Println("\nedges")
	for _, e := range st.Edges {
		fmt.Println("  " + e)
	}
	return nil
}

// reaches reads the declared edges back out of the state file, so `ps` shows
// the topology that is running rather than the one the file says today — the
// two can differ if someone edits the policy while a team is up.
func reaches(st *teamState, agent string) []string {
	var out []string
	for _, e := range st.Edges {
		from, to, ok := strings.Cut(e, " -> ")
		if !ok {
			continue
		}
		if from == agent {
			out = append(out, to)
		}
	}
	sort.Strings(out)
	return out
}

func teamDown(argv []string) error {
	fs := flag.NewFlagSet("kelyfos team down", flag.ExitOnError)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	st, err := readTeamState()
	if err != nil {
		return err
	}
	// The team is torn down by the process that brought it up, because that
	// process holds the workspaces, the proxies and the recorder. Signalling it
	// is not a shortcut around doing the work — it is how the work gets done by
	// the only party that can do it.
	if st.PID == 0 {
		return fmt.Errorf("the team state names no process to stop")
	}
	// A team raised through serve-mcp is held by the server, whose process is
	// also holding every sandbox it created. Signalling that would stop all of
	// it, which is not what somebody typing `team down` is asking for.
	if st.Owner == ownerServeMCP {
		return fmt.Errorf("team %s was raised through `kelyfos serve-mcp` (pid %d), which is holding "+
			"it along with whatever else that server made.\n"+
			"    retire it with the server's team_down tool, or stop the server itself, which takes "+
			"the team down with it.", st.Name, st.PID)
	}
	if err := syscall.Kill(st.PID, syscall.SIGTERM); err != nil {
		_ = os.Remove(teamStatePath())
		return fmt.Errorf("the team's process (%d) is gone; cleared its state", st.PID)
	}
	fmt.Printf("stopping team %s (pid %d)\n", st.Name, st.PID)
	for i := 0; i < 120; i++ {
		if _, err := os.Stat(teamStatePath()); os.IsNotExist(err) {
			fmt.Println("team down")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("team %s did not stop within a minute", st.Name)
}

func readTeamState() (*teamState, error) {
	blob, err := os.ReadFile(teamStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no team is running")
	}
	if err != nil {
		return nil, err
	}
	var st teamState
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, fmt.Errorf("the team state file is unreadable: %w", err)
	}
	return &st, nil
}
