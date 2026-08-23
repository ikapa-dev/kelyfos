package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"github.com/p4r4n0rm4l/KelyfOS/internal/team"
)

const teamUsage = `usage: kelyfos team up | ps | down

  up     boot the team declared in kelyfos.toml and hold it until Ctrl-C
  ps     show the running team: agents, edges, and what each is consuming
  down   stop a running team, syncing every workspace on the way out

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
	if cfg == nil || cfg.Team == nil {
		return fmt.Errorf("no [team] section in this project's %s — see docs/teams.md", config.FileName)
	}
	if _, err := os.Stat(teamStatePath()); err == nil {
		return fmt.Errorf("a team is already running; stop it with `kelyfos team down`")
	}

	plan, err := planTeam(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("team %s: %d agents, %d edges\n", plan.name, len(plan.agents), len(plan.edgeText))

	// One flight recorder for the whole team, so a team produces one verifiable
	// transcript rather than five that have to be correlated afterwards. The
	// session is named for the team, not for any one machine in it.
	sessionID, err := sandbox.NewID()
	if err != nil {
		return err
	}
	rec, err := recorder.Open(sandbox.Root(), sessionID)
	if err != nil {
		return err
	}
	defer func() {
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "shutdown",
			DurationMS: rec.Since().Milliseconds()})
		_ = rec.Close()
	}()
	_ = rec.Append(recorder.Event{Type: recorder.TypeSessionStart, Arch: *arch,
		Kelyfos: Version, Argv: os.Args})

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
			return err
		}
		broker.Store = store
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The collective cap, built before any agent so that every agent is inside
	// it from the instant it exists — a budget that arrives after the machines
	// is a budget with a hole in it. A team that declared no CPU numbers at all
	// gets no cgroup machinery, and so needs neither systemd nor a delegated
	// cgroup to run (E2-6).
	var teamSlice *sandbox.TeamSlice
	if plan.needsSlice() {
		teamSlice, err = sandbox.NewTeamSlice(plan.name, plan.budget.CPUQuota)
		if err != nil {
			return err
		}
	}

	crew := &roster{plan: plan, session: sessionID, edges: plan.edgeText, slice: teamSlice}
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
			if err := running[i].stop(10 * time.Second); err != nil {
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
	defer teardown()

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
		rig, err := bootAgent(ctx, plannedAgent{name: req.Name, image: req.Image, res: res},
			broker, rec, teamSlice, *arch, *timeout)
		if err != nil {
			return err
		}
		rig.via = "cold"
		sb := rig.sb
		crew.add(rig, req.Spawner+" -> "+req.Name, req.Name+" -> "+req.Spawner)
		fmt.Printf("  %-12s %s spawned by %s, ready in %d ms\n",
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
				fmt.Printf("  %-12s reached its %s lifetime; stopping it\n", req.Name, req.Lifetime)
				broker.Despawn(req.Name)
				crew.remove(req.Name)
				_ = rig.stop(10 * time.Second)
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
	for _, idx := range candidates {
		key, err := templateKey(plan.agents[idx[0]], *arch)
		if err != nil {
			// No manifest, no key — and a template that cannot be identified
			// must never be served. Cold-boot rather than guess.
			cold = append(cold, idx...)
			continue
		}
		if dir, ok := lookupTemplate(key); ok {
			groups[dir] = idx
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
			rig, err := bootAgent(ctx, plan.agents[i], broker, rec, teamSlice, *arch, *timeout)
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
			fmt.Printf("  %-12s %s, forking %d from a cached template\n",
				"template", plan.agents[idx[0]].image, len(idx))
			var fwg sync.WaitGroup
			for _, i := range idx {
				fwg.Add(1)
				go func(i int) {
					defer fwg.Done()
					rig, err := forkAgent(ctx, plan.agents[i], dir, broker, rec,
						teamSlice, *arch, *timeout)
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
		return bootErr
	}
	for i, rig := range order {
		how := ""
		if rig.via == "fork" {
			how = "  (forked)"
		}
		fmt.Printf("  %-12s %s ready in %d ms%s\n",
			plan.agents[i].name, rig.sb.State.ID, rig.sb.State.BootReadyMS, how)
		if d := describeAgent(plan.agents[i], rig, plan.budget.CPUQuota > 0); d != "" {
			fmt.Printf("  %-12s %s\n", "", d)
		}
		// Which path a machine took is a fact about that machine, so it belongs
		// in the record beside everything else about it rather than only in the
		// terminal that happened to be watching (F-D19).
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionReady, Agent: rig.name,
			Image: plan.agents[i].image, Via: rig.via, BootMS: rig.sb.State.BootReadyMS})
	}
	if forked := len(plan.agents) - len(cold); forked > 0 {
		fmt.Printf("team up in %d ms  (%d forked from %d cached template(s), %d cold)\n",
			total.Milliseconds(), forked, len(groups), len(cold))
	} else {
		fmt.Printf("team up in %d ms  (%d cold)\n", total.Milliseconds(), len(cold))
	}

	// On the systemd path the parent's directory is systemd's to choose, so it
	// is learned from where a child actually landed rather than predicted; then
	// the cap is read back rather than assumed to have been applied (F-D11).
	if teamSlice != nil {
		for _, rig := range order {
			teamSlice.Resolve(rig.sb.State.CGroupPath)
		}
		if err := teamSlice.Confirm(); err != nil {
			return err
		}
		if plan.budget.CPUQuota > 0 {
			fmt.Printf("  %-12s %d%% of one core's CPU time for the whole team, divided by equal weight\n",
				"team cap", plan.budget.CPUQuota)
		}
		fmt.Printf("  %-12s %s\n", "cgroup", teamSlice.Path)
	}

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
			_ = rig.stop(10 * time.Second)
		}(rig, limit)
	}

	// The cache fills behind the team, not in front of it. A shape that had no
	// template when this team booted gets one built now, in the background,
	// under the team's own context — so the next team-up of that shape forks
	// instead of cold-booting, and this one paid nothing for it (F-D26).
	for _, i := range toBuild {
		a := plan.agents[i]
		key, err := templateKey(a, *arch)
		if err != nil {
			continue
		}
		templates.Add(1)
		go func(a plannedAgent, key string) {
			defer templates.Done()
			if err := storeTemplate(ctx, a, sessionID, *arch, key, *timeout); err != nil {
				if ctx.Err() == nil {
					fmt.Fprintf(os.Stderr,
						"kelyfos: could not cache a fork template for %s (the team is unaffected): %v\n",
						a.image, err)
				}
				return
			}
			fmt.Printf("cached a fork template for %s; the next team of this shape will fork\n", a.image)
		}(a, key)
	}

	if err := crew.write(); err != nil {
		return err
	}
	fmt.Println("\nCtrl-C to stop the team.")
	<-ctx.Done()
	fmt.Println("\nstopping...")
	return nil
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
}

// stop unwinds one member in the reverse of the order it was built. The machine
// goes first, because everything after it is plumbing the machine is still
// using; the workspace is written back last, once nothing can still be writing
// into the disk it came from.
func (r *agentRig) stop(timeout time.Duration) error {
	// The receipt is taken immediately before the shutdown, because every
	// counter it reads belongs to a process that is about to stop existing
	// (E1-7). In a team there is one per agent, in the team's chain, named by
	// the agent it is about.
	if u, err := r.sb.State.Sample(); err == nil {
		_ = r.rec.Append(recorder.Event{
			Type: recorder.TypeResourceSummary, Agent: r.name,
			CPUSeconds: u.CPUSeconds, PeakRSSKiB: u.PeakRSSKiB,
			NetInBytes: u.NetInBytes, NetOutBytes: u.NetOutBytes,
			DiskReadBytes: u.DiskReadBytes, DiskWriteBytes: u.DiskWriteBytes,
			MemMiB: r.sb.State.MemMiB, VcpuCount: r.sb.State.VcpuCount,
			CPUQuota: r.sb.State.CPUQuota,
		})
	}
	err := r.sb.Shutdown(timeout)
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
			fmt.Printf("  %-12s host directory changed while the team ran; results written to %s\n",
				r.name, dest)
		default:
			fmt.Printf("  %-12s workspace written back to %s\n", r.name, dest)
		}
		_ = os.Remove(r.ws.ImagePath)
	}
	return err
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

	opts := sandbox.Options{
		ID: id, Arch: arch, Flavor: a.image, Agent: a.name, MaySpawn: a.spawn != nil,
		// Everything this machine does is recorded in the team's chain, not its
		// own — including the commands `kelyfos exec` runs against it, which is
		// a different process and would otherwise open a different file (E2-7).
		Session:   rec.Session(),
		VcpuCount: a.res.CPUs, MemMiB: a.res.MemMiB, ScratchBytes: a.res.ScratchByte,
		IO: sandbox.IOLimits{NetMbpsRx: a.res.NetMbpsRx, NetMbpsTx: a.res.NetMbpsTx,
			DiskIOPS: a.res.DiskIOPS, DiskMbps: a.res.DiskMbps},
		Quiet: true,
		// The agent name comes from here and not from the frame the guest
		// sends: a guest that could name itself could name someone else.
		OnTeamRequest: func(req proto.TeamRequest) proto.TeamResponse {
			return broker.Serve(a.name, req)
		},
		// An OOM kill inside a team member is the RAM cap being reached by one
		// machine, and without this it would be the one thing that happened in
		// the team nobody could see afterwards (E1-4).
		OnGuestEvent: func(ev proto.GuestEvent) {
			if ev.Type != proto.GuestEventOOM {
				return
			}
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeResourceOOM, Source: recorder.SourceGuest, Agent: a.name,
				PID: ev.PID, Comm: ev.Comm, RSSKiB: ev.RSSKiB, MemMiB: a.res.MemMiB,
			})
			fmt.Fprintf(os.Stderr,
				"\nkelyfos: %s ran out of memory and killed %s (pid %d, %s resident of a %d MiB machine)\n",
				a.name, ev.Comm, ev.PID, report.HumanKiB(ev.RSSKiB), a.res.MemMiB)
		},
	}

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
		rig.proxy = &egress.Proxy{Policy: policy, CA: ca}
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
		rig.proxy.OnSecret = func(name, host string) {
			_ = rec.Append(recorder.Event{Type: recorder.TypeSecretUse,
				Agent: a.name, Name: name, Host: host})
		}
		rig.proxy.OnEvent = func(at egress.Attempt) {
			allowed := at.Allowed
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeEgressAttempt, Agent: a.name,
				Host: at.Host, Port: at.Port, Allowed: &allowed,
				Reason: at.Reason, Mode: at.Mode,
				BytesIn: at.BytesIn, BytesOut: at.BytesOut,
			})
		}
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
	snapDir = filepath.Join(sandbox.Root(), "snapshots", "team-"+sessionID+"-"+id)
	if _, _, err := sb.Snapshot(snapDir); err != nil {
		stopNow()
		_ = os.RemoveAll(snapDir)
		return nil, "", 0, 0, fmt.Errorf("snapshot the fork template: %w", err)
	}
	if err := sandbox.WriteSnapshotMeta(snapDir, sandbox.SnapshotMeta{
		Arch: arch, Flavor: a.image,
		VcpuCount: sb.State.VcpuCount, MemMiB: sb.State.MemMiB,
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
	opts := sandbox.Options{
		ID: id, Arch: arch, Flavor: a.image, Agent: a.name, Session: rec.Session(),
		MaySpawn:  a.spawn != nil,
		VcpuCount: a.res.CPUs, MemMiB: a.res.MemMiB, ScratchBytes: a.res.ScratchByte,
		Quiet: true,
		OnTeamRequest: func(req proto.TeamRequest) proto.TeamResponse {
			return broker.Serve(a.name, req)
		},
	}
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
	ok = true
	return rig, nil
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
		StartedAt: r.started, Edges: append([]string(nil), r.edges...)}
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

func teamPS(argv []string) error {
	fs := flag.NewFlagSet("kelyfos team ps", flag.ExitOnError)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	st, err := readTeamState()
	if err != nil {
		return err
	}
	fmt.Printf("team %s — up %s, session %s\n\n", st.Name,
		time.Since(st.StartedAt).Truncate(time.Second), st.Session)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "AGENT\tSANDBOX\tBOOT\tCPU/CAP\tMEM/CAP\tDISK WRITTEN\tEGRESS\tREACHES")
	for _, a := range st.Agents {
		cpu, mem, disk := "—", "—", "—"
		// "none" rather than a blank: an agent with no network interface is a
		// deliberate state and reads differently from a column that failed to
		// fill in, which is what "—" means everywhere else in this table.
		out := "?"
		state, err := sandbox.Load(a.Sandbox)
		if err == nil {
			if u, err := state.Sample(); err == nil {
				// Consumption beside the cap it was consumed under. A figure
				// without its ceiling is half a figure, and joining the two
				// later means trusting that nothing changed in between (E1-7).
				cpu = fmt.Sprintf("%.1fs", u.CPUSeconds)
				switch {
				case state.CPUQuota > 0:
					cpu += fmt.Sprintf("/%d%%", state.CPUQuota)
				case state.VcpuCount > 0:
					cpu += fmt.Sprintf("/%dc", state.VcpuCount)
				}
				mem = report.HumanKiB(u.RSSKiB)
				if state.MemMiB > 0 {
					mem += fmt.Sprintf("/%dM", state.MemMiB)
				}
				disk = humanBytes(u.DiskWriteBytes)
			}
			out = "none"
			if len(state.Allow) > 0 {
				out = strings.Join(state.Allow, ",")
			}
		}
		via := a.Via
		if via == "" {
			via = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.Name, a.Sandbox, via, cpu, mem, disk, out,
			strings.Join(reaches(st, a.Name), " "))
	}
	_ = w.Flush()

	// The collective figure, read from the parent slice's own accounting rather
	// than summed from the agents: the parent is what the cap is on, so it is
	// the only number that cannot disagree with the limit it is measured
	// against (E2-6). A team with no CPU numbers has no slice and no line.
	if st.CGroup != "" {
		cap := "no collective cap"
		if st.CPUQuota > 0 {
			cap = fmt.Sprintf("cap %d%% of one core", st.CPUQuota)
		}
		used := "\u2014"
		if stat, err := sandbox.CPUStatAt(st.CGroup); err == nil {
			used = fmt.Sprintf("%.1fs used", float64(stat["usage_usec"])/1e6)
			if t := stat["throttled_usec"]; t > 0 {
				used += fmt.Sprintf(", %.1fs throttled", float64(t)/1e6)
			}
		}
		fmt.Printf("\nteam budget  %s \u00b7 %s\n  %s\n", cap, used, st.CGroup)
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
