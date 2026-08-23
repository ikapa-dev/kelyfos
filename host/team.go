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
	} `json:"agents"`
	Edges []string `json:"edges"`
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

	crew := &roster{plan: plan, session: sessionID, edges: plan.edgeText}
	teardown := func() {
		// Reverse order, so the agent booted last is stopped first — the same
		// order a single run's defers would have taken. Spawned workers are in
		// this list too, and are the last in, so they are the first out.
		running := crew.snapshot()
		for i := len(running) - 1; i >= 0; i-- {
			if err := running[i].Shutdown(10 * time.Second); err != nil {
				fmt.Fprintf(os.Stderr, "kelyfos: %s: %v\n", running[i].State.Agent, err)
			}
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
		res := plan.spawnResources(req.Spawner)
		sb, err := bootAgent(ctx, plannedAgent{name: req.Name, image: req.Image, res: res},
			broker, *arch, *timeout)
		if err != nil {
			return err
		}
		crew.add(sb, req.Spawner+" -> "+req.Name, req.Name+" -> "+req.Spawner)
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
				_ = sb.Shutdown(10 * time.Second)
			}()
		}
		return nil
	}

	// Booted together, not one after another. Each agent is an independent
	// machine with its own TAP, its own image and its own caps, and nothing
	// about the second depends on the first — so a team of five costs one boot
	// rather than five (F-D17 on why this is not fork-based).
	started := time.Now()
	type booted struct {
		i   int
		sb  *sandbox.Sandbox
		err error
	}
	results := make(chan booted, len(plan.agents))
	var wg sync.WaitGroup
	for i, a := range plan.agents {
		wg.Add(1)
		go func(i int, a plannedAgent) {
			defer wg.Done()
			sb, err := bootAgent(ctx, a, broker, *arch, *timeout)
			results <- booted{i, sb, err}
		}(i, a)
	}
	wg.Wait()
	close(results)

	// Collected in declaration order, so the output reads like the file and a
	// failure names the agent the user wrote rather than whichever lost a race.
	order := make([]*sandbox.Sandbox, len(plan.agents))
	var bootErr error
	for r := range results {
		if r.err != nil {
			if bootErr == nil {
				bootErr = fmt.Errorf("%s: %w", plan.agents[r.i].name, r.err)
			}
			continue
		}
		order[r.i] = r.sb
	}
	for _, sb := range order {
		if sb != nil {
			crew.add(sb)
		}
	}
	if bootErr != nil {
		return bootErr
	}
	for i, sb := range order {
		fmt.Printf("  %-12s %s ready in %d ms\n", plan.agents[i].name, sb.State.ID, sb.State.BootReadyMS)
	}
	fmt.Printf("team up in %d ms\n", time.Since(started).Milliseconds())

	if err := crew.write(); err != nil {
		return err
	}
	fmt.Println("\nCtrl-C to stop the team.")
	<-ctx.Done()
	fmt.Println("\nstopping...")
	return nil
}

// bootAgent brings up one member of a team: its own network, its own caps, its
// own workspace, and a team channel wired to the shared broker.
func bootAgent(ctx context.Context, a plannedAgent, broker *team.Broker, arch string, timeout time.Duration) (*sandbox.Sandbox, error) {
	id, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	opts := sandbox.Options{
		ID: id, Arch: arch, Flavor: a.image, Agent: a.name, MaySpawn: a.spawn != nil,
		VcpuCount: a.res.CPUs, MemMiB: a.res.MemMiB, ScratchBytes: a.res.ScratchByte,
		IO: sandbox.IOLimits{NetMbpsRx: a.res.NetMbpsRx, NetMbpsTx: a.res.NetMbpsTx,
			DiskIOPS: a.res.DiskIOPS, DiskMbps: a.res.DiskMbps},
		Quiet: true,
		// The agent name comes from here and not from the frame the guest
		// sends: a guest that could name itself could name someone else.
		OnTeamRequest: func(req proto.TeamRequest) proto.TeamResponse {
			return broker.Serve(a.name, req)
		},
	}
	sb, err := sandbox.New(opts)
	if err != nil {
		return nil, err
	}
	if err := sb.Start(ctx); err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := sb.WaitReady(readyCtx); err != nil {
		_ = sb.Shutdown(5 * time.Second)
		return nil, fmt.Errorf("never became ready: %w", err)
	}
	return sb, nil
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
	running []*sandbox.Sandbox
	edges   []string
}

func (r *roster) add(sb *sandbox.Sandbox, edges ...string) {
	r.mu.Lock()
	r.running = append(r.running, sb)
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
	for _, sb := range r.running {
		if sb.State.Agent != name {
			kept = append(kept, sb)
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

func (r *roster) snapshot() []*sandbox.Sandbox {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*sandbox.Sandbox(nil), r.running...)
}

func (r *roster) write() error {
	r.mu.Lock()
	if r.started.IsZero() {
		r.started = time.Now()
	}
	st := teamState{Name: r.plan.name, PID: os.Getpid(), Session: r.session,
		StartedAt: r.started, Edges: append([]string(nil), r.edges...)}
	for _, sb := range r.running {
		st.Agents = append(st.Agents, struct {
			Name    string `json:"name"`
			Sandbox string `json:"sandbox"`
		}{sb.State.Agent, sb.State.ID})
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
	fmt.Fprintln(w, "AGENT\tSANDBOX\tCPU\tMEM\tDISK WRITTEN\tREACHES")
	for _, a := range st.Agents {
		cpu, mem, disk := "—", "—", "—"
		state, err := sandbox.Load(a.Sandbox)
		if err == nil {
			if u, err := state.Sample(); err == nil {
				cpu = fmt.Sprintf("%.1fs", u.CPUSeconds)
				mem = report.HumanKiB(u.RSSKiB)
				disk = humanBytes(u.DiskWriteBytes)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Name, a.Sandbox, cpu, mem, disk,
			strings.Join(reaches(st, a.Name), " "))
	}
	_ = w.Flush()

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
