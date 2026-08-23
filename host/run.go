package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/exitcode"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

func runCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos run", flag.ExitOnError)
	var (
		arch    = fs.String("arch", sandbox.HostArch(), "guest architecture (aarch64|x86_64)")
		flavor  = fs.String("image", "base", "image flavor")
		imgDir  = fs.String("image-dir", "", "directory holding the kernel and rootfs (default: the build output)")
		vcpus   = fs.Int("vcpus", 0, "alias for --cpus, kept so v0.3 command lines keep working")
		cpus    = fs.Int("cpus", 0, "virtual CPUs the guest sees (default 2)")
		disk    = fs.String("disk", "", "ceiling on the packed workspace image, e.g. 2G (default: no ceiling)")
		quota   = fs.String("cpu-quota", "", "host CPU time cap as a share of one core, e.g. 150% (default: uncapped)")
		memStr  = fs.String("mem", "", "guest memory, e.g. 2G or 512M; a bare number is MiB (default 512)")
		maxRun  = fs.String("max-runtime", "", "stop the sandbox after this long, e.g. 30m (default: no limit)")
		idleFor = fs.String("idle-timeout", "", "stop the sandbox after this long with no activity, e.g. 5m (default: no limit)")
		console = fs.Bool("console", false, "stream the guest serial console")
		verbose = fs.Bool("verbose-boot", false, "drop the quiet parameter from the kernel command line")
		timeout = fs.Duration("ready-timeout", 30*time.Second, "how long to wait for the guest to become ready")
		allow   = fs.String("allow", "", "comma-separated egress allowlist, e.g. github.com,pypi.org. Without it the sandbox has no network interface at all.")
		wsDir   = fs.String("workspace", "", "host directory to make available at /work inside the sandbox")
		noSync  = fs.Bool("no-sync-back", false, "do not write the workspace back to the host on shutdown")
		secrets multiFlag
	)
	fs.Var(&secrets, "secret", "attach a credential to a domain: NAME@domain[:bearer|basic]. "+
		"The value is read from the host environment and never enters the guest. Repeatable.")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `usage: kelyfos run [flags]
       kelyfos run [flags] -- <command>...

Boots a sandbox. With no trailing command it keeps running until Ctrl-C.

With one, that command runs on the host for as long as the sandbox lives, with
KELYFOS_SANDBOX set so its `+"`kelyfos mcp`"+` and `+"`kelyfos exec`"+` attach to this machine.
The sandbox is torn down when the command exits, and kelyfos exits with its
status. This is how you hand an agent a sandbox and nothing else:

    kelyfos run --workspace . --allow github.com -- claude`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	command := fs.Args()

	// A committed policy file supplies the defaults; an explicit flag always
	// wins. Knowing which flags the user actually typed is the whole trick —
	// otherwise a default is indistinguishable from a choice, and the file
	// could never override anything.
	typed := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { typed[f.Name] = true })

	// --vcpus is v0.3's name for --cpus. Accept both, refuse a contradiction
	// rather than silently picking one (F-D10).
	var diskCeiling int64
	if typed["cpus"] && typed["vcpus"] && *cpus != *vcpus {
		return fmt.Errorf("--cpus %d and --vcpus %d disagree; --vcpus is an alias for --cpus", *cpus, *vcpus)
	}
	if typed["vcpus"] && !typed["cpus"] {
		*cpus = *vcpus
	}
	if *disk != "" {
		n, err := config.ParseSize(*disk)
		if err != nil {
			return fmt.Errorf("--disk %s: %w", *disk, err)
		}
		diskCeiling = n
	}
	var maxRuntime, idleTimeout time.Duration
	for _, b := range []struct {
		flag  string
		value *string
		into  *time.Duration
	}{{"max-runtime", maxRun, &maxRuntime}, {"idle-timeout", idleFor, &idleTimeout}} {
		if *b.value == "" {
			continue
		}
		d, err := config.ParseDuration(*b.value, "--"+b.flag)
		if err != nil {
			return err
		}
		*b.into = d
	}

	cpuQuota := 0
	if *quota != "" {
		n, err := config.ParsePercent(*quota)
		if err != nil {
			return err
		}
		cpuQuota = n
	}
	memMiB := new(int)
	*memMiB = 512
	if *memStr != "" {
		n, err := config.ParseMemMiB(*memStr)
		if err != nil {
			return fmt.Errorf("--mem %s: %w", *memStr, err)
		}
		*memMiB = n
	}

	var ioLimits sandbox.IOLimits
	var scratchBytes int64

	cfg, cfgErr := loadPolicy()
	if cfgErr != nil {
		return cfgErr
	}
	if cfg != nil {
		fmt.Printf("policy: %s\n", cfg.Path)
		if cfg.Image != "" && !typed["image"] {
			*flavor = cfg.Image
		}
		if cfg.Arch != "" && !typed["arch"] {
			*arch = cfg.Arch
		}
		// [resources] declares ceilings, not defaults: a flag may ask for less,
		// never for more (docs/resources.md). Refusing rather than clamping,
		// because a clamped run reports limits nobody asked for while the
		// command line still reads what the user typed.
		if err := ceiling("cpus", "cpus", cfg, cfg.ResCPUs, cpus, typed["cpus"] || typed["vcpus"],
			func(v int) string { return fmt.Sprint(v) }); err != nil {
			return err
		}
		if err := ceiling("mem", "mem", cfg, cfg.ResMemMiB, memMiB, typed["mem"],
			func(v int) string { return fmt.Sprintf("%d MiB", v) }); err != nil {
			return err
		}
		if err := ceiling("cpu_quota", "cpu-quota", cfg, cfg.ResCPUQuota, &cpuQuota, typed["cpu-quota"],
			func(v int) string { return fmt.Sprintf("%d%%", v) }); err != nil {
			return err
		}
		if cfg.ResDiskByte != 0 {
			if diskCeiling == 0 {
				diskCeiling = cfg.ResDiskByte
			} else if diskCeiling > cfg.ResDiskByte {
				line, _ := cfg.Ceiling("disk")
				return fmt.Errorf("--disk %s exceeds the ceiling disk = %d bytes set at %s:%d\n"+
					"    lower the flag, or raise the ceiling in the policy file",
					*disk, cfg.ResDiskByte, cfg.Path, line)
			}
		}
		if len(cfg.Allow) > 0 && !typed["allow"] {
			*allow = strings.Join(cfg.Allow, ",")
		}
		if len(cfg.Secrets) > 0 && len(secrets) == 0 {
			secrets = append(secrets, cfg.Secrets...)
		}
		if cfg.Workspace != "" && !typed["workspace"] {
			// Relative to the policy file, not the working directory: the file
			// describes its own project, wherever it is invoked from.
			ws := cfg.Workspace
			if !filepath.IsAbs(ws) {
				ws = filepath.Join(filepath.Dir(cfg.Path), ws)
			}
			*wsDir = ws
		}
		if cfg.Vcpus > 0 && !typed["vcpus"] && !typed["cpus"] && *cpus == 0 {
			*cpus = cfg.Vcpus
		}
		if cfg.MemMiB > 0 && !typed["mem"] && cfg.ResMemMiB == 0 {
			*memMiB = cfg.MemMiB
		}
		// The I/O rates have no flags by design (E1-3 names toml keys only), so
		// there is no request to check against a ceiling: the declared value is
		// the value.
		scratchBytes = cfg.ResScratchByte
		// A budget behaves like every other ceiling: the file may only be asked
		// for less, and asking for more refuses rather than clamps.
		for _, b := range []struct {
			key, flag string
			limit     time.Duration
			into      *time.Duration
		}{
			{"max_runtime", "max-runtime", cfg.ResMaxRuntime, &maxRuntime},
			{"idle_timeout", "idle-timeout", cfg.ResIdleTimeout, &idleTimeout},
		} {
			if b.limit == 0 {
				continue
			}
			if *b.into == 0 {
				*b.into = b.limit
				continue
			}
			if *b.into > b.limit {
				line, _ := cfg.Ceiling(b.key)
				return fmt.Errorf("--%s %s exceeds the ceiling %s = %s set at %s:%d\n"+
					"    lower the flag, or raise the ceiling in the policy file",
					b.flag, *b.into, b.key, b.limit, cfg.Path, line)
			}
		}
		ioLimits = sandbox.IOLimits{
			NetMbpsRx: cfg.ResNetMbpsRx,
			NetMbpsTx: cfg.ResNetMbpsTx,
			DiskIOPS:  cfg.ResDiskIOPS,
			DiskMbps:  cfg.ResDiskMbps,
		}
	}

	if *cpus == 0 {
		*cpus = 2
	}
	// A scratch cap larger than the machine's RAM is not a generous limit, it is
	// no limit: the tmpfs it sizes lives in that same RAM and can never reach
	// it. Refusing beats accepting, for the same reason the parser refuses a key
	// it cannot enforce — a limits file whose limit is inert is the worst
	// outcome available (docs/resources.md).
	if scratchBytes > 0 && scratchBytes > int64(*memMiB)<<20 {
		line, _ := cfg.Ceiling("scratch")
		return fmt.Errorf("scratch = %d bytes at %s:%d is larger than the %d MiB the machine has\n"+
			"    the scratch tmpfs lives in that memory, so a cap above it can never be reached",
			scratchBytes, cfg.Path, line, *memMiB)
	}

	sandboxID, err := sandbox.NewID()
	if err != nil {
		return err
	}

	var cpuSlice *sandbox.Slice
	var consoleOut io.Writer
	if *console || *verbose {
		consoleOut = prefixWriter{os.Stderr, "[guest] "}
	}

	if cpuQuota > 0 {
		slice, err := sandbox.NewCPUSlice(sandboxID, cpuQuota)
		if err != nil {
			return err
		}
		defer slice.Close()
		cpuSlice = slice
	}

	// The guest reports; the host records. onGuestEvent is late-bound because
	// the flight recorder is opened after the sandbox is built, and a guest that
	// managed to report before then must not take the process down with a nil
	// call (docs/events.md §1).
	var onGuestEvent atomic.Pointer[func(proto.GuestEvent)]

	opts := sandbox.Options{
		CPUSlice:     cpuSlice,
		IO:           ioLimits,
		ScratchBytes: scratchBytes,
		OnGuestEvent: func(ev proto.GuestEvent) {
			if fn := onGuestEvent.Load(); fn != nil {
				(*fn)(ev)
			}
		},
		Arch:      *arch,
		Flavor:    *flavor,
		ImageDir:  *imgDir,
		VcpuCount: *cpus,
		MemMiB:    *memMiB,
		Quiet:     !*verbose,
		Console:   consoleOut,
	}

	// Egress is opt-in and, when opted into, is built before the VM exists:
	// the TAP first, then the proxy bound on it, then the firewall that makes
	// the proxy the only reachable destination, and only then a machine that
	// can send a packet anywhere (docs/networking.md).
	var proxy *egress.Proxy
	var ca *egress.CA
	if list := splitAllow(*allow); len(list) > 0 {
		opts.Allow = list
		opts.Net, err = sandbox.NewNetwork(sandboxID)
		if err != nil {
			return err
		}
		defer opts.Net.Down()

		policy := egress.Policy{Allow: list}
		for _, spec := range secrets {
			sec, err := egress.ParseSecret(spec)
			if err != nil {
				return err
			}
			// A secret is only useful for a domain traffic may reach at all.
			if !containsDomain(list, sec.Domain) {
				return fmt.Errorf("--secret %s: %s is not in --allow", spec, sec.Domain)
			}
			policy.Secrets = append(policy.Secrets, sec)
		}
		if len(policy.Secrets) > 0 {
			if ca, err = egress.NewCA(); err != nil {
				return err
			}
		}
		proxy = &egress.Proxy{Policy: policy, CA: ca}
		port, err := proxy.Listen(opts.Net.HostIP.String() + ":0")
		if err != nil {
			return err
		}
		if err := opts.Net.Restrict(port); err != nil {
			return err
		}
		go proxy.Serve()
		defer proxy.Close()
	}
	opts.ID = sandboxID

	// Firecracker has no shared-filesystem device, so a workspace is a copy in
	// and a copy out rather than a mount (docs/networking.md is about egress;
	// this is the local-files path). Packing happens before boot because the
	// image has to exist to be attached.
	// pausedAs is the name `kelyfos pause` stored this machine under, sampled
	// at teardown before the run directory goes. Empty for every ordinary stop.
	var pausedAs string

	// The plugins device, when the project declares any. Read-only, packed
	// before boot for the same reason the workspace is: the image has to exist
	// to be attached (E4-6).
	plugins, err := packPlugins(cfg, sandboxID)
	if err != nil {
		return err
	}
	opts.Plugins = plugins
	if plugins != nil {
		// The device is rebuilt from the policy every run, so it is removed
		// with the machine. A snapshot that needs it kept its own copy.
		defer os.Remove(plugins.ImagePath)
		fmt.Printf("plugins    %s (read-only)\n", strings.Join(plugins.Names(), ", "))
	}

	if *wsDir != "" {
		ws, err := sandbox.PackWorkspace(*wsDir,
			filepath.Join(sandbox.Root(), "workspaces", sandboxID+".ext4"), diskCeiling)
		if err != nil {
			return err
		}
		opts.Workspace = ws
		defer func() {
			// A pause is not an ending. The machine is going to come back, and
			// writing the host directory now would change it under somebody who
			// did not ask — then change it again when the session really ends
			// (docs/qol.md §1.3). The workspace travelled into the stored
			// session with the snapshot; it comes back with the machine.
			if pausedAs != "" {
				name := pausedAs
				fmt.Printf("\npaused as %q; the workspace travels with the session and is written "+
					"back when it finally ends\n", name)
				return
			}
			if *noSync {
				fmt.Printf("workspace not written back (--no-sync-back); image kept at %s\n", ws.ImagePath)
				return
			}
			dest, diverted, err := ws.SyncBack()
			if err != nil {
				fmt.Fprintf(os.Stderr, "kelyfos: workspace sync-back failed: %v\n", err)
				return
			}
			if diverted {
				fmt.Printf("\nthe host directory changed while the sandbox was running, so it was NOT "+
					"overwritten.\nresults written to %s instead\n", dest)
			} else {
				fmt.Printf("workspace written back to %s\n", dest)
			}
			_ = os.Remove(ws.ImagePath)
		}()
	}

	sb, err := sandbox.New(opts)
	if err != nil {
		return err
	}

	// The flight recorder is opened before the VM starts and closed after it
	// stops, so a session's record brackets the thing it describes. It lives
	// outside the run directory, which is deleted on teardown.
	rec, err := recorder.Open(sandbox.Root(), sb.State.ID)
	if err != nil {
		return err
	}
	reason := "error"
	defer func() {
		// A pause does not end the session — it is the same machine, coming
		// back — so the chain stays open. Closing it would make `--verify`
		// describe a machine that still exists as finished, and the resume
		// would then append after an end (docs/qol.md §1.4).
		if reason == "paused" {
			_ = rec.Close()
			return
		}
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSessionEnd, Reason: reason,
			DurationMS: rec.Since().Milliseconds(),
		})
		_ = rec.Close()
	}()

	// An OOM kill is the RAM cap being reached. The cap itself is the VM's
	// hardware and needs no help holding; what needed building is the part that
	// makes hitting it legible instead of a process that silently vanished
	// (E1-4). oomKills is read once, at the end, to decide the exit status.
	var oomKills atomic.Int32
	handler := func(ev proto.GuestEvent) {
		switch ev.Type {
		case proto.GuestEventOOM:
			oomKills.Add(1)
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeResourceOOM, Source: recorder.SourceGuest,
				PID: ev.PID, Comm: ev.Comm, RSSKiB: ev.RSSKiB, MemMiB: *memMiB,
			})
			fmt.Fprintf(os.Stderr,
				"\nkelyfos: the guest ran out of memory and killed %s (pid %d, %s resident "+
					"of a %d MiB machine)\n         raise --mem, or lower what the agent is asked to hold\n",
				ev.Comm, ev.PID, report.HumanKiB(ev.RSSKiB), *memMiB)
		case proto.GuestEventPluginCall, proto.GuestEventPluginCrash:
			_ = rec.Append(pluginEvent(ev))
			if ev.Type == proto.GuestEventPluginCrash {
				fmt.Fprintf(os.Stderr, "\nkelyfos: plugin %s stopped: %s\n"+
					"         its tools now fail and say so; nothing else in the sandbox is affected\n",
					ev.Name, ev.Message)
			}
		default:
			// Unknown guest event types are ignored rather than recorded: the
			// guest is untrusted, and an unrecognised type is either a version
			// skew or an attempt to write something arbitrary into the audit
			// trail. Neither belongs in the chain.
		}
	}
	onGuestEvent.Store(&handler)

	// Teardown must happen on every path out of this function, including the
	// signal path — a sandbox left running with its run directory deleted, or a
	// stale socket left behind, is worse than a failure.
	//
	// The usage receipt is taken here, immediately before the shutdown, because
	// every counter it reads belongs to a process that is about to stop
	// existing (E1-7).
	defer func() {
		// Sampled before the shutdown, which deletes the run directory the
		// marker lives in. The workspace defer runs after this one — defers
		// unwind last-registered-first — so it has to be told rather than look.
		pausedAs = sandbox.PausedAs(&sb.State)
		// No usage receipt for a pause. The receipt is what a machine spent
		// over its life, written once when that life ends; a pause is the
		// middle of one, and by this point the VMM's counters are gone anyway —
		// which is why the first live pause recorded a receipt of zeroes.
		if u, err := sb.State.Sample(); err == nil && pausedAs == "" {
			_ = rec.Append(recorder.Event{
				Type:       recorder.TypeResourceSummary,
				CPUSeconds: u.CPUSeconds, PeakRSSKiB: u.PeakRSSKiB,
				NetInBytes: u.NetInBytes, NetOutBytes: u.NetOutBytes,
				DiskReadBytes: u.DiskReadBytes, DiskWriteBytes: u.DiskWriteBytes,
				MemMiB: sb.State.MemMiB, VcpuCount: sb.State.VcpuCount, CPUQuota: sb.State.CPUQuota,
			})
		}
		if err := sb.Shutdown(5 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
	}()

	if err := rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: *flavor, Arch: *arch,
		Kelyfos: Version, Argv: os.Args,
	}); err != nil {
		return err
	}

	// Every attempt to leave the sandbox is recorded, allowed or not. The
	// blocked ones are the interesting ones.
	if proxy != nil {
		proxy.OnSecret = func(name, host string) {
			// Name and destination only. The value is never recorded in any
			// field, in any form (docs/events.md §4).
			_ = rec.Append(recorder.Event{Type: recorder.TypeSecretUse, Name: name, Host: host})
		}
		proxy.OnEvent = func(a egress.Attempt) {
			allowed := a.Allowed
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeEgressAttempt,
				Host: a.Host, Port: a.Port, Allowed: &allowed,
				Reason: a.Reason, Mode: a.Mode,
				BytesIn: a.BytesIn, BytesOut: a.BytesOut,
			})
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sb.Start(ctx); err != nil {
		return err
	}

	readyCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	ready, err := sb.WaitReady(readyCtx)
	if err != nil {
		return fmt.Errorf("guest never became ready: %w", err)
	}

	// The split matters when tuning: guest time is kernel plus init plus
	// supervisor, measured by the guest's own monotonic clock; the remainder is
	// Firecracker setting the machine up and loading the kernel, which no
	// amount of guest tuning will touch.
	// The split is worth printing because the two halves are tuned by different
	// means: guest time is the kernel and the init path, measured by the guest's
	// own monotonic clock; the remainder is Firecracker building the machine and
	// loading the kernel, which no amount of guest tuning will touch.
	guestMS := ready.MonotonicNS / 1e6
	// The guest must trust the egress CA before anything tries to use it.
	if ca != nil {
		if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			return err
		}
	}

	overlay := ready.Overlay
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: sb.State.BootReadyMS,
		Kernel: ready.Kernel, Supervisor: ready.Supervisor, Overlay: &overlay,
	})

	fmt.Printf("sandbox %s ready in %d ms (vmm %d ms + guest %d ms)\n",
		sb.State.ID, sb.State.BootReadyMS, sb.State.BootReadyMS-guestMS, guestMS)
	fmt.Printf("  kernel      %s (%s)\n", ready.Kernel, ready.Arch)
	fmt.Printf("  supervisor  %s\n", ready.Supervisor)
	if !ready.Overlay {
		fmt.Fprintln(os.Stderr, "  warning: the guest is running on a READ-ONLY root — the overlay failed")
	}
	fmt.Printf("  vsock       %s\n", sb.State.UDSPath)
	if cpuSlice != nil {
		// Say both numbers together, because the pair is the whole point:
		// cores are parallelism, the quota is consumption.
		fmt.Printf("  cpu         %d core(s), capped at %d%% of one core's CPU time\n",
			*cpus, cpuSlice.Percent)
		fmt.Printf("  cgroup      %s\n", sb.State.CGroupPath)
	}
	if scratchBytes > 0 {
		fmt.Printf("  scratch     %s for everything written outside /work\n",
			report.HumanKiB(scratchBytes>>10))
	}
	if ioLimits.DiskIOPS > 0 || ioLimits.DiskMbps > 0 {
		// Per device, not shared — the limiter is a property of one virtio-blk
		// device and a sandbox with a workspace has two of them.
		fmt.Printf("  disk limit  %s, per block device\n", describeDiskLimit(ioLimits))
	}
	if ioLimits.NetMbpsRx > 0 || ioLimits.NetMbpsTx > 0 {
		if opts.Net == nil {
			// Not an error: no network at all is a stricter limit than a
			// throttled one. Said out loud so nobody reads the silence as the
			// limit having been applied.
			fmt.Printf("  net limit   not applied — this sandbox has no network interface\n")
		} else {
			fmt.Printf("  net limit   %s\n", describeNetLimit(ioLimits))
		}
	}
	if opts.Net != nil {
		fmt.Printf("  egress      %s via proxy on %s:%d\n",
			strings.Join(opts.Allow, ", "), opts.Net.HostIP, opts.Net.ProxyPort)
		for _, sec := range proxy.Policy.Secrets {
			fmt.Printf("  secret      %s -> %s (%s; the value stays on the host)\n",
				sec.Name, sec.Domain, sec.Scheme)
		}
	} else {
		fmt.Printf("  egress      none (no network interface)\n")
	}
	if opts.Workspace != nil {
		fmt.Printf("  workspace   %s -> /work\n", opts.Workspace.HostDir)
	}
	if maxRuntime > 0 {
		fmt.Printf("  max runtime %s\n", maxRuntime)
	}
	if idleTimeout > 0 {
		fmt.Printf("  idle timeout %s — no tool call and no traffic for that long ends the run\n", idleTimeout)
	}

	vmExited := make(chan struct{})
	go func() { _ = sb.Wait(); close(vmExited) }()

	// Time budgets (E1-6). The watchdog is host-side and observes host-side
	// facts only: how long the sandbox has been up, whether the flight recorder
	// has grown, and whether any byte has crossed the egress proxy. Between
	// them those are exactly "no vsock RPC and no egress traffic" — every exec
	// and every MCP tool call is recorded, whichever process issued it, and the
	// proxy is the only route out.
	budgetFired := make(chan timeoutFired, 1)
	if maxRuntime > 0 || idleTimeout > 0 {
		stopWatchdog := make(chan struct{})
		defer close(stopWatchdog)
		go watchBudgets(budgets{
			max:      maxRuntime,
			idle:     idleTimeout,
			started:  time.Now(),
			eventLog: recorder.Path(sandbox.Root(), sb.State.ID),
			proxy:    proxy,
			fired:    budgetFired,
			stop:     stopWatchdog,
		})
	}
	// recordTimeout writes the audit event and says why the run is ending. It
	// runs on whichever path notices first, and only once.
	var timedOut string
	noteTimeout := func(t timeoutFired) {
		timedOut = t.budget
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeResourceTimeout, Budget: t.budget,
			BudgetMS: t.budgetLimit.Milliseconds(), ElapsedMS: t.elapsed.Milliseconds(),
		})
		fmt.Fprintf(os.Stderr, "\nkelyfos: the %s budget of %s expired after %s; stopping the sandbox\n",
			t.budget, t.budgetLimit, t.elapsed.Round(time.Second))
	}

	// With a trailing command, the sandbox's lifetime is that command's: run
	// it on the host with a handle to this machine, then tear everything down
	// and exit with its status (D23, and section 1's definition of done).
	if len(command) > 0 {
		fmt.Printf("\nrunning: %s\n\n", strings.Join(command, " "))
		child := exec.Command(command[0], command[1:]...)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		// The command's whole purpose is to reach back in through `kelyfos
		// mcp`, so make sure it can find the binary that launched it — the
		// README installs to ./bin, which is not on anyone's PATH.
		env := append(os.Environ(), "KELYFOS_SANDBOX="+sb.State.ID)
		if self, err := os.Executable(); err == nil {
			env = append(env, "PATH="+filepath.Dir(self)+string(os.PathListSeparator)+os.Getenv("PATH"))
		}
		child.Env = env
		if err := child.Start(); err != nil {
			return fmt.Errorf("run %s: %w", command[0], err)
		}
		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()

		var err error
		select {
		case err = <-childDone:
		case t := <-budgetFired:
			noteTimeout(t)
			// SIGTERM first and a grace period after it: the command is the
			// agent, and an agent that is given a moment can finish the line it
			// is writing. Killing outright would leave the workspace mid-edit,
			// and the sync-back that follows would carry that state to the host
			// as if it were a result.
			_ = child.Process.Signal(syscall.SIGTERM)
			select {
			case err = <-childDone:
			case <-time.After(childGrace):
				fmt.Fprintf(os.Stderr, "kelyfos: %s did not stop within %s; killing it\n",
					command[0], childGrace)
				_ = child.Process.Kill()
				err = <-childDone
			}
		}
		reason = "command_exited"
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				return fmt.Errorf("run %s: %w", command[0], err)
			}
		}
		if timedOut != "" {
			reason = "timeout"
			code = exitTimedOut
		}
		fmt.Printf("\n%s exited %d; stopping the sandbox\n", command[0], code)
		if code == 0 && oomKills.Load() > 0 {
			// The command finished, but something in the sandbox was killed for
			// running the machine out of memory. Reporting success would hide
			// exactly the failure the user most needs to see, so `run` exits
			// 137 — the shell's convention for death by SIGKILL, which is
			// literally what the OOM killer sent.
			code = exitOOMKilled
		}
		if code != 0 {
			// Returned, never os.Exit: this function's deferred teardown is
			// what stops the VM, syncs the workspace back and closes the
			// session record, and os.Exit runs none of them.
			return &exitError{code}
		}
		return nil
	}

	fmt.Println("\nCtrl-C to stop.")

	// Return when the user interrupts, or earlier if the VM dies on its own.
	select {
	case <-ctx.Done():
		fmt.Println("\nstopping...")
		reason = "interrupted"
	case t := <-budgetFired:
		noteTimeout(t)
		reason = "timeout"
	case <-vmExited:
		// A pause stops the machine on purpose, from another process. Calling
		// that unexpected would make the ordinary path print an error.
		if name := sandbox.PausedAs(&sb.State); name != "" {
			reason = "paused"
			fmt.Printf("\npaused as %q\n", name)
			break
		}
		reason = "vm_exited"
		return fmt.Errorf("the microVM exited unexpectedly")
	}
	switch {
	case timedOut != "":
		return &exitError{exitTimedOut}
	case oomKills.Load() > 0:
		return &exitError{exitOOMKilled}
	}
	return nil
}

// childGrace is how long a trailing command has to stop itself after SIGTERM
// before it is killed.
const childGrace = 5 * time.Second

// exitTimedOut is timeout(1)'s exit status, for the same meaning. A CI job that
// already treats 124 as "this took too long" needs no teaching. It lives in
// internal/exitcode with the rest, so the generated reference documents the
// number this code actually returns.
const exitTimedOut = exitcode.TimedOut

type timeoutFired struct {
	budget      string
	budgetLimit time.Duration
	elapsed     time.Duration
}

type budgets struct {
	max, idle time.Duration
	started   time.Time
	eventLog  string
	proxy     *egress.Proxy
	fired     chan<- timeoutFired
	stop      <-chan struct{}
}

// watchBudgets fires at most once, on whichever budget expires first.
//
// Idle is measured from two host-side facts and no guest-side ones: the size of
// the flight recorder, which grows on every exec and every MCP tool call
// whichever process issued it, and the proxy's own last-byte timestamp, which
// covers a long download that produces no events until it finishes. A sandbox
// doing neither is doing nothing the host can see, and the host is the only
// side entitled to an opinion (F-D2).
func watchBudgets(b budgets) {
	const tick = time.Second
	lastSize := int64(-1)
	lastChange := b.started
	for {
		select {
		case <-b.stop:
			return
		case <-time.After(tick):
		}
		now := time.Now()
		if b.max > 0 && now.Sub(b.started) >= b.max {
			b.fired <- timeoutFired{"max_runtime", b.max, now.Sub(b.started)}
			return
		}
		if b.idle == 0 {
			continue
		}
		if fi, err := os.Stat(b.eventLog); err == nil && fi.Size() != lastSize {
			lastSize = fi.Size()
			lastChange = now
		}
		if b.proxy != nil {
			if t := b.proxy.LastActive(); t.After(lastChange) {
				lastChange = t
			}
		}
		if idle := now.Sub(lastChange); idle >= b.idle {
			b.fired <- timeoutFired{"idle_timeout", b.idle, idle}
			return
		}
	}
}

// exitOOMKilled is 128 + SIGKILL, the shell's convention for a process killed by
// signal 9 — which is what the OOM killer sends. A user who greps for 137 in a
// CI log to find "the box ran out of memory" finds it here too.
const exitOOMKilled = exitcode.OOMKilled

type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p prefixWriter) Write(b []byte) (int, error) {
	if _, err := fmt.Fprintf(p.w, "%s%s", p.prefix, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// splitAllow turns --allow into a list, tolerating spaces and trailing commas
// because people type them.
func splitAllow(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// containsDomain reports whether an allowlist covers a domain, using the same
// suffix rule the proxy enforces.
func containsDomain(allow []string, domain string) bool {
	for _, a := range allow {
		a = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(a, "."), "*."))
		if domain == a || strings.HasSuffix(domain, "."+a) {
			return true
		}
	}
	return false
}

// loadPolicy finds and reads a project's kelyfos.toml, if it has one. Absence
// is normal and silent; a file that exists but is wrong is an error, because a
// policy that fails to apply is worse than no policy at all.
func loadPolicy() (*config.Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil
	}
	path, found := config.Find(cwd)
	if !found {
		return nil, nil
	}
	return config.Load(path)
}

// ceiling applies one [resources] limit: with no flag it becomes the value,
// with a flag under it the flag wins, and with a flag over it the boot is
// describeDiskLimit and describeNetLimit render only the limits that are set,
// because "500 iops / unlimited MB/s" reads like a limit nobody chose.
func describeDiskLimit(l sandbox.IOLimits) string {
	var parts []string
	if l.DiskIOPS > 0 {
		parts = append(parts, fmt.Sprintf("%d iops", l.DiskIOPS))
	}
	if l.DiskMbps > 0 {
		parts = append(parts, fmt.Sprintf("%d MB/s", l.DiskMbps))
	}
	return strings.Join(parts, " and ")
}

func describeNetLimit(l sandbox.IOLimits) string {
	var parts []string
	if l.NetMbpsRx > 0 {
		parts = append(parts, fmt.Sprintf("%d Mbps in", l.NetMbpsRx))
	}
	if l.NetMbpsTx > 0 {
		parts = append(parts, fmt.Sprintf("%d Mbps out", l.NetMbpsTx))
	}
	return strings.Join(parts, " and ")
}

// refused naming the policy line (docs/resources.md).
func ceiling(key, flagName string, cfg *config.Config, limit int, flagVal *int, typed bool, show func(int) string) error {
	if limit == 0 {
		return nil
	}
	if !typed || *flagVal == 0 {
		*flagVal = limit
		return nil
	}
	if *flagVal > limit {
		line, _ := cfg.Ceiling(key)
		return fmt.Errorf("--%s %s exceeds the ceiling %s = %s set at %s:%d\n"+
			"    lower the flag, or raise the ceiling in the policy file",
			flagName, show(*flagVal), key, show(limit), cfg.Path, line)
	}
	return nil
}
