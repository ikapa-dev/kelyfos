package main

import (
	gocontext "context"
	"errors"
	"flag"
	"fmt"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func forkCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos fork", flag.ExitOnError)
	var (
		name   = fs.String("name", "default", "snapshot to fork from")
		n      = fs.Int("n", 2, "how many forks to create")
		arch   = fs.String("arch", sandbox.HostArch(), "guest architecture")
		flavor = fs.String("image", "dev", "image flavor the snapshot was taken from")
		// The policy is named the same way `run` names it, and for the same
		// reason: a ceiling that only some entry points read is not a ceiling
		// (P6-26, finding M-2).
		policyPath = fs.String("policy", "", "the kelyfos.toml whose ceilings apply (default: the nearest one, found by walking up)")
		cpuQuota   = fs.Int("cpu-quota", 0, "percent of one core's worth of host CPU each fork may consume")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos fork [flags]

Restores one snapshot into several independent sandboxes. Each fork resumes from
the same prepared state and then diverges: writes land in the in-guest tmpfs
overlay, which is part of guest memory, and each fork maps the memory snapshot
privately so the kernel provides page-level copy-on-write for free. The rootfs is
opened read-only and shared by all of them.

Every fork is resynced on resume with a fresh wall clock and fresh entropy —
without that, forks of one snapshot would generate identical "random" values.

Forks are vsock-only in v0.x: networked forks need per-fork TAP re-pairing and a
unique guest network identity, which is backlog work.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *n < 1 {
		return errors.New("-n must be at least 1")
	}

	type forked struct {
		sb      *sandbox.Sandbox
		rec     *recorder.Recorder
		elapsed time.Duration
		err     error
	}
	results := make([]forked, *n)
	// One cgroup slice per fork, closed with the fork it caps.
	slices := make([]*sandbox.Slice, *n)
	defer func() {
		for _, sl := range slices {
			if sl != nil {
				sl.Close()
			}
		}
	}()

	// Refuse before starting rather than failing partway through the third
	// copy. Without reflink support each fork is a full copy of the workspace.
	meta, err := sandbox.ReadSnapshotMeta(snapshotDir(*name))
	if err != nil {
		return err
	}
	if meta.HasWorkspace {
		if err := sandbox.CheckForkSpace(sandbox.RunRoot(), *n, meta.WorkspaceSize); err != nil {
			return err
		}
		fmt.Printf("each fork gets its own copy of a %d byte workspace disk\n", meta.WorkspaceSize)
	}
	// Forks are vsock-only in v0.x, exactly as P3-2 scopes them. One restore
	// can re-pair its NIC to a fresh TAP (D22), but N forks would need N
	// distinct guest network identities, and the guest's address and default
	// route live inside the memory image every fork shares. Say that here
	// rather than letting each fork fail separately inside Firecracker.
	if meta.HasNetwork {
		return fmt.Errorf("snapshot %q was taken from a sandbox with egress (allowed: %s), and forks are vsock-only in v0.x.\n"+
			"    Forking needs one network identity per fork; the guest's address is baked into the shared memory image.\n"+
			"    restore it as a single machine:  kelyfos snapshot restore -name %s\n"+
			"    or prepare the snapshot without egress and fork that.",
			*name, strings.Join(meta.Allow, ","), *name)
	}

	// The ceiling the file declares, applied here because until now it was
	// not applied at all (P6-26, finding M-2).
	//
	// `fork` never read kelyfos.toml, so `resources.cpu_quota` — which
	// docs/resources.md describes as cgroup v2 cpu.max on the Firecracker
	// process, with no exception for this command — was simply absent from
	// every forked machine. A ceiling that one entry point ignores is worse
	// than one that was never claimed: the claim is what a reader plans around,
	// and the way to get an unlimited machine was to ask for it from the side
	// that was not looking.
	//
	// Per fork rather than shared, matching what `run` does for a single
	// sandbox: the quota is what one machine may consume, and N forks of a
	// prepared snapshot are N machines.
	typedQuota := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "cpu-quota" {
			typedQuota = true
		}
	})
	cfg, cfgErr := loadPolicyAt(*policyPath)
	if cfgErr != nil {
		return cfgErr
	}
	if cfg != nil {
		if err := ceiling("cpu_quota", "cpu-quota", cfg, cfg.ResCPUQuota, cpuQuota,
			typedQuota, func(v int) string { return strconv.Itoa(v) + "%" }); err != nil {
			return err
		}
	}

	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := sandbox.NewID()
			if err != nil {
				results[i] = forked{err: err}
				return
			}
			opts := sandbox.Options{ID: id, Arch: *arch, Flavor: *flavor, Quiet: true}
			if *cpuQuota > 0 {
				slice, err := sandbox.NewCPUSlice(fmt.Sprintf("fork-%d-%d", started.UnixNano(), i), *cpuQuota)
				if err != nil {
					results[i] = forked{err: err}
					return
				}
				slices[i] = slice
				opts.CPUSlice = slice
			}
			// Opened and wired before Restore, not after every fork in the batch
			// has finished as this used to do: the guest is live and reporting
			// from the instant Restore resumes it, and a handler wired only
			// afterward missed whatever the fastest of them said first (F3).
			rec, err := recorder.Open(sandbox.Root(), id)
			if err != nil {
				results[i] = forked{err: err}
				return
			}
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeSessionStart, Image: *flavor, Arch: *arch,
				Kelyfos: Version, Argv: os.Args, Reason: "forked from " + *name,
			})
			opts.OnGuestEvent = guestEventRecorder(rec, "", meta.MemMiB)
			sb, elapsed, err := sandbox.Restore(snapshotDir(*name), opts)
			if err != nil {
				_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "error",
					DurationMS: rec.Since().Milliseconds()})
				_ = rec.Close()
				results[i] = forked{err: err}
				return
			}
			results[i] = forked{sb: sb, rec: rec, elapsed: elapsed}
		}(i)
	}
	wg.Wait()
	total := time.Since(started)

	// Tear down everything on any exit path, including the ones taken because
	// some forks failed. A half-forked fleet left running is worse than none.
	//
	// Each fork's record is closed here too. A session that opens and never
	// ends is a chain a reader cannot tell apart from one still running, and
	// `kelyfos log --list` would call it open forever (F-D33).
	var recs []*recorder.Recorder
	defer func() {
		for _, r := range results {
			if r.sb != nil {
				ws := r.sb.State.Workspace
				_ = r.sb.Shutdown(5 * time.Second)
				// A fork's copy of the workspace now outlives its run directory
				// on purpose, so this is where it goes: a fork writes nothing
				// back, and an image nobody reads is an image nobody should
				// keep (E5-1).
				if ws != "" {
					_ = os.Remove(ws)
				}
			}
		}
		for _, rec := range recs {
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeSessionEnd, Reason: "shutdown",
				DurationMS: rec.Since().Milliseconds(),
			})
			_ = rec.Close()
		}
	}()

	var live int
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "fork %d failed: %v\n", i+1, r.err)
			continue
		}
		live++
		if r.rec != nil {
			if err := recordFork(r.rec, r.sb, r.elapsed); err == nil {
				recs = append(recs, r.rec)
			}
		}
		fmt.Printf("fork %d/%d  sandbox %s  restored in %d ms\n",
			i+1, *n, r.sb.State.ID, r.elapsed.Milliseconds())
	}
	if live == 0 {
		return fmt.Errorf("no fork could be restored from snapshot %q", *name)
	}
	fmt.Printf("\n%d fork(s) live in %d ms wall clock; run commands with\n", live, total.Milliseconds())
	fmt.Printf("    kelyfos exec --sandbox <id> \"<command>\"\n")
	fmt.Println("\nCtrl-C to stop them all.")

	ctx, stop := signal.NotifyContext(gocontext.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("\nstopping...")
	return nil
}

// recordFork writes the "ready" event into a fork's chain, which the goroutine
// above already opened and started (with its guest-event handler wired) before
// calling sandbox.Restore. The recorder is left open on success rather than
// closed, because a session ends when the machine does and the caller's
// shutdown defer is what knows when that is.
func recordFork(rec *recorder.Recorder, sb *sandbox.Sandbox, elapsed time.Duration) error {
	if err := rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: elapsed.Milliseconds(),
	}.WithPosture(sb.State.Jailed, sb.State.Profile)); err != nil {
		_ = rec.Close()
		return err
	}
	return nil
}
