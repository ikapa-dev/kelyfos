package main

import (
	gocontext "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

func forkCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos fork", flag.ExitOnError)
	var (
		name   = fs.String("name", "default", "snapshot to fork from")
		n      = fs.Int("n", 2, "how many forks to create")
		arch   = fs.String("arch", sandbox.HostArch(), "guest architecture")
		flavor = fs.String("image", "dev", "image flavor the snapshot was taken from")
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
		elapsed time.Duration
		err     error
	}
	results := make([]forked, *n)

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

	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sb, elapsed, err := sandbox.Restore(snapshotDir(*name),
				sandbox.Options{Arch: *arch, Flavor: *flavor, Quiet: true})
			results[i] = forked{sb: sb, elapsed: elapsed, err: err}
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
				_ = r.sb.Shutdown(5 * time.Second)
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
		if rec, err := recordFork(r.sb, *flavor, *arch, *name, r.elapsed); err == nil {
			recs = append(recs, rec)
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

// recordFork opens one fork's chain and writes its opening events. The recorder
// is returned rather than closed, because a session ends when the machine does
// and the caller is what knows when that is.
func recordFork(sb *sandbox.Sandbox, flavor, arch, snapshot string, elapsed time.Duration) (*recorder.Recorder, error) {
	rec, err := recorder.Open(sandbox.Root(), sb.State.ID)
	if err != nil {
		return nil, err
	}
	if err := rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: flavor, Arch: arch,
		Kelyfos: Version, Argv: os.Args, Reason: "forked from " + snapshot,
	}); err != nil {
		_ = rec.Close()
		return nil, err
	}
	if err := rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: elapsed.Milliseconds(),
	}); err != nil {
		_ = rec.Close()
		return nil, err
	}
	return rec, nil
}
