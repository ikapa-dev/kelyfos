package main

import (
	gocontext "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

func snapshotCmd(argv []string) error {
	if len(argv) == 0 {
		return errors.New("usage: kelyfos snapshot save|restore [flags]")
	}
	switch argv[0] {
	case "save":
		return snapshotSave(argv[1:])
	case "restore":
		return snapshotRestore(argv[1:])
	default:
		return fmt.Errorf("unknown snapshot subcommand %q (want save or restore)", argv[0])
	}
}

// snapshotDir is where a named snapshot lives. Snapshots outlive the sandbox
// that produced them, so they sit alongside sessions rather than in a run
// directory that is deleted on teardown.
func snapshotDir(name string) string {
	return filepath.Join(sandbox.Root(), "snapshots", name)
}

func snapshotSave(argv []string) error {
	fs := flag.NewFlagSet("kelyfos snapshot save", flag.ExitOnError)
	var (
		id   = fs.String("sandbox", "", "sandbox id (default: the only running one)")
		name = fs.String("name", "default", "snapshot name")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}

	st, err := sandbox.Load(*id)
	if err != nil {
		return err
	}
	dir := snapshotDir(*name)
	started := time.Now()
	state, mem, err := sandbox.SnapshotRunning(st, dir)
	if err != nil {
		return err
	}
	stateInfo, _ := os.Stat(state)
	memInfo, _ := os.Stat(mem)
	fmt.Printf("saved snapshot %q from sandbox %s in %d ms\n", *name, st.ID, time.Since(started).Milliseconds())
	fmt.Printf("  state   %s (%d bytes)\n", state, sizeOf(stateInfo))
	fmt.Printf("  memory  %s (%d bytes)\n", mem, sizeOf(memInfo))
	fmt.Printf("  the sandbox is still running\n")
	return nil
}

func snapshotRestore(argv []string) error {
	fs := flag.NewFlagSet("kelyfos snapshot restore", flag.ExitOnError)
	var (
		name    = fs.String("name", "default", "snapshot name")
		arch    = fs.String("arch", sandbox.HostArch(), "guest architecture")
		flavor  = fs.String("image", "dev", "image flavor the snapshot was taken from")
		console = fs.Bool("console", false, "stream the guest serial console")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}

	dir := snapshotDir(*name)
	opts := sandbox.Options{Arch: *arch, Flavor: *flavor, Quiet: true}
	if *console {
		opts.Console = prefixWriter{os.Stderr, "[guest] "}
	}

	sb, elapsed, err := sandbox.Restore(dir, opts)
	if err != nil {
		return err
	}
	defer func() {
		if err := sb.Shutdown(5 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
	}()

	rec, err := recorder.Open(sandbox.Root(), sb.State.ID)
	if err != nil {
		return err
	}
	defer rec.Close()
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: *flavor, Arch: *arch,
		Kelyfos: Version, Argv: os.Args, Reason: "restored from " + *name,
	})
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: elapsed.Milliseconds(),
	})

	fmt.Printf("sandbox %s restored from %q in %d ms\n", sb.State.ID, *name, elapsed.Milliseconds())
	fmt.Printf("  vsock       %s\n", sb.State.UDSPath)
	fmt.Println("  clock and entropy resynced")
	fmt.Println("\nCtrl-C to stop.")

	ctx, stop := signal.NotifyContext(gocontext.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	vmExited := make(chan struct{})
	go func() { _ = sb.Wait(); close(vmExited) }()
	select {
	case <-ctx.Done():
		fmt.Println("\nstopping...")
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "interrupted",
			DurationMS: rec.Since().Milliseconds()})
	case <-vmExited:
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "vm_exited",
			DurationMS: rec.Since().Milliseconds()})
		return errors.New("the restored microVM exited unexpectedly")
	}
	return nil
}

func sizeOf(fi os.FileInfo) int64 {
	if fi == nil {
		return 0
	}
	return fi.Size()
}
