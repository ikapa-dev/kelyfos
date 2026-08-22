package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

func runCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos run", flag.ExitOnError)
	var (
		arch    = fs.String("arch", sandbox.HostArch(), "guest architecture (aarch64|x86_64)")
		flavor  = fs.String("image", "base", "image flavor")
		imgDir  = fs.String("image-dir", "", "directory holding the kernel and rootfs (default: the build output)")
		vcpus   = fs.Int("vcpus", 2, "virtual CPUs")
		memMiB  = fs.Int("mem", 512, "guest memory, MiB")
		console = fs.Bool("console", false, "stream the guest serial console")
		verbose = fs.Bool("verbose-boot", false, "drop `quiet` from the kernel command line")
		timeout = fs.Duration("ready-timeout", 30*time.Second, "how long to wait for the guest to become ready")
	)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: kelyfos run [flags]\n\nBoots a sandbox and keeps it running until Ctrl-C.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	var consoleOut io.Writer
	if *console || *verbose {
		consoleOut = prefixWriter{os.Stderr, "[guest] "}
	}

	sb, err := sandbox.New(sandbox.Options{
		Arch:      *arch,
		Flavor:    *flavor,
		ImageDir:  *imgDir,
		VcpuCount: *vcpus,
		MemMiB:    *memMiB,
		Quiet:     !*verbose,
		Console:   consoleOut,
	})
	if err != nil {
		return err
	}

	// Teardown must happen on every path out of this function, including the
	// signal path — a sandbox left running with its run directory deleted, or a
	// stale socket left behind, is worse than a failure.
	defer func() {
		if err := sb.Shutdown(5 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
	}()

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

	fmt.Printf("sandbox %s ready in %d ms\n", sb.State.ID, sb.State.BootReadyMS)
	fmt.Printf("  kernel      %s (%s)\n", ready.Kernel, ready.Arch)
	fmt.Printf("  supervisor  %s\n", ready.Supervisor)
	if !ready.Overlay {
		fmt.Fprintln(os.Stderr, "  warning: the guest is running on a READ-ONLY root — the overlay failed")
	}
	fmt.Printf("  vsock       %s\n", sb.State.UDSPath)
	fmt.Println("\nCtrl-C to stop.")

	// Return when the user interrupts, or earlier if the VM dies on its own.
	vmExited := make(chan struct{})
	go func() { _ = sb.Wait(); close(vmExited) }()
	select {
	case <-ctx.Done():
		fmt.Println("\nstopping...")
	case <-vmExited:
		return fmt.Errorf("the microVM exited unexpectedly")
	}
	return nil
}

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
