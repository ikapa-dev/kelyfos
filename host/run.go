package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
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
		allow   = fs.String("allow", "", "comma-separated egress allowlist, e.g. github.com,pypi.org. Without it the sandbox has no network interface at all.")
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

	opts := sandbox.Options{
		Arch:      *arch,
		Flavor:    *flavor,
		ImageDir:  *imgDir,
		VcpuCount: *vcpus,
		MemMiB:    *memMiB,
		Quiet:     !*verbose,
		Console:   consoleOut,
	}

	// Egress is opt-in and, when opted into, is built before the VM exists:
	// the TAP first, then the proxy bound on it, then the firewall that makes
	// the proxy the only reachable destination, and only then a machine that
	// can send a packet anywhere (docs/networking.md).
	var proxy *egress.Proxy
	sandboxID, err := sandbox.NewID()
	if err != nil {
		return err
	}
	if list := splitAllow(*allow); len(list) > 0 {
		opts.Allow = list
		opts.Net, err = sandbox.NewNetwork(sandboxID)
		if err != nil {
			return err
		}
		defer opts.Net.Down()

		proxy = &egress.Proxy{Policy: egress.Policy{Allow: list}}
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
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSessionEnd, Reason: reason,
			DurationMS: rec.Since().Milliseconds(),
		})
		_ = rec.Close()
	}()

	// Teardown must happen on every path out of this function, including the
	// signal path — a sandbox left running with its run directory deleted, or a
	// stale socket left behind, is worse than a failure.
	defer func() {
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
	if opts.Net != nil {
		fmt.Printf("  egress      %s via proxy on %s:%d\n",
			strings.Join(opts.Allow, ", "), opts.Net.HostIP, opts.Net.ProxyPort)
	} else {
		fmt.Printf("  egress      none (no network interface)\n")
	}
	fmt.Println("\nCtrl-C to stop.")

	// Return when the user interrupts, or earlier if the VM dies on its own.
	vmExited := make(chan struct{})
	go func() { _ = sb.Wait(); close(vmExited) }()
	select {
	case <-ctx.Done():
		fmt.Println("\nstopping...")
		reason = "interrupted"
	case <-vmExited:
		reason = "vm_exited"
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
