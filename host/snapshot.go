package main

import (
	gocontext "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
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
		allow   = fs.String("allow", "", "egress allowlist for the restored machine (default: whatever the snapshot recorded)")
		secrets multiFlag
	)
	fs.Var(&secrets, "secret", "attach a credential to a domain: NAME@domain[:bearer|basic]. Repeatable.")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	dir := snapshotDir(*name)
	opts := sandbox.Options{Arch: *arch, Flavor: *flavor, Quiet: true}
	if *console {
		opts.Console = prefixWriter{os.Stderr, "[guest] "}
	}

	// A machine frozen with a NIC has to be restored into one, or Firecracker
	// refuses the load outright. The allowlist defaults to what the snapshot
	// was taken with, so restoring does not silently widen what the machine
	// can reach — and --allow can narrow it (D22).
	var proxy *egress.Proxy
	var ca *egress.CA
	meta, metaErr := sandbox.ReadSnapshotMeta(dir)
	if metaErr == nil && meta.HasNetwork {
		list := splitAllow(*allow)
		if len(list) == 0 {
			list = meta.Allow
		}
		if len(list) == 0 {
			return fmt.Errorf("snapshot %q was taken from a networked sandbox but recorded no allowlist; pass --allow", *name)
		}
		var vetted []*egress.Secret
		for _, spec := range secrets {
			sec, err := egress.ParseSecret(spec)
			if err != nil {
				return err
			}
			if !containsDomain(list, sec.Domain) {
				return fmt.Errorf("--secret %s: %s is not in the allowlist", spec, sec.Domain)
			}
			vetted = append(vetted, sec)
		}
		var err error
		if proxy, ca, err = restoreNetwork(meta, list, vetted, &opts); err != nil {
			return err
		}
		defer opts.Net.Down()
		defer proxy.Close()
	}

	sb, elapsed, err := sandbox.Restore(dir, opts)
	if err != nil {
		return err
	}
	// D6 mints a fresh CA every run, so a restored guest is carrying an anchor
	// for a CA that no longer exists. It has to be replaced before anything in
	// there tries to reach a secret-bound domain.
	if ca != nil {
		if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			return err
		}
	}
	defer func() {
		ws := sb.State.Workspace
		if err := sb.Shutdown(5 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
		// A restore writes nothing back, so its copy of the workspace goes with
		// the machine rather than accumulating in the cache (E5-1).
		if ws != "" {
			_ = os.Remove(ws)
		}
	}()

	rec, err := recorder.Open(sandbox.Root(), sb.State.ID)
	if err != nil {
		return err
	}
	defer rec.Close()
	// A restored machine records its egress like any other. It did not until
	// P6-4 went looking: this is the fifth of five proxies in the product and
	// the only one whose audit hooks were never wired, so a restore wrote a
	// chain with a start, a ready and an end and nothing in between — a blocked
	// attempt left no trace, and a credential spent left no trace.
	//
	// Wired here rather than at restoreNetwork because the recorder is keyed on
	// the sandbox id and that id does not exist until Restore returns. The gap
	// that leaves is the milliseconds between the proxy binding and this line,
	// during which the guest has not resumed; `serve-mcp`'s restore has no such
	// gap because it knows the box id in advance.
	wireProxyAudit(proxy, rec, "", newBlockedOnce(os.Stderr))
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: *flavor, Arch: *arch,
		Kelyfos: Version, Argv: os.Args, Reason: "restored from " + *name,
	})
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: elapsed.Milliseconds(),
	}.WithPosture(sb.State.Jailed, sb.State.Profile))

	fmt.Printf("sandbox %s restored from %q in %d ms\n", sb.State.ID, *name, elapsed.Milliseconds())
	fmt.Printf("  vsock       %s\n", sb.State.UDSPath)
	if sb.State.TAP != "" {
		fmt.Printf("  egress      %s via %s\n", strings.Join(sb.State.Allow, ", "), sb.State.TAP)
	}
	fmt.Println("  clock and entropy resynced")
	if sb.State.Profile != "" {
		// A restore says what it brought back for the same reason a run says
		// what it started: the machine is not the one in front of you, and the
		// absence of this line is what the warning above it explains (P5-7).
		fmt.Printf("  profile     %s\n", sb.State.Profile)
	}
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

// restoreNetwork plugs a restored machine back into the network the snapshot
// recorded, filling in the parts of opts that describe it. Both doors that can
// restore one — the command line and `serve-mcp` — go through here, because a
// restored machine's addressing is a set of details that have to agree exactly
// and two copies of them would eventually stop agreeing.
//
// The caller keeps the cleanup: on success opts.Net and the returned proxy are
// live and belong to whatever now owns the machine. On failure this cleans up
// after itself and returns nothing to close.
func restoreNetwork(meta *sandbox.SnapshotMeta, allow []string, secrets []*egress.Secret, opts *sandbox.Options) (*egress.Proxy, *egress.CA, error) {
	id := opts.ID
	if id == "" {
		var err error
		if id, err = sandbox.NewID(); err != nil {
			return nil, nil, err
		}
		opts.ID = id
	}
	opts.Allow = allow

	var err error

	// Re-use the addressing the snapshot recorded, not a fresh /30: the guest's
	// HTTPS_PROXY is in the memory image and cannot be changed from out here
	// (D22).
	if meta.HostIP != "" {
		opts.Net, err = sandbox.NewNetworkFor(id, meta.HostIP, meta.GuestIP, meta.Netmask, meta.HostMAC)
	} else {
		opts.Net, err = sandbox.NewNetwork(id)
	}
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*egress.Proxy, *egress.CA, error) {
		opts.Net.Down()
		opts.Net = nil
		return nil, nil, err
	}

	var ca *egress.CA
	policy := egress.Policy{Allow: allow, Secrets: secrets}
	if len(policy.Secrets) > 0 {
		if ca, err = egress.NewCA(); err != nil {
			return fail(err)
		}
	}
	proxy := &egress.Proxy{Policy: policy, CA: ca}
	// Same reasoning as the address: the port is baked into the guest's proxy
	// environment, so the restored proxy has to bind the one the snapshot
	// recorded rather than whatever the kernel offers.
	bind := opts.Net.HostIP.String() + ":0"
	if meta.ProxyPort != 0 {
		bind = fmt.Sprintf("%s:%d", opts.Net.HostIP, meta.ProxyPort)
	}
	port, err := proxy.Listen(bind)
	if err != nil {
		// The address is not a choice: the frozen guest has it in its memory
		// image and will dial it whatever this side does (D22). A bind failure
		// here almost always means the machine the snapshot came from is still
		// running on it.
		return fail(fmt.Errorf("bind the egress proxy on %s, which is the address this snapshot's "+
			"guest expects and not something that can be moved: %w\n"+
			"    if the sandbox this snapshot was taken from is still running, stop it first",
			bind, err))
	}
	opts.ProxyPort = port
	if err := opts.Net.Restrict(port); err != nil {
		proxy.Close()
		return fail(err)
	}
	go proxy.Serve()
	return proxy, ca, nil
}
