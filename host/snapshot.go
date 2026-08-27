package main

import (
	gocontext "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
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
		// Named and resolved exactly the way run and fork name and resolve it
		// (loadPolicyAt): --policy names a file, and naming one that is not
		// there is an error; with nothing named, it walks up from the working
		// directory and applies whatever kelyfos.toml it finds, if any (F9).
		// That is a real change from every kelyfos before this one — restore
		// used to read no policy file at all, so a working directory with a
		// kelyfos.toml above it (this repository's own included) now gets
		// its restores held to it by default, the same as `kelyfos run` and
		// `kelyfos fork` already are. Found or named, the restore is held to
		// it the same three ways serve-mcp's sandbox_restore already holds a
		// restore to it: see checkSnapshotCeiling below and the allow/secret
		// narrowing a few lines down, both mirrored from checkSnapshotFits
		// and restoreAllow in host/servemcpstate.go.
		policyPath = fs.String("policy", "", "the kelyfos.toml whose ceilings, allowlist and secrets this restore is held to (default: the nearest one, found by walking up — same as run and fork)")
		secrets    multiFlag
	)
	fs.Var(&secrets, "secret", "attach a credential to a domain: NAME@domain[:bearer|basic]. Repeatable.")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	cfg, cfgErr := loadPolicyAt(*policyPath)
	if cfgErr != nil {
		return cfgErr
	}
	if cfg != nil {
		fmt.Printf("policy: %s\n", cfg.Path)
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
	// Firecracker takes vcpu and memory from the state file, so a restore
	// cannot shrink a machine to fit — checked before anything else runs, the
	// same way checkSnapshotFits holds sandbox_restore to it (F9). metaErr is
	// only ever a genuine read/parse failure here, never "no metadata file"
	// (ReadSnapshotMeta already turns that into a zero-value SnapshotMeta), so
	// it gets the same treatment checkSnapshotCeiling gives an old snapshot's
	// unset fields: a ceiling that cannot be checked against nothing is refused
	// rather than waved through.
	if cfg != nil {
		checkMeta := meta
		if metaErr != nil {
			checkMeta = &sandbox.SnapshotMeta{}
		}
		if err := checkSnapshotCeiling(cfg, *name, checkMeta); err != nil {
			return err
		}
	}
	if metaErr == nil && meta.HasNetwork {
		list := splitAllow(*allow)
		if len(list) == 0 {
			list = meta.Allow
		}
		if len(list) == 0 {
			return fmt.Errorf("snapshot %q was taken from a networked sandbox but recorded no allowlist; pass --allow", *name)
		}
		// A named policy narrows the allowlist the same way restoreAllow
		// narrows sandbox_restore's (host/servemcpstate.go, F9): a domain the
		// project's kelyfos.toml does not permit is refused here, before a
		// proxy is ever built for it, rather than dialled and refused later.
		if err := restoreAllowCeiling(cfg, list); err != nil {
			return err
		}
		vetted, err := restoreSecrets(cfg, secrets, list)
		if err != nil {
			return err
		}
		if proxy, ca, err = restoreNetwork(meta, list, vetted, &opts); err != nil {
			return err
		}
		defer opts.Net.Down()
		defer proxy.Close()
	}

	// The id is picked here, before Restore is ever called, whether or not
	// there is a network: restoreNetwork already assigns one when there is,
	// and the no-network case has no reason to be different. sandbox.Restore
	// does not merely build a Sandbox value and hand it back — it calls the
	// Firecracker resume API partway through, and the guest is live, and
	// making its own round trips over the control port (Resync,
	// confirmSeccomp), well before Restore returns to this function. A
	// recorder wired only after Restore returns is wired after the guest has
	// already been running unaudited; this used to be that recorder, and
	// P6-4 is the fix (see the comment below wireProxyAudit for what it cost).
	if opts.ID == "" {
		var err error
		if opts.ID, err = sandbox.NewID(); err != nil {
			return err
		}
	}

	rec, err := recorder.Open(sandbox.Root(), opts.ID)
	if err != nil {
		return err
	}
	defer rec.Close()
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: *flavor, Arch: *arch,
		Kelyfos: Version, Argv: os.Args, Reason: "restored from " + *name,
	})
	// Wired before Restore for the same reason the egress audit hooks a few
	// lines down are: the guest is live and reporting well before Restore
	// returns, and a handler wired only afterward is a handler that missed
	// whatever it said first (F3).
	var memMiB int
	if metaErr == nil {
		memMiB = meta.MemMiB
	}
	opts.OnGuestEvent = guestEventRecorder(rec, "", memMiB)
	// A restored machine records its egress like any other. It did not until
	// P6-4 went looking: this is the fifth of five proxies in the product and
	// the only one whose audit hooks were never wired, so a restore wrote a
	// chain with a start, a ready and an end and nothing in between — a blocked
	// attempt left no trace, and a credential spent left no trace.
	//
	// Wired here, before sandbox.Restore is called, rather than after it
	// returns as this used to do: the id is already known (above), so there is
	// no reason left to wait, and waiting is what left the gap. It is not a
	// gap of milliseconds — InstallTrustAnchor below is a control-port round
	// trip to the very guest that just resumed, with a 10-second read deadline
	// a hostile guest controls the far end of (internal/sandbox/sandbox.go's
	// InstallTrustAnchor), and the deferred Shutdown a few lines down adds
	// another 5. wireProxyAudit no-ops safely when proxy is nil, which is the
	// no-network case here — see host/denials.go. `serve-mcp`'s restore
	// (host/servemcpstate.go) already wires before Restore for the same
	// reason; this was the one restore path that did not.
	wireProxyAudit(proxy, rec, "", newBlockedOnce(os.Stderr))

	sb, elapsed, err := sandbox.Restore(dir, opts)
	if err != nil {
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "error",
			DurationMS: rec.Since().Milliseconds()})
		return err
	}
	// Registered the instant there is a machine, before anything that can fail
	// with it running. It used to sit one block lower, under the trust anchor,
	// and a guest that refused the anchor therefore returned past a live
	// Firecracker nobody held: the VMM is started with its own process group and
	// no Pdeathsig, so it outlived `kelyfos restore` itself, taking the
	// workspace copy and the run directory with it (finding M-1).
	defer func() {
		ws := sb.State.Workspace
		// The receipt is sampled before Shutdown, the same as every other
		// teardown in this product (E1-7). This door had none until F14.
		if u, err := sb.State.Sample(); err == nil {
			_ = rec.Append(recorder.Event{
				Type:       recorder.TypeResourceSummary,
				CPUSeconds: u.CPUSeconds, PeakRSSKiB: u.PeakRSSKiB,
				NetInBytes: u.NetInBytes, NetOutBytes: u.NetOutBytes,
				DiskReadBytes: u.DiskReadBytes, DiskWriteBytes: u.DiskWriteBytes,
				MemMiB: sb.State.MemMiB, VcpuCount: sb.State.VcpuCount, CPUQuota: sb.State.CPUQuota,
				BlockedPackets: blockedPackets(opts.Net),
			})
		}
		if err := sb.Shutdown(5 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
		// A restore writes nothing back, so its copy of the workspace goes with
		// the machine rather than accumulating in the cache (E5-1).
		if ws != "" {
			_ = os.Remove(ws)
		}
	}()
	// D6 mints a fresh CA every run, so a restored guest is carrying an anchor
	// for a CA that no longer exists. It has to be replaced before anything in
	// there tries to reach a secret-bound domain. The audit hooks above are
	// already live by the time this runs, so a guest that stalls or refuses
	// here is a stall or a refusal the chain actually shows.
	if ca != nil {
		if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "error",
				DurationMS: rec.Since().Milliseconds()})
			return err
		}
	}

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

// checkSnapshotCeiling holds a frozen machine restored on the command line to
// the same ceiling checkSnapshotFits (host/servemcpstate.go) already holds a
// restore through serve-mcp to (F9). It is a mirror rather than a shared
// function because the two doors — this one taking a *config.Config it just
// loaded, that one a *hostServer holding one it loaded at startup — have
// nothing else in common to share it through.
//
// Firecracker takes vcpu and memory from the state file, so a restore cannot
// shrink a machine to fit — the only honest answers are to allow it or refuse
// it. A snapshot from an older kelyfos does not say what it holds; when there
// is a ceiling to enforce, that unknown is refused rather than waved through,
// because a wall with an exception in it is not a wall.
func checkSnapshotCeiling(cfg *config.Config, name string, meta *sandbox.SnapshotMeta) error {
	if cfg == nil || (cfg.ResCPUs == 0 && cfg.ResMemMiB == 0) {
		return nil
	}
	if meta.VcpuCount == 0 && meta.MemMiB == 0 {
		return denial.CeilingSnapshotUnknown.Err(denial.V{"name": name, "file": cfg.Path})
	}
	if cfg.ResCPUs > 0 && meta.VcpuCount > cfg.ResCPUs {
		line, _ := cfg.Ceiling("cpus")
		return denial.CeilingSnapshot.Err(denial.V{
			"name": name, "held": fmt.Sprintf("%d vcpu", meta.VcpuCount), "key": "cpus",
			"limit": strconv.Itoa(cfg.ResCPUs), "file": cfg.Path, "line": strconv.Itoa(line)})
	}
	if cfg.ResMemMiB > 0 && meta.MemMiB > cfg.ResMemMiB {
		line, _ := cfg.Ceiling("mem")
		return denial.CeilingSnapshot.Err(denial.V{
			"name": name, "held": fmt.Sprintf("%d MiB", meta.MemMiB), "key": "mem",
			"limit": fmt.Sprintf("%d MiB", cfg.ResMemMiB), "file": cfg.Path,
			"line": strconv.Itoa(line)})
	}
	return nil
}

// restoreAllowCeiling narrows a restore's allowlist to a named policy, the
// same way the second half of restoreAllow (host/servemcpstate.go) narrows
// sandbox_restore's (F9). The snapshot's own list is the first ceiling and
// stays enforced by list's own default and by restoreNetwork below; this is
// the second one, and only applies when there is a policy to enforce.
func restoreAllowCeiling(cfg *config.Config, list []string) error {
	if cfg == nil {
		return nil
	}
	for _, d := range list {
		if !containsDomain(cfg.Allow, d) {
			return denial.AllowProject.Err(denial.V{
				"domain": d, "file": cfg.Path, "permitted": describeAllow(cfg.Allow)})
		}
	}
	return nil
}

// restoreSecrets decides which credentials a restore attaches. An explicit
// --secret always wins, checked against the restore's allowlist exactly as
// before F9. With none typed, a named policy supplies its own — the same
// secrets sandbox_restore pulls from s.policy.Secrets — filtered to what this
// restore may actually reach rather than erroring on the rest, because a
// kelyfos.toml written for the project in general will usually name domains
// beyond any one snapshot's own allowlist.
func restoreSecrets(cfg *config.Config, typed []string, list []string) ([]*egress.Secret, error) {
	specs := typed
	fromPolicy := false
	if len(specs) == 0 && cfg != nil {
		specs = cfg.Secrets
		fromPolicy = true
	}
	var vetted []*egress.Secret
	for _, spec := range specs {
		sec, err := egress.ParseSecret(spec)
		if err != nil {
			return nil, err
		}
		if !containsDomain(list, sec.Domain) {
			if fromPolicy {
				continue
			}
			return nil, denial.SecretUnallowed.Err(denial.V{"spec": spec, "domain": sec.Domain})
		}
		vetted = append(vetted, sec)
	}
	return vetted, nil
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
