package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/egress"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// TestSnapshotRestoreRealVMWiresAuditBeforeResume is the end-to-end half of
// the P6-4 restore-audit fix that neither of this package's other two
// snapshot-restore tests can be: TestSnapshotRestoreWiresAuditBeforeResume
// reads snapshot.go's own source and never boots anything; the "window"
// half of TestWiringBeforeLiveWindowMatters proves the general
// wired-after-the-fact mechanism with a synthetic egress.Proxy and
// recorder.Recorder standing in for the guest. Neither touches a real
// Firecracker guest, because neither could assume one exists.
//
// This one does. It restores one real snapshot into two independent real
// microVMs — sandbox.go's own "independent fork" guarantee (P3-2) is what
// makes that safe to do twice from a single snapshot directory — and drives
// the exact call order by hand in each: snapshotRestore's fixed order in one
// (restoreNetwork, then recorder.Open, then wireProxyAudit, THEN
// sandbox.Restore, THEN InstallTrustAnchor), and the order it used to have in
// the other (sandbox.Restore and InstallTrustAnchor first, wireProxyAudit
// only afterward). The actual guest, in both, makes one real HTTP attempt
// through the real egress proxy while that ordering is in force. There is no
// timing race anywhere in this: which order ran is a fact about which
// functions this test called before which others, not about how fast
// anything happened to go, so the two subtests are exactly as deterministic
// as the functions they call.
func TestSnapshotRestoreRealVMWiresAuditBeforeResume(t *testing.T) {
	base := requireRealSandbox(t)

	// The destination the guest's egress attempt is aimed at: a plain HTTP
	// server in this test's own process, standing in for whatever a guest
	// would otherwise be reaching on the far side of the proxy — mirroring
	// how snapshot_restore_window_test.go's newTestEgressProxy avoids
	// depending on a real domain or real internet reachability from this
	// machine. It has to be on port 80: restoreNetwork builds its Policy with
	// no Ports field set, and an empty Ports list means the proxy's default
	// of 80 and 443 and nothing else (egress.Policy.allowsPort) — the same
	// restriction `kelyfos snapshot restore` itself lives under, since
	// neither it nor restoreNetwork expose a way to widen it. This sandbox's
	// default net.ipv4.ip_unprivileged_port_start lets an unprivileged
	// process bind it directly; where that is not true this skips rather
	// than failing, the same as every other environmental precondition here.
	upstream := newPort80Server(t)

	dir, err := snapshotDir("realvm-audit-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// The machine the snapshot is taken from needs a network of its own —
	// restoreNetwork only runs when the snapshot says HasNetwork, and the
	// addressing it reuses (HostIP, GuestIP, Netmask, HostMAC, ProxyPort) has
	// to come from somewhere real, the same way a snapshot taken by `kelyfos
	// snapshot save` would carry it (D22). What that source machine's own
	// allowlist says does not matter: both restores below pass their own.
	source, sourceProxy, sourceNet := bootSourceForSnapshot(t, base)
	// Registered before anything below can fail, not just performed inline
	// after SnapshotRunning/Shutdown succeed: Shutdown, proxy.Close and
	// Network.Down are all documented safe to call twice, so this is a
	// harmless no-op on the happy path below and the only thing standing
	// between a failed snapshot (or a failed Shutdown) and a Firecracker
	// process, TAP interface and nftables table leaked on this shared VM.
	t.Cleanup(sourceNet.Down)
	t.Cleanup(sourceProxy.Close)
	t.Cleanup(func() { _ = source.Shutdown(5 * time.Second) })
	if _, _, err := sandbox.SnapshotRunning(&source.State, dir); err != nil {
		t.Fatalf("snapshot the source sandbox: %v", err)
	}
	// Shut the source down and its network with it before either restore
	// stands its own network up, so the TAP and nftables state each restore
	// creates starts from nothing — the task this test was written against
	// asks for exactly this ordering.
	if err := source.Shutdown(5 * time.Second); err != nil {
		t.Fatalf("shut down the source sandbox: %v", err)
	}
	sourceProxy.Close()
	sourceNet.Down()

	meta, err := sandbox.ReadSnapshotMeta(dir)
	if err != nil {
		t.Fatalf("read snapshot meta: %v", err)
	}
	if !meta.HasNetwork || meta.HostIP == "" {
		t.Fatal("the snapshot did not record network metadata — restoreNetwork has nothing to reuse")
	}

	allow := []string{"127.0.0.1"}

	// vetSecret mints one real --secret binding per subtest — NAME@127.0.0.1,
	// with NAME set to a plausible value in this process's own environment so
	// egress.ParseSecret genuinely resolves it, the same way `kelyfos
	// snapshot restore --secret` would. Bound rather than left out so ca is
	// non-nil in both subtests and InstallTrustAnchor is a real control-port
	// round trip to the resumed guest in both, not merely Restore's own
	// Resync and confirmSeccomp round trips — that anchor install is a named
	// part of what P6-4 moved, not an incidental one.
	vetSecret := func(t *testing.T, envName string) *egress.Secret {
		t.Helper()
		t.Setenv(envName, "test-value-never-sent-anywhere")
		sec, err := egress.ParseSecret(envName + "@127.0.0.1")
		if err != nil {
			t.Fatalf("parse secret: %v", err)
		}
		return sec
	}

	t.Run("fixed_order_captures_the_attempt", func(t *testing.T) {
		sec := vetSecret(t, "KELYFOS_TEST_SECRET_FIXED_ORDER")

		opts := base
		proxy, ca, err := restoreNetwork(meta, allow, []*egress.Secret{sec}, &opts)
		if err != nil {
			t.Fatalf("restoreNetwork: %v", err)
		}
		t.Cleanup(opts.Net.Down)
		t.Cleanup(proxy.Close)

		recPath := recorder.Path(sandbox.Root(), opts.ID)
		// The directory, not just the chain inside it. Removing the file alone
		// left `sessions/<id>/` behind empty, twice per run of this package,
		// and 989 of them had piled up in the development cache by the end of
		// Phase 7. `kelyfos runs` is right to list no row for a session with no
		// chain, so the litter is invisible until dev/accept-runs.sh checks its
		// strong claim — one row per session directory, nothing else to keep in
		// step — and fails on the NEXT run because of what this one left.
		t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(recPath)) })
		rec, err := recorder.Open(sandbox.Root(), opts.ID)
		if err != nil {
			t.Fatalf("open recorder: %v", err)
		}
		t.Cleanup(func() { _ = rec.Close() })
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSessionStart, Kelyfos: Version,
			Reason: "restored from realvm-audit-test (fixed order)",
		})
		// The fix: wired while the guest is still frozen, before Restore ever
		// lets it run — exactly the order host/snapshot.go's snapshotRestore
		// uses, and exactly what TestSnapshotRestoreWiresAuditBeforeResume
		// checks for textually in that function's own source.
		wireProxyAudit(proxy, rec, "", nil)

		sb, _, err := sandbox.Restore(dir, opts)
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		t.Cleanup(func() { _ = sb.Shutdown(5 * time.Second) })

		if ca != nil {
			if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
				t.Fatalf("install trust anchor: %v", err)
			}
		}

		hitsBefore := upstream.Hits()
		code, err := guestEgressAttempt(sb, upstream.port)
		if err != nil {
			t.Fatalf("guest egress attempt: %v", err)
		}
		requireRealHTTPClientRan(t, code)
		// Waits for the proxy's own handler goroutine — including its call to
		// report(), which is what actually calls OnEvent — to finish before
		// this goroutine reads the chain back below. Same reasoning as
		// snapshot_restore_window_test.go's identical call in its
		// "wired_before" subtest.
		proxy.Close()
		if upstream.Hits() <= hitsBefore {
			t.Fatal("no request reached the upstream server — the guest's exec did not make a " +
				"genuine attempt, so this subtest cannot prove what it claims to")
		}

		events := readChain(t, sandbox.Root(), opts.ID)
		if !hasEgressAttemptFor(events, "127.0.0.1", 80) {
			t.Error("a real guest's egress attempt, made after wireProxyAudit ran and before " +
				"sandbox.Restore resumed it, is missing from the real recorder chain — the fix in " +
				"host/snapshot.go should have captured it")
		}
		if !hasSecretWithheldFor(events, "127.0.0.1") {
			t.Error("the secret bound to 127.0.0.1 should have produced a secret.withheld event " +
				"(the attempt was plain HTTP, and a credential is never attached to one) — its " +
				"absence means this subtest is not exercising the trust-anchor path it claims to")
		}
	})

	t.Run("old_order_missed_the_attempt", func(t *testing.T) {
		sec := vetSecret(t, "KELYFOS_TEST_SECRET_OLD_ORDER")

		opts := base
		proxy, ca, err := restoreNetwork(meta, allow, []*egress.Secret{sec}, &opts)
		if err != nil {
			t.Fatalf("restoreNetwork: %v", err)
		}
		t.Cleanup(opts.Net.Down)
		t.Cleanup(proxy.Close)

		// The bug's order: the guest resumes — and InstallTrustAnchor makes
		// its own live control-port round trip to it — while proxy.OnEvent,
		// OnSecret and OnWithheld are still nil. This is the exact sequence
		// host/snapshot.go's snapshotRestore used to run before P6-4.
		sb, _, err := sandbox.Restore(dir, opts)
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		t.Cleanup(func() { _ = sb.Shutdown(5 * time.Second) })

		if ca != nil {
			if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
				t.Fatalf("install trust anchor: %v", err)
			}
		}

		hitsBefore := upstream.Hits()
		code, err := guestEgressAttempt(sb, upstream.port)
		if err != nil {
			t.Fatalf("guest egress attempt: %v", err)
		}
		requireRealHTTPClientRan(t, code)
		// Same barrier as the sibling subtest, for the same reason: wait for
		// the attempt's own handler goroutine to finish before this goroutine
		// writes OnEvent/OnSecret/OnWithheld by wiring below — without it the
		// two race on the same fields, which -race rightly calls out even
		// though production code never wires a proxy while a request it
		// already accepted is in flight.
		proxy.Close()
		// This is the guard against F20's vacuous-pass failure mode: the
		// assertion below this one proves the ABSENCE of egress.attempt and
		// secret.withheld, which passes trivially if the guest never made a
		// request at all. requireRealHTTPClientRan already rules out "the
		// client binary was missing"; this rules out every other way the
		// request could have failed to happen by checking, independently of
		// the recorder chain this subtest is about to say is silent, that the
		// request genuinely landed on the real upstream server.
		if upstream.Hits() <= hitsBefore {
			t.Fatal("no request reached the upstream server — the guest's exec did not make a " +
				"genuine attempt, so the assertion below would pass vacuously")
		}

		recPath := recorder.Path(sandbox.Root(), opts.ID)
		// The directory, not just the chain inside it. Removing the file alone
		// left `sessions/<id>/` behind empty, twice per run of this package,
		// and 989 of them had piled up in the development cache by the end of
		// Phase 7. `kelyfos runs` is right to list no row for a session with no
		// chain, so the litter is invisible until dev/accept-runs.sh checks its
		// strong claim — one row per session directory, nothing else to keep in
		// step — and fails on the NEXT run because of what this one left.
		t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(recPath)) })
		rec, err := recorder.Open(sandbox.Root(), opts.ID)
		if err != nil {
			t.Fatalf("open recorder: %v", err)
		}
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSessionStart, Kelyfos: Version,
			Reason: "restored from realvm-audit-test (old order)",
		})
		wireProxyAudit(proxy, rec, "", nil)
		_ = rec.Close()

		events := readChain(t, sandbox.Root(), opts.ID)
		if hasEgressAttemptFor(events, "127.0.0.1", 80) || hasSecretWithheldFor(events, "127.0.0.1") {
			t.Fatal("an attempt made before wireProxyAudit ran was somehow captured — this subtest's " +
				"reproduction of the old bug is wrong, which means the sibling subtest above is not " +
				"proving what it claims to")
		}
		// This branch passing is not good news about the product — it is this
		// test proving that the old order really did drop a real guest's real
		// attempt on the floor, silently, egress.attempt and secret.withheld
		// alike. Same spirit as snapshot_restore_window_test.go's own
		// "wired_after" subtest. What keeps this repository out of this
		// branch is that snapshotRestore no longer runs this order at all.
	})
}

// requireRealSandbox mirrors internal/sandbox/integration_test.go's
// requireSandbox: skip cleanly rather than fail whenever this machine cannot
// boot a real microVM, so `go test ./host/...` stays useful on a laptop with
// none of KVM, Firecracker or a built image, and `go test -race
// ./internal/sandbox/... ./host/...` under Lima exercises this test for
// real. Duplicated rather than imported because that helper lives in
// internal/sandbox's own external test package (sandbox_test), which this
// package cannot reach into.
func requireRealSandbox(t *testing.T) sandbox.Options {
	t.Helper()
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("no /dev/kvm on this machine")
	}
	if _, err := exec.LookPath("firecracker"); err != nil {
		t.Skip("firecracker is not on PATH")
	}
	arch := sandbox.HostArch()
	dir := sandbox.ImageDir(arch)
	kernel, err := sandbox.KernelArtifact(arch)
	if err != nil {
		t.Skipf("unsupported architecture %s", arch)
	}
	for _, f := range []string{filepath.Join(dir, kernel), filepath.Join(dir, "rootfs.ext4")} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("no built image at %s — run `make image` first", dir)
		}
	}
	m, err := sandbox.ReadManifest(dir)
	if err != nil {
		t.Skipf("no image.json in %s — rebuild with `make image`: %v", dir, err)
	}
	return sandbox.Options{Arch: arch, Flavor: m.Flavor, Quiet: true}
}

// bootSourceForSnapshot boots a real, networked sandbox for
// sandbox.SnapshotRunning to freeze — the template both restores in this
// test's two subtests come from. Its own allowlist is never exercised (both
// restores pass their own to restoreNetwork), so it is a narrow one purely
// to give the machine a NIC and a proxy port worth recording in the
// snapshot's metadata.
func bootSourceForSnapshot(t *testing.T, base sandbox.Options) (*sandbox.Sandbox, *egress.Proxy, *sandbox.Network) {
	t.Helper()
	id, err := sandbox.NewID()
	if err != nil {
		t.Fatalf("mint sandbox id: %v", err)
	}
	netw, err := sandbox.NewNetwork(id)
	if err != nil {
		t.Fatalf("new network: %v", err)
	}
	ok := false
	defer func() {
		if !ok {
			netw.Down()
		}
	}()

	// Peer is set here for the same reason the five production sites set it:
	// this proxy binds a real TAP address and is the only one in the tree the
	// repo-wide audit cannot see, _test.go being excluded from it. Without it
	// the nftables drop would be the single layer under a proxy on a live
	// address — the layer F9's own fix argues may be wrong (F9).
	proxy := &egress.Proxy{Policy: egress.Policy{Allow: []string{"127.0.0.1"}}, Peer: netw.GuestAddr()}
	port, err := proxy.Listen(netw.HostIP.String() + ":0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	if err := netw.Restrict(port); err != nil {
		proxy.Close()
		t.Fatalf("restrict network: %v", err)
	}
	go proxy.Serve()

	opts := base
	opts.ID = id
	opts.Net = netw
	opts.Allow = []string{"127.0.0.1"}

	sb, err := sandbox.New(opts)
	if err != nil {
		proxy.Close()
		t.Fatalf("new sandbox: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		proxy.Close()
		t.Fatalf("start: %v", err)
	}
	if _, err := sb.WaitReady(ctx); err != nil {
		_ = sb.Shutdown(5 * time.Second)
		proxy.Close()
		t.Fatalf("guest never became ready: %v", err)
	}

	ok = true
	return sb, proxy, netw
}

// port80Server is a real HTTP server on 127.0.0.1:80 — the port a guest's
// attempt through a restored proxy is actually allowed to reach, since
// restoreNetwork's Policy carries no Ports override and an empty one means
// 80 and 443 only.
type port80Server struct {
	*httptest.Server
	port int
	hits *int32
}

// newPort80Server binds one, or skips this test cleanly when the environment
// will not allow it (a normal Linux default reserves ports below 1024 for
// privileged processes; this sandbox's own default does not, but nothing
// here should assume that of anywhere else this test might run).
func newPort80Server(t *testing.T) port80Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:80 in this environment: %v", err)
	}
	var hits int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	_ = ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)
	return port80Server{Server: ts, port: 80, hits: &hits}
}

// Hits reports how many real HTTP requests this server has received so far.
// It exists so a subtest can prove, independently of the recorder chain, that
// guestEgressAttempt's exec genuinely reached this process rather than merely
// that the exec returned without a protocol-level error — the two are not the
// same claim, and F20 is exactly a case where they were conflated.
// forwardHTTP (internal/egress/proxy.go) calls RoundTrip against this server
// regardless of whether OnEvent/OnSecret/OnWithheld are wired, so a real
// attempt lands here the same way whether or not the recorder saw it; a
// subtest that asserts the recorder did NOT see it still needs this to prove
// the silence was the proxy's unwired hooks and not a guest that never tried.
func (p port80Server) Hits() int32 {
	return atomic.LoadInt32(p.hits)
}

// guestEgressAttempt drives the real guest to make one real HTTP request to
// 127.0.0.1:port through its own HTTPS_PROXY — the same environment variable
// docs/networking.md §5 says the supervisor sets from the kernel command
// line, and the same one a real wget invocation inside the sandbox would pick
// up unprompted. NO_PROXY and no_proxy are cleared for this one command: the
// supervisor also sets them, to "localhost,127.0.0.1" (§5), and with them in
// place wget bypasses the proxy entirely and dials the guest's OWN loopback
// instead — which has nothing listening on it and fails before ever reaching
// the proxy this test means to exercise. This is confirmed against a real
// guest, not assumed: an unmodified request to 127.0.0.1 fails with
// "Connection refused" from the guest's own loopback, and clearing NO_PROXY
// is what turns that into a real CONNECT/absolute-URI request the proxy
// receives.
//
// wget, not curl: image/flavors/base/buildroot.fragment is explicit that the
// base flavor is "BusyBox and musl and nothing else. No TLS client" — curl is
// dev-flavor-only (BR2_PACKAGE_LIBCURL_CURL in
// image/flavors/dev/buildroot.fragment), so a guest built from the base
// flavor, which is what requireRealSandbox accepts and what this VM normally
// builds, has no curl in it at all (F20: an earlier version of this comment
// claimed otherwise, and was wrong). BusyBox wget is on both flavors and
// carries -q/-O/-T, which is enough for the plain-HTTP attempt this test
// makes. The exit code is returned rather than swallowed here, on purpose:
// 127 (command not found) looks identical to a connection error from
// outside, and a caller that never distinguishes the two can spend hours
// asking "is the product broken?" about a guest that never ran the command at
// all. It is the caller's job to check it, in both subtests — see
// requireRealHTTPClientRan.
func guestEgressAttempt(sb *sandbox.Sandbox, port int) (code int, err error) {
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf(
		"NO_PROXY= no_proxy= wget -q -O /dev/null -T 10 http://127.0.0.1:%d/", port,
	)}
	_, code, _, err = runGuestExec(sb.State.UDSPath, cmd)
	return code, err
}

// requireRealHTTPClientRan fails the subtest loudly when the guest's exec
// never actually ran an HTTP client — exit 127, "command not found" — rather
// than let it proceed on the false premise that a real attempt was made. This
// is the fix for F20: guestEgressAttempt used to discard the exec's exit
// status entirely, so a guest image missing the client it was told to run
// looked, from here, identical to one that ran it and hit a real connection
// error.
func requireRealHTTPClientRan(t *testing.T, code int) {
	t.Helper()
	if code == 127 {
		t.Fatal("guest lacks a usable HTTP client (exit 127, command not found) — " +
			"this test requires BusyBox wget in the guest image")
	}
}

// runGuestExec performs one full exec round trip over vsock and returns
// stdout, the exit code and any protocol-level error the guest reported.
// Copied from internal/sandbox/integration_test.go's runExec rather than
// shared, for the same reason requireRealSandbox is: that helper lives in
// sandbox_test, an external test package this one cannot import.
func runGuestExec(uds string, cmd []string) (stdout string, code int, perr *proto.Error, err error) {
	conn, err := sandbox.Connect(uds, proto.PortExec, 15*time.Second)
	if err != nil {
		return "", 0, nil, err
	}
	defer conn.Close()

	if err := proto.NewWriter(conn).Write(proto.ExecRequest{
		V: proto.Version, ID: "realvm-audit-test", Cmd: proto.EncodeCmd(cmd), TimeoutMS: 20000,
	}); err != nil {
		return "", 0, nil, err
	}

	var out strings.Builder
	r := proto.NewReader(conn)
	for {
		var resp proto.ExecResponse
		if err := r.Read(&resp); err != nil {
			return out.String(), 0, nil, fmt.Errorf("closed without an exit frame: %w", err)
		}
		switch resp.Stream {
		case proto.StreamStdout:
			b, _ := base64.StdEncoding.DecodeString(resp.Data)
			out.Write(b)
		case proto.StreamStderr:
			// ignored by this test
		case proto.StreamExit:
			c := -1
			if resp.Code != nil {
				c = *resp.Code
			}
			return out.String(), c, resp.Error, nil
		}
	}
}

// readChain reads one sandbox's recorder chain back from disk.
func readChain(t *testing.T, root, id string) []recorder.Event {
	t.Helper()
	f, err := os.Open(recorder.Path(root, id))
	if err != nil {
		t.Fatalf("open recorder chain: %v", err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		t.Fatalf("read recorder chain: %v", err)
	}
	return events
}

func hasEgressAttemptFor(events []recorder.Event, host string, port int) bool {
	for _, e := range events {
		if e.Type == recorder.TypeEgressAttempt && e.Host == host && e.Port == port {
			return true
		}
	}
	return false
}

func hasSecretWithheldFor(events []recorder.Event, host string) bool {
	for _, e := range events {
		if e.Type == recorder.TypeSecretWithheld && e.Host == host {
			return true
		}
	}
	return false
}
