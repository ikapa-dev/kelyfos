package sandbox_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// These tests boot a real microVM, so they need KVM, Firecracker and a built
// image. They are skipped otherwise rather than failing, so `go test ./...`
// stays useful on a machine that has none of those. `make test-integration`
// runs them deliberately.
func requireSandbox(t *testing.T) sandbox.Options {
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
	// Take the flavor from the image that is actually there (D21) rather than
	// assuming base: a dev machine usually holds dev, and hardcoding the label
	// would make every integration test fail the manifest check.
	m, err := sandbox.ReadManifest(dir)
	if err != nil {
		t.Skipf("no image.json in %s — rebuild with `make image`: %v", dir, err)
	}
	return sandbox.Options{Arch: arch, Flavor: m.Flavor, Quiet: true}
}

func bootOne(t *testing.T) *sandbox.Sandbox {
	t.Helper()
	sb, err := sandbox.New(requireSandbox(t))
	if err != nil {
		t.Fatalf("new sandbox: %v", err)
	}
	t.Cleanup(func() { _ = sb.Shutdown(5 * time.Second) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := sb.WaitReady(ctx); err != nil {
		t.Fatalf("guest never became ready: %v", err)
	}
	return sb
}

// runExec performs one full exec round trip and returns stdout, the exit code
// and any protocol-level error the guest reported.
func runExec(uds string, cmd []string) (stdout string, code int, perr *proto.Error, err error) {
	conn, err := sandbox.Connect(uds, proto.PortExec, 15*time.Second)
	if err != nil {
		return "", 0, nil, err
	}
	defer conn.Close()

	if err := proto.NewWriter(conn).Write(proto.ExecRequest{
		V: proto.Version, ID: "t", Cmd: cmd, TimeoutMS: 20000,
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
			// ignored by these tests
		case proto.StreamExit:
			c := -1
			if resp.Code != nil {
				c = *resp.Code
			}
			return out.String(), c, resp.Error, nil
		}
	}
}

// TestConcurrentExecs is a regression test for the PID 1 reaping race.
//
// Before P2-1 the supervisor could have had both os/exec's Cmd.Wait and a
// wait4(-1) reaper loop waiting on the same children; whichever won stole the
// other's status. The failure mode is nasty precisely because it is
// intermittent — a command runs perfectly and is reported as failing with
// "waitid: no child processes", once in a while, under load.
//
// So this hammers it: many concurrent commands, each with output unique to its
// own request, all of which must come back with exit 0, no protocol error, and
// their own output. One stolen status anywhere fails the test.
func TestConcurrentExecs(t *testing.T) {
	sb := bootOne(t)

	const workers = 24
	type result struct {
		i    int
		out  string
		code int
		perr *proto.Error
		err  error
	}
	results := make(chan result, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Mixed durations so exits interleave rather than arriving in a
			// tidy batch; a single SIGCHLD can cover several of them.
			script := fmt.Sprintf("sleep 0.%02d; echo marker-%d", i%20, i)
			out, code, perr, err := runExec(sb.State.UDSPath, []string{"/bin/sh", "-c", script})
			results <- result{i: i, out: out, code: code, perr: perr, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	seen := 0
	for r := range results {
		seen++
		switch {
		case r.err != nil:
			t.Errorf("worker %d: transport error: %v", r.i, r.err)
		case r.perr != nil:
			t.Errorf("worker %d: guest reported %s: %s", r.i, r.perr.Kind, r.perr.Message)
		case r.code != 0:
			t.Errorf("worker %d: exit %d, want 0 (a stolen wait status looks exactly like this)", r.i, r.code)
		case strings.TrimSpace(r.out) != fmt.Sprintf("marker-%d", r.i):
			t.Errorf("worker %d: got output %q, want marker-%d", r.i, strings.TrimSpace(r.out), r.i)
		}
	}
	if seen != workers {
		t.Fatalf("got %d results, want %d", seen, workers)
	}
}

// TestOrphansAreReaped checks the other half of PID 1's job: a child that
// outlives its parent is re-parented to PID 1, and if nobody waits for it the
// process table fills with zombies.
func TestOrphansAreReaped(t *testing.T) {
	sb := bootOne(t)

	for i := 0; i < 12; i++ {
		// The subshell exits immediately, orphaning the background sleep onto
		// PID 1.
		if _, code, perr, err := runExec(sb.State.UDSPath,
			[]string{"/bin/sh", "-c", "(sleep 0.2 &) ; exit 0"}); err != nil || perr != nil || code != 0 {
			t.Fatalf("spawn %d: code=%d perr=%v err=%v", i, code, perr, err)
		}
	}

	// Give the orphans time to exit and be reaped.
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, code, perr, err := runExec(sb.State.UDSPath,
			[]string{"/bin/sh", "-c", "ps -o stat | grep -c '^Z' || true"})
		if err != nil || perr != nil || code != 0 {
			t.Fatalf("zombie count: code=%d perr=%v err=%v", code, perr, err)
		}
		zombies := strings.TrimSpace(out)
		if zombies == "0" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s zombies still present — PID 1 is not reaping orphans", zombies)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// TestExecExitCodesAndStreams pins the contract the CLI depends on: exit codes
// pass through, and a command that produces a lot of output survives chunking.
func TestExecExitCodesAndStreams(t *testing.T) {
	sb := bootOne(t)

	if _, code, perr, err := runExec(sb.State.UDSPath, []string{"/bin/sh", "-c", "exit 42"}); err != nil || perr != nil {
		t.Fatalf("exit 42: perr=%v err=%v", perr, err)
	} else if code != 42 {
		t.Errorf("got exit %d, want 42", code)
	}

	out, code, perr, err := runExec(sb.State.UDSPath,
		[]string{"/bin/sh", "-c", "dd if=/dev/zero bs=1024 count=512 2>/dev/null | wc -c"})
	if err != nil || perr != nil || code != 0 {
		t.Fatalf("large output: code=%d perr=%v err=%v", code, perr, err)
	}
	if strings.TrimSpace(out) != "524288" {
		t.Errorf("got %q, want 524288 — output was truncated across chunk boundaries", strings.TrimSpace(out))
	}
}
