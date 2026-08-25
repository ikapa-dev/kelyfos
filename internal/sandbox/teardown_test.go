package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// cleanup is what New and Restore call on every failure once the guest's
// channels are bound, and until L-7 it removed the run directory and nothing
// else. Removing the directory unlinks the socket names; it does not close a
// single descriptor. So a machine that failed to start left its listeners bound
// and their accept loops running, held alive for the life of the process by the
// closure over the sandbox — invisible on `kelyfos run`, which exits moments
// later, and cumulative inside `serve-mcp` or a team host, which does not.
func TestCleanupClosesTheChannelsTheGuestDialsIn(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "firecracker", "abc123", "root")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Sandbox{
		State: State{ID: "abc123", RunDir: runDir, UDSPath: filepath.Join(runDir, "v.sock")},
		opts: Options{OnTeamRequest: func(proto.TeamRequest) proto.TeamResponse {
			return proto.TeamResponse{OK: true}
		}},
	}
	ln, err := net.Listen("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortReady))
	if err != nil {
		t.Fatal(err)
	}
	s.readyLn = ln
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	if err := s.listenTeam(); err != nil {
		t.Fatal(err)
	}

	// The goroutine leak, in the shape serveReady has it: an accept loop that
	// only a closed listener returns from.
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		if c, err := s.readyLn.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	s.cleanup()

	select {
	case <-accepting:
	case <-time.After(10 * time.Second):
		t.Fatal("the accept loop is still running on a listener nobody holds a handle to")
	}
	// The other two, asked directly rather than through their serve loops. A
	// deadline so an open listener fails the test instead of hanging it.
	for name, l := range map[string]net.Listener{"events": s.eventsLn, "team": s.teamLn} {
		ul, ok := l.(*net.UnixListener)
		if !ok {
			t.Fatalf("the %s channel is not a unix listener", name)
		}
		_ = ul.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := ul.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("the %s listener is still bound after cleanup: %v", name, err)
		}
	}
}

// syncJailedWorkspace was written for the case where the image inside the jail
// and the image on the host are two files rather than one under two names, and
// it had no caller at all — so on a run directory that could not be hard-linked
// to the workspace image, the guest wrote to a copy that cleanup deleted, and
// the run then announced a write-back that had put nothing anywhere (D-1).
//
// Two filesystems is what causes that for real and a test cannot mount one.
// What it can do is set up what a cross-device stageJail leaves behind, which
// is the whole of the condition: two separate files.
func TestAJailedWorkspaceLeavesTheJailBeforeTheJailIsRemoved(t *testing.T) {
	hostImage := filepath.Join(t.TempDir(), "abc123.ext4")
	if err := os.WriteFile(hostImage, []byte("what the host packed"), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(t.TempDir(), "firecracker", "abc123", "root")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(runDir, defaultJailNames().Workspace)
	if err := os.WriteFile(inside, []byte("what the guest wrote"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Sandbox{State: State{ID: "abc123", RunDir: runDir, Jailed: true, Workspace: hostImage}}
	if err := s.Shutdown(time.Second); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	got, err := os.ReadFile(hostImage)
	if err != nil {
		t.Fatalf("the host image is not there to be written back to: %v", err)
	}
	if string(got) != "what the guest wrote" {
		t.Fatalf("the guest's work never left the jail: the host image still reads %q", got)
	}
	if _, err := os.Stat(filepath.Dir(runDir)); !os.IsNotExist(err) {
		t.Fatalf("the jail outlived the machine: %v", err)
	}

	// Shutdown is documented safe to call more than once, and the write-back is
	// now one of the things it does. The second call finds no jail and has
	// nothing to say about it — it must not report a loss it did not cause.
	if err := s.Shutdown(time.Second); err != nil {
		t.Fatalf("a second shutdown reported a failure: %v", err)
	}
	if got, err := os.ReadFile(hostImage); err != nil || string(got) != "what the guest wrote" {
		t.Fatalf("the second shutdown changed the host image: %q, %v", got, err)
	}
}

// The other half of the same change, and the one every ordinary installation
// takes: images and jails live under one cache root, so stageJail hard-links
// and the two names are one file. Teardown must then cost two stats and change
// nothing — and in particular must not report a failure, because Shutdown now
// returns one when the write-back does not happen and every run goes through
// here.
func TestAHardLinkedWorkspaceIsLeftExactlyAsItIs(t *testing.T) {
	hostImage := filepath.Join(t.TempDir(), "abc123.ext4")
	if err := os.WriteFile(hostImage, []byte("one file, two names"), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(t.TempDir(), "firecracker", "abc123", "root")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(runDir, defaultJailNames().Workspace)
	if err := os.Link(hostImage, inside); err != nil {
		t.Skipf("this filesystem will not hard-link, which is the other test: %v", err)
	}
	before, err := os.Stat(hostImage)
	if err != nil {
		t.Fatal(err)
	}

	s := &Sandbox{State: State{ID: "abc123", RunDir: runDir, Jailed: true, Workspace: hostImage}}
	if err := s.Shutdown(time.Second); err != nil {
		t.Fatalf("an ordinary teardown reported a failure: %v", err)
	}

	after, err := os.Stat(hostImage)
	if err != nil {
		t.Fatalf("the host image did not survive its own machine: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the image was replaced rather than recognised as the file it already was")
	}
	got, err := os.ReadFile(hostImage)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one file, two names" {
		t.Fatalf("the host image reads %q", got)
	}
}

// The other direction of the same worry as D-1, and the one D-1 introduced: a
// write-back is a rescue, and a rescue that can destroy what it is rescuing is
// the same lost work wearing the other hat.
//
// The write-back used to reuse linkInto, which removes the destination and then
// links or copies onto the name. That is right for staging into a jail and
// wrong for the host's own image: on the cross-device path the second half is a
// copy, so between the remove and the last byte the person has no image, and an
// interruption in the middle leaves a partial one under the name they trust.
//
// An interruption is what a test cannot stage. What it can stage is the same
// window entered from the other side — a write-back that gets as far as the
// copy and then cannot finish — and a directory is the source that does that
// wherever this runs, because both refusals are the kernel's rather than any
// filesystem's: link(2) refuses a directory with EPERM, which is the branch a
// cross-device stage takes, and the read that follows fails with EISDIR.
// Measured against the old code this left an empty file where the image had
// been, which is the loss with none of the drama of a power cut.
func TestAWriteBackThatCannotFinishLeavesTheHostImageWhereItWas(t *testing.T) {
	hostDir := t.TempDir()
	hostImage := filepath.Join(hostDir, "abc123.ext4")
	if err := os.WriteFile(hostImage, []byte("what the host packed"), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(t.TempDir(), "firecracker", "abc123", "root")
	inside := filepath.Join(runDir, defaultJailNames().Workspace)
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := syncJailedWorkspace(runDir, hostImage); err == nil {
		t.Fatal("a write-back that could not read its source reported success")
	}

	got, err := os.ReadFile(hostImage)
	if err != nil {
		t.Fatalf("the failed write-back took the host's image with it: %v", err)
	}
	if string(got) != "what the host packed" {
		t.Fatalf("the host image was replaced by what the failed write-back got as far as: %q", got)
	}
	// And nothing left beside it. A temporary that outlives the attempt is a
	// second copy of somebody's workspace sitting in their directory under a
	// name nothing will ever pick up again.
	ents, err := os.ReadDir(hostDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != filepath.Base(hostImage) {
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = e.Name()
		}
		t.Fatalf("the failed write-back left something beside the image: %v", names)
	}
}
