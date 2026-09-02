package main

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// The audit of 2026-09-01's A10: tool calls were dispatched on unbounded
// goroutines — every network listener in the product has a semaphore; this
// door, the one that turns a model's calls into machines and credentials, had
// none. With the bound in force, a pipelined stream cannot have more calls in
// flight than the cap: the read loop waits for a slot, which is backpressure
// rather than amplification.

func TestA10_PipelinedCallsNeverExceedTheDispatchCap(t *testing.T) {
	s := serverWith(t, policy)
	// A cap of 2, small enough to watch fail if it does not hold.
	s.toolSem = make(chan struct{}, 2)

	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	release := make(chan struct{})
	s.dispatched = func(tool string) {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		<-release // every call blocks in dispatch until the test lets it go
		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	// Four pipelined calls through the door with two slots: at most two may
	// reach dispatch before the first release.
	var out strings.Builder
	in := ""
	for i := 1; i <= 4; i++ {
		in += fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"sandbox_list","arguments":{}}}`+"\n", i)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.serve(strings.NewReader(in), &out)
	}()

	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	reached := inFlight
	mu.Unlock()
	if reached != 2 {
		t.Fatalf("%d calls were in flight with a cap of 2", reached)
	}
	close(release)
	<-done

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight > 2 {
		t.Errorf("%d calls were in flight at once, want at most the cap of 2", maxInFlight)
	}
	// Every call was answered, none dropped by the throttle.
	if got := strings.Count(out.String(), `"id"`); got != 4 {
		t.Errorf("the transcript holds %d answers, want 4:\n%s", got, out.String())
	}
}

// The cap is the same 128 the guest channels' listeners use, and it is
// actually in force on a real serve: a server constructed without a preset
// semaphore builds one lazily, and the bound holds on it too — the first test
// pins the preset case, this one pins the lazily-built default, which a
// refactor could quietly drop.
func TestA10_TheDefaultCapIsBuiltAndHolds(t *testing.T) {
	s := serverWith(t, policy)
	if s.toolSem != nil {
		t.Fatal("a fresh server pre-built its semaphore; the lazy build moved")
	}

	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	release := make(chan struct{})
	s.dispatched = func(tool string) {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	// Two over the built-in cap of maxConcurrentToolCalls: at most that many
	// in flight, and everything answered.
	in := ""
	for i := 1; i <= maxConcurrentToolCalls+2; i++ {
		in += fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"sandbox_list","arguments":{}}}`+"\n", i)
	}
	var out strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.serve(strings.NewReader(in), &out)
	}()

	// Fill the cap and confirm the bound, then let everything through.
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	reached := inFlight
	mu.Unlock()
	if reached != maxConcurrentToolCalls {
		t.Fatalf("%d calls were in flight, want the default cap of %d", reached, maxConcurrentToolCalls)
	}
	close(release)
	<-done
	mu.Lock()
	defer mu.Unlock()
	if maxInFlight > maxConcurrentToolCalls {
		t.Errorf("%d calls were in flight at once, want at most %d", maxInFlight, maxConcurrentToolCalls)
	}
	if got := strings.Count(out.String(), `"id"`); got != maxConcurrentToolCalls+2 {
		t.Errorf("the transcript holds %d answers, want %d", got, maxConcurrentToolCalls+2)
	}
}

// M10: at the dispatch cap the read loop reads nothing further, so before this
// fix a shutdown could not break in — stop() now closes s.stopping, and the
// read loop parked on a full toolSem wakes and returns rather than dispatching
// the next call. The stopping channel is built here as newHostServer does, not
// left to serve's lazy build, so the test's stop() cannot race the init.
func TestM10_AStopReleasesAReadLoopParkedAtTheCap(t *testing.T) {
	s := serverWith(t, policy)
	s.toolSem = make(chan struct{}, 1) // one slot
	s.stopping = make(chan struct{})

	var mu sync.Mutex
	dispatched := 0
	release := make(chan struct{})
	firstIn := make(chan struct{})
	var once sync.Once
	s.dispatched = func(tool string) {
		mu.Lock()
		dispatched++
		mu.Unlock()
		once.Do(func() { close(firstIn) })
		<-release // hold the one slot until the test lets go
	}

	// Two pipelined calls: the first takes the slot and blocks in dispatch, so
	// the read loop parks trying to take the slot for the second.
	in := ""
	for i := 1; i <= 2; i++ {
		in += fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"sandbox_list","arguments":{}}}`+"\n", i)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.serve(strings.NewReader(in), io.Discard)
	}()

	<-firstIn                          // the first call is in dispatch, holding the slot
	time.Sleep(100 * time.Millisecond) // let the read loop park on the cap for the second

	s.stop()       // wakes the parked read loop; it returns without dispatching the second
	close(release) // let the first call finish so serve's wg.Wait() can return
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after stop() released the read loop parked at the cap")
	}
	mu.Lock()
	defer mu.Unlock()
	if dispatched != 1 {
		t.Errorf("%d calls were dispatched; the second must never have been — the read loop was stopped at the cap", dispatched)
	}
}

// M10: a sandbox_exec in flight is cut short by stop() rather than held for its
// whole timeout. The guest here is a socket that accepts and never answers, so
// the exec blocks in its handshake; stop() returns errServerStopping.
func TestM10_AnInFlightExecIsCutShortByAStop(t *testing.T) {
	s := serverWith(t, policy)
	s.stopping = make(chan struct{})

	sock := filepath.Join(t.TempDir(), "x.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		var held []net.Conn
		for {
			c, err := ln.Accept()
			if err != nil {
				for _, h := range held {
					_ = h.Close()
				}
				return
			}
			held = append(held, c) // hold open, never respond
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()

	b := &servedBox{sb: &sandbox.Sandbox{State: sandbox.State{UDSPath: sock}}}
	type outcome struct {
		res *sandbox.ExecResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := s.execUnlessStopping(b, []string{"true"}, nil, time.Minute)
		done <- outcome{res, err}
	}()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the exec never dialled the guest")
	}
	s.stop() // the exec is blocked in its handshake; stop cuts it short
	select {
	case o := <-done:
		if o.err != errServerStopping {
			t.Errorf("a stopped exec returned %v, want errServerStopping", o.err)
		}
		if o.res != nil {
			t.Errorf("a cut-short exec returned a result, want none: %v", o.res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("execUnlessStopping did not return after stop()")
	}
}
