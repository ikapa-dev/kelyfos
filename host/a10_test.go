package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
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
