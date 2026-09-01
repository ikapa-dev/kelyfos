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

// The audit also observed a list racing a run: with the cap forcing the
// pipeline's floor through one bounded set of goroutines, calls dispatched in
// burst order can still overlap — that is the concurrency MCP promises and
// this documents, not a race the cap was meant to remove. What the cap removes
// is the amplification.
func TestA10_TheCapIsSizedLikeEveryOtherListener(t *testing.T) {
	if maxConcurrentToolCalls != 128 {
		t.Errorf("maxConcurrentToolCalls = %d, want the 128 every other listener uses", maxConcurrentToolCalls)
	}
}
