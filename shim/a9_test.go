package shim

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// The audit of 2026-09-01's A9: createSandbox censused the fleet, released
// the lock, booted for seconds, and registered without a re-check — a burst
// of 32 concurrent POSTs against a cap of 16 overshoots it roughly two times,
// each excess box a real microVM. The fix is the pattern serve-mcp's adopt
// already used: the limit is re-checked under the registration lock, so a
// lost race costs one torn-down machine, never an over-cap fleet.
//
// No boot is needed to hold that property: registration itself is what the
// burst contends for, and these tests drive it with fake boxes the way the
// a1 fork tests drive the fleet ceiling.

func TestA9_RegistrationRefusesWhenTheFleetIsFull(t *testing.T) {
	s := &Server{boxes: map[string]*box{}}
	for i := 0; i < MaxSandboxes; i++ {
		b := &box{sb: &sandbox.Sandbox{State: sandbox.State{ID: fmt.Sprintf("full%02d", i)}}}
		if !s.register(b) {
			t.Fatalf("box %d could not register on an empty fleet", i)
		}
	}
	extra := &box{sb: &sandbox.Sandbox{State: sandbox.State{ID: "overthecap"}}}
	if s.register(extra) {
		t.Fatal("a box registered past MaxSandboxes")
	}
	if len(s.boxes) != MaxSandboxes {
		t.Errorf("the fleet holds %d boxes, want exactly the cap", len(s.boxes))
	}
}

// The concurrency the TOCTOU lived in: 32 goroutines race for one free slot.
// Exactly one wins; the cap never moves; nothing deadlocks on the lock.
func TestA9_ABurstOfRacingRegistrationsNeverExceedsTheCap(t *testing.T) {
	s := &Server{boxes: map[string]*box{}}
	for i := 0; i < MaxSandboxes-1; i++ {
		s.boxes[fmt.Sprintf("pre%02d", i)] = &box{sb: &sandbox.Sandbox{State: sandbox.State{ID: fmt.Sprintf("pre%02d", i)}}}
	}

	const burst = 32
	winners := make(chan bool, burst)
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := &box{sb: &sandbox.Sandbox{State: sandbox.State{ID: fmt.Sprintf("racer%02d", i)}}}
			winners <- s.register(b)
		}(i)
	}
	wg.Wait()
	close(winners)

	won := 0
	for ok := range winners {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d of %d racing registrations won, want exactly 1 — the cap is one slot and it was the only one free", won, burst)
	}
	if len(s.boxes) != MaxSandboxes {
		t.Errorf("the fleet holds %d boxes after the burst, want the cap", len(s.boxes))
	}
}

// The adversarial review of this fix caught the first version refusing the
// request and walking away: a booted loser that never enters s.boxes is
// unreachable by GET, DELETE and Close — an orphaned VMM the cap never
// counts. The teardown call is structural, so the structural check is what
// pins it (the same shape TestEveryToolCallPassesTheAudit uses), because
// driving a real booted loser needs KVM.
func TestA9_TheLoserIsTornDownNotAbandoned(t *testing.T) {
	src, err := os.ReadFile("shim.go")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(src), "if !s.register(b) {")
	if i < 0 {
		t.Fatal("the register-failure branch is gone; this test needs rewriting with it")
	}
	body := string(src)[i:]
	if end := strings.Index(body, "\n\t}\n"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, `b.close("over_limit")`) {
		t.Error("a lost race no longer tears down the booted loser — it would orphan a " +
			"VMM nothing can reach, outside the cap")
	}
}
