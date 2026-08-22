package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The idle watchdog is the one piece of E1-6 with logic worth testing away from
// a VM: it decides "nothing is happening" from two host-side signals, and
// getting either wrong ends a working sandbox.
func TestIdleBudgetFiresOnlyWhenNothingHappens(t *testing.T) {
	log := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(log, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fired := make(chan timeoutFired, 1)
	stop := make(chan struct{})
	defer close(stop)

	go watchBudgets(budgets{
		idle: 3 * time.Second, started: time.Now(),
		eventLog: log, fired: fired, stop: stop,
	})

	// Keep the log growing for longer than the budget: a busy sandbox must not
	// be torn down, however long it stays busy.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("{}\n")
		f.Close()
		select {
		case ev := <-fired:
			t.Fatalf("the idle budget fired while the log was still growing: %+v", ev)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Then stop touching it. Now it must fire, and name the right budget.
	select {
	case ev := <-fired:
		if ev.budget != "idle_timeout" {
			t.Errorf("budget = %q, want idle_timeout", ev.budget)
		}
		if ev.elapsed < 3*time.Second {
			t.Errorf("fired after %s, before the 3s budget was up", ev.elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the idle budget never fired after the log went quiet")
	}
}

// max_runtime is wall-clock from the start and owes nothing to activity.
func TestMaxRuntimeFiresRegardlessOfActivity(t *testing.T) {
	log := filepath.Join(t.TempDir(), "events.jsonl")
	fired := make(chan timeoutFired, 1)
	stop := make(chan struct{})
	defer close(stop)

	started := time.Now()
	go watchBudgets(budgets{
		max: 2 * time.Second, idle: time.Hour, started: started,
		eventLog: log, fired: fired, stop: stop,
	})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
				if err == nil {
					_, _ = f.WriteString("{}\n")
					f.Close()
				}
			}
		}
	}()

	select {
	case ev := <-fired:
		if ev.budget != "max_runtime" {
			t.Errorf("budget = %q, want max_runtime", ev.budget)
		}
		if d := time.Since(started); d < 2*time.Second {
			t.Errorf("fired after %s, before the 2s budget was up", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("max_runtime never fired")
	}
}

// No budgets means no watchdog behaviour at all: a sandbox with neither key set
// must be able to sit idle indefinitely, which is the v0.3 behaviour.
func TestNoBudgetsNeverFires(t *testing.T) {
	fired := make(chan timeoutFired, 1)
	stop := make(chan struct{})
	defer close(stop)
	go watchBudgets(budgets{started: time.Now(), eventLog: "/nonexistent", fired: fired, stop: stop})
	select {
	case ev := <-fired:
		t.Fatalf("a sandbox with no budgets was timed out: %+v", ev)
	case <-time.After(3 * time.Second):
	}
}
