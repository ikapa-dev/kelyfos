package main

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// reaper owns every wait(2) in this process.
//
// PID 1 inherits every orphan on the machine and must reap them, or the process
// table fills with zombies. The obvious implementation — a goroutine calling
// wait4(-1) — is wrong in Go, because os/exec's Cmd.Wait also calls wait4 on
// its own child, and whichever call wins steals the status from the other. The
// symptom is intermittent "waitid: no child processes" on commands that in fact
// ran perfectly.
//
// So there is exactly one waiter: this one. Callers start their children
// through startAndRegister and read the status from a channel instead of
// calling Cmd.Wait, which is why exec.go builds its pipes by hand.
type reaper struct {
	mu      sync.Mutex
	waiters map[int]chan syscall.WaitStatus
}

func newReaper() *reaper {
	return &reaper{waiters: make(map[int]chan syscall.WaitStatus)}
}

// start begins reaping. SIGCHLD is the wake-up, but each wake drains every
// available zombie: signals are not queued, so several children exiting at once
// can produce a single SIGCHLD.
func (r *reaper) start() {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, unix.SIGCHLD)
	go func() {
		for range ch {
			r.drain()
		}
	}()
}

func (r *reaper) drain() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drainLocked()
}

func (r *reaper) drainLocked() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err != nil || pid <= 0 {
			// ECHILD (no children at all) or 0 (none have exited yet).
			return
		}
		r.deliverLocked(pid, ws)
	}
}

// startAndRegister starts a child and registers its waiter atomically with
// respect to reaping.
//
// This has to be one operation, not two. If it were two, a short-lived command
// could exit in the window between fork and registration; the SIGCHLD handler
// would reap it, find no waiter, and drop the status on the floor — and the
// caller would then block forever on a channel nobody will ever write to. That
// failure is invisible under light load and reliable under concurrency, which
// is the worst combination a bug can have. Holding the lock across both closes
// the window, because a concurrent drain cannot run until the waiter exists.
func (r *reaper) startAndRegister(cmd *exec.Cmd) (chan syscall.WaitStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Every process this supervisor starts passes through here, which is why
	// the profile is applied here and not at the three call sites (P5-3).
	confine(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	restoreOOMScore(cmd.Process.Pid)
	c := make(chan syscall.WaitStatus, 1)
	r.waiters[cmd.Process.Pid] = c
	return c, nil
}

func (r *reaper) forget(pid int) {
	r.mu.Lock()
	delete(r.waiters, pid)
	r.mu.Unlock()
}

// deliverLocked hands a status to its waiter. The caller holds r.mu.
func (r *reaper) deliverLocked(pid int, ws syscall.WaitStatus) {
	c, ok := r.waiters[pid]
	if !ok {
		// An orphan the machine handed us. Reaping it was the entire point;
		// there is nobody to tell.
		return
	}
	delete(r.waiters, pid)
	c <- ws
	close(c)
}
