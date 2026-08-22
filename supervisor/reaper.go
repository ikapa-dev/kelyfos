package main

import (
	"os"
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
// So there is exactly one waiter: this one. Callers that start a child register
// its pid and read the status from a channel instead of calling Cmd.Wait, which
// is why exec.go builds its pipes by hand.
type reaper struct {
	mu      sync.Mutex
	waiters map[int]chan syscall.WaitStatus
}

func newReaper() *reaper {
	return &reaper{waiters: make(map[int]chan syscall.WaitStatus)}
}

// start begins reaping. SIGCHLD is the wake-up, but the loop drains every
// available zombie on each wake: signals are not queued, so several children
// exiting at once can produce a single SIGCHLD.
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
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err != nil || pid <= 0 {
			// ECHILD (no children at all) or 0 (none exited yet).
			return
		}
		r.deliver(pid, ws)
	}
}

// register must be called before the child can exit, so the status has
// somewhere to go. Callers hold the returned channel and read exactly once.
func (r *reaper) register(pid int) chan syscall.WaitStatus {
	c := make(chan syscall.WaitStatus, 1)
	r.mu.Lock()
	r.waiters[pid] = c
	r.mu.Unlock()
	// A child can exit between fork and register; drain again so its status is
	// not stranded in a zombie nobody is listening for.
	go r.drain()
	return c
}

func (r *reaper) forget(pid int) {
	r.mu.Lock()
	delete(r.waiters, pid)
	r.mu.Unlock()
}

func (r *reaper) deliver(pid int, ws syscall.WaitStatus) {
	r.mu.Lock()
	c, ok := r.waiters[pid]
	if ok {
		delete(r.waiters, pid)
	}
	r.mu.Unlock()
	if ok {
		c <- ws
		close(c)
	}
	// An unregistered pid is an orphan the machine handed us. Reaping it was
	// the entire point; there is nobody to tell.
}
