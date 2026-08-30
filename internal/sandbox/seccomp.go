package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/denial"
)

// The host-side syscall filter (P5-2, docs/hardening.md §3).
//
// Firecracker compiles its own seccomp filter into the release binary and
// installs it with no flag from us. KelyfOS therefore gets that protection for
// free — and for six releases got it without ever looking, which is the same as
// hoping for it. This file is the looking.
//
// What is checked is not "did we pass --no-seccomp" (we never do; the test in
// jail_test.go is what keeps that true) but what the kernel says about the
// process that is running: every thread of the VMM, in filter mode. A binary
// built for a target Firecracker has no filter file for, or built in debug,
// ships an empty filter and installs nothing at all — so this is a real
// condition a real machine can be in, and it is refused rather than run.
//
// The read happens after the guest is ready, for two reasons. The filters go on
// at three different moments during Firecracker's startup — each vcpu thread
// before it executes guest code, the API thread before it serves, the main
// thread last of all — so a machine that is answering has installed all of
// them. And it keeps the check off the boot path the bars are measured on: by
// the time this runs, boot-to-ready has already been recorded.

// seccompModeFilter is SECCOMP_MODE_FILTER as /proc/<pid>/status reports it:
// 0 disabled, 1 strict, 2 filter (proc_pid_status(5)).
const seccompModeFilter = 2

// seccompDeadline bounds the wait for the filters to appear. At the point this
// runs they are already on, so the loop normally reads once; the deadline is
// for the case where that assumption is wrong, and it fails closed.
const seccompDeadline = 3 * time.Second

// threadFilter is what one task of the VMM reports about itself.
type threadFilter struct {
	tid  int
	comm string
	mode int
}

// confirmSeccomp refuses a machine whose VMM is not running under a syscall
// filter, and records the observation when it is.
//
// Called from WaitReady and from Restore rather than from each of the eight
// commands that start a microVM — the same reason requireJail lives in New and
// Restore. A check half the entry points make is a check nobody can reason
// about.
func (s *Sandbox) confirmSeccomp() error {
	if s.State.PID == 0 {
		return denial.SeccompNotInForce.Err(denial.V{
			"detail": "the VMM's pid is not known, so its filter cannot be read",
		})
	}
	deadline := time.Now().Add(seccompDeadline)
	var last string
	for {
		threads, err := vmmThreads(s.State.PID)
		if err == nil {
			unfiltered := 0
			for _, t := range threads {
				if t.mode != seccompModeFilter {
					unfiltered++
				}
			}
			if len(threads) > 0 && unfiltered == 0 {
				s.State.Seccomp = "filter"
				s.State.SeccompThreads = len(threads)
				return s.writeState()
			}
			last = describeThreads(threads)
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return denial.SeccompNotInForce.Err(denial.V{"detail": last})
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// vmmThreads reads the seccomp mode of every thread of a process.
//
// Per thread, not per process: Firecracker installs its filters without
// SECCOMP_FILTER_FLAG_TSYNC, so each thread carries its own and one unfiltered
// thread would be a hole a process-level read cannot see.
func vmmThreads(pid int) ([]threadFilter, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, fmt.Errorf("read the VMM's thread list: %w", err)
	}
	var out []threadFilter
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, mode, err := threadSeccomp(tid)
		if err != nil {
			// A thread that exited between the listing and the read is not a
			// finding; it is a thread that is no longer there.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		out = append(out, threadFilter{tid: tid, comm: comm, mode: mode})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].tid < out[j].tid })
	if len(out) == 0 {
		return nil, fmt.Errorf("the VMM has no readable threads")
	}
	return out, nil
}

func threadSeccomp(tid int) (comm string, mode int, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	// Seccomp is absent on a kernel built without CONFIG_SECCOMP, which reads
	// here as mode 0 — which is the truth about that machine, not a parse
	// failure to paper over.
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Seccomp:"):
			fields := strings.Fields(line)
			if len(fields) > 1 {
				mode, _ = strconv.Atoi(fields[1])
			}
		}
	}
	return comm, mode, sc.Err()
}

// describeThreads names the threads that are not filtered, because "seccomp is
// off" is a worse refusal than one that says which thread and what it reported.
func describeThreads(threads []threadFilter) string {
	var bad []string
	for _, t := range threads {
		if t.mode != seccompModeFilter {
			bad = append(bad, fmt.Sprintf("%s (tid %d) reports Seccomp: %d", t.comm, t.tid, t.mode))
		}
	}
	if len(bad) == 0 {
		return "no VMM threads could be read"
	}
	return strings.Join(bad, "; ")
}
