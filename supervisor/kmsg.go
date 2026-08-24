package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"golang.org/x/sys/unix"
)

// The OOM killer's own words, from mm/oom_kill.c in the kernel this image is
// built against (6.18.x):
//
//	pr_err("%s: Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, ...")
//
// where %s is "Out of memory" or "Out of memory (oom_kill_allocating_task)".
// Matching the kernel's format string rather than a loose "killed" keyword is
// deliberate: this line is the only place the guest learns *which* process died,
// and a looser pattern would report unrelated kills as memory exhaustion.
//
// anon-rss is the number worth reporting. total-vm counts address space the
// process never touched, which for a runtime that reserves generously says
// nothing about the memory that ran out.
var oomLine = regexp.MustCompile(
	`Killed process (\d+) \((.*?)\) total-vm:\d+kB, anon-rss:(\d+)kB`)

// parseOOM extracts one resource.oom report from a kernel log line, or reports
// that the line was not one.
func parseOOM(line string) (proto.GuestEvent, bool) {
	m := oomLine.FindStringSubmatch(line)
	if m == nil {
		return proto.GuestEvent{}, false
	}
	pid, err := strconv.Atoi(m[1])
	if err != nil {
		return proto.GuestEvent{}, false
	}
	rss, err := strconv.ParseInt(m[3], 10, 64)
	if err != nil {
		return proto.GuestEvent{}, false
	}
	// The process name is the one field here the agent chooses: `comm` is
	// whatever it called the binary. It travels to the host, into the record,
	// and out again through every renderer, so a control character in it is a
	// line of transcript the agent gets to shape. Quoted rather than stripped,
	// so an odd name is still recognisable as itself. Found by FuzzParseOOM
	// (P6-3), which is the third place this class turned up in one task.
	return proto.GuestEvent{
		V:      proto.Version,
		Type:   proto.GuestEventOOM,
		PID:    pid,
		Comm:   safeArgLine(m[2]),
		RSSKiB: rss,
	}, true
}

// kmsgMessage strips the record header /dev/kmsg puts in front of every line:
//
//	<priority>,<sequence>,<timestamp_usec>,<flags>[,<key=value>...];<message>
//
// Continuation lines begin with a space and carry structured key/value data,
// never the message itself, so they are dropped rather than parsed.
func kmsgMessage(record string) (string, bool) {
	if strings.HasPrefix(record, " ") {
		return "", false
	}
	_, msg, ok := strings.Cut(record, ";")
	if !ok {
		return "", false
	}
	// Only the first line of a multi-line record is the message.
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return msg, true
}

// watchKmsg reports guest OOM kills as they happen.
//
// Reading /dev/kmsg rather than parsing dmesg output, because this has to see
// the kill at the moment it happens on a machine that is by definition out of
// memory: a read on this device blocks until the next record and allocates
// nothing per record beyond the line buffer. The file position is moved to the
// end first, so a sandbox does not open its session by reporting boot messages.
//
// This is visibility, not enforcement. The RAM cap is the VM's hardware and the
// guest cannot exceed it whatever this function does; all that is at stake here
// is whether hitting it is legible afterwards (E1-4, and F-D2 on why nothing in
// the guest is trusted to police anything).
func watchKmsg(send func(proto.GuestEvent)) {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		logf("cannot watch /dev/kmsg for OOM kills: %v", err)
		return
	}
	defer f.Close()
	// SEEK_END on this device means "the next record written", not "the last
	// record in the buffer" — exactly the semantics wanted.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		logf("cannot seek /dev/kmsg: %v", err)
		return
	}

	r := bufio.NewReaderSize(f, 8<<10)
	for {
		record, err := r.ReadString('\n')
		if err != nil {
			// EPIPE means this reader fell behind and the kernel overwrote
			// records it had not read. The position has already been moved to
			// the oldest surviving record, so the right response is to carry on
			// rather than to give up on the rest of the session.
			if errors.Is(err, unix.EPIPE) {
				continue
			}
			if len(record) == 0 {
				logf("stopped watching /dev/kmsg: %v", err)
				return
			}
		}
		msg, ok := kmsgMessage(strings.TrimRight(record, "\n"))
		if !ok {
			continue
		}
		if ev, ok := parseOOM(msg); ok {
			ev.MonotonicNS = monotonic().Nanoseconds()
			send(ev)
		}
	}
}
