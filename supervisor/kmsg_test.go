package main

import "testing"

// The line this parser exists for, copied verbatim from a real KelyfOS guest
// (aarch64, 6.18.45, --mem 256M) rather than written from the format string.
const realOOMLine = "Out of memory: Killed process 57 (python3) total-vm:237980kB, " +
	"anon-rss:230016kB, file-rss:88kB, shmem-rss:0kB, UID:0 pgtables:500kB oom_score_adj:0"

func TestParsesARealOOMLine(t *testing.T) {
	ev, ok := parseOOM(realOOMLine)
	if !ok {
		t.Fatal("did not recognise the kernel's own OOM line")
	}
	if ev.PID != 57 {
		t.Errorf("pid = %d, want 57", ev.PID)
	}
	if ev.Comm != "python3" {
		t.Errorf("comm = %q, want python3", ev.Comm)
	}
	// anon-rss, not total-vm: address space a process reserved and never
	// touched says nothing about the memory that ran out.
	if ev.RSSKiB != 230016 {
		t.Errorf("rss = %d KiB, want 230016", ev.RSSKiB)
	}
	if ev.Type != "resource.oom" {
		t.Errorf("type = %q", ev.Type)
	}
}

// The kernel prefixes the same line with a different message for an allocating
// task, and a process name may contain almost anything.
func TestParsesTheOtherOOMShapes(t *testing.T) {
	cases := map[string]struct {
		pid  int
		comm string
	}{
		"Out of memory (oom_kill_allocating_task): Killed process 9 (a b) total-vm:1kB, anon-rss:2kB,": {9, "a b"},
		"Memory cgroup out of memory: Killed process 1234 (node) total-vm:99kB, anon-rss:44kB,":        {1234, "node"},
	}
	for line, want := range cases {
		ev, ok := parseOOM(line)
		if !ok {
			t.Errorf("not recognised: %s", line)
			continue
		}
		if ev.PID != want.pid || ev.Comm != want.comm {
			t.Errorf("%s -> pid %d comm %q, want %d %q", line, ev.PID, ev.Comm, want.pid, want.comm)
		}
	}
}

// A loose "killed" match would report unrelated kills as memory exhaustion,
// which is a worse failure than missing one: it would send a user tuning --mem
// after a problem that has nothing to do with memory.
func TestIgnoresLinesThatAreNotOOMKills(t *testing.T) {
	for _, line := range []string{
		"systemd-shutdown[1]: Killed process 42 (dontcare)",
		"python3 invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0",
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),task=python3,pid=57,uid=0",
		"Out of memory and no killable processes...",
		"",
	} {
		if ev, ok := parseOOM(line); ok {
			t.Errorf("reported an OOM kill for %q: %+v", line, ev)
		}
	}
}

func TestStripsTheKmsgRecordHeader(t *testing.T) {
	msg, ok := kmsgMessage("3,246,4941890,-;" + realOOMLine)
	if !ok {
		t.Fatal("header not recognised")
	}
	if msg != realOOMLine {
		t.Errorf("message = %q", msg)
	}
	// Continuation lines carry structured key/value data, never the message.
	if _, ok := kmsgMessage(" SUBSYSTEM=acpi"); ok {
		t.Error("a continuation line was treated as a message")
	}
	// A record with no separator is not a record.
	if _, ok := kmsgMessage("garbage"); ok {
		t.Error("a line with no ';' was treated as a record")
	}
}

// End to end through both halves: what /dev/kmsg actually delivers, in the
// shape it delivers it, becomes the event the host records.
func TestARecordBecomesAnEvent(t *testing.T) {
	msg, ok := kmsgMessage("3,246,4941890,-;" + realOOMLine)
	if !ok {
		t.Fatal("header not recognised")
	}
	ev, ok := parseOOM(msg)
	if !ok || ev.PID != 57 || ev.Comm != "python3" {
		t.Fatalf("record did not become the expected event: %+v (ok=%v)", ev, ok)
	}
}
