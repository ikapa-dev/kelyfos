package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fuzz targets for the guest supervisor (P6-3).
//
// These run inside the guest, which is the untrusted side — so at first glance
// they are not on a trust boundary at all. They are, and the route is worth
// stating because it is the kind that gets missed: everything here produces
// something the *host* then writes into the flight recorder. The agent chooses
// what a process is called and what a plugin's arguments are, so the agent
// chooses part of the input to these functions, and the output is a line in the
// record that a person reads and believes.

// FuzzParseOOM drives the kernel-log line that becomes a resource.oom event.
//
// The agent controls the process name: `comm` in an OOM line is whatever the
// agent named its binary. That makes a kernel log line a place where agent-
// chosen text enters the audit record.
func FuzzParseOOM(f *testing.F) {
	f.Add("Out of memory: Killed process 412 (python3) total-vm:2097152kB, anon-rss:1048576kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:2048kB oom_score_adj:0")
	f.Add("Out of memory: Killed process 1 (init) total-vm:0kB, anon-rss:0kB")
	f.Add("Out of memory: Killed process 99999999999999999999 (x) anon-rss:1kB")
	f.Add("Out of memory: Killed process 5 (a\nb) anon-rss:1kB")
	f.Add("Memory cgroup out of memory: Killed process 7 (node) anon-rss:512kB")
	f.Add("")

	f.Fuzz(func(t *testing.T, line string) {
		ev, ok := parseOOM(line)
		if !ok {
			return
		}
		// A recognised OOM must produce a usable event. A negative pid or a
		// negative resident size would be recorded and rendered as fact.
		if ev.PID < 0 {
			t.Fatalf("parsed pid %d from %q", ev.PID, line)
		}
		if ev.RSSKiB < 0 {
			t.Fatalf("parsed rss %d KiB from %q", ev.RSSKiB, line)
		}
		if strings.ContainsAny(ev.Comm, "\n\r") {
			t.Fatalf("parsed a process name containing a line break from %q: %q", line, ev.Comm)
		}
	})
}

// FuzzKmsgMessage drives the /dev/kmsg record split. The guest kernel writes
// these, but what they contain includes text the agent chose.
func FuzzKmsgMessage(f *testing.F) {
	f.Add("6,339,5150951,-;Out of memory: Killed process 412 (python3)")
	f.Add(" SUBSYSTEM=acpi")
	f.Add("no semicolon here")
	f.Add(";")
	f.Add("")

	f.Fuzz(func(t *testing.T, record string) {
		_, _ = kmsgMessage(record)
	})
}

// FuzzSummarisePluginArgsNeverEchoesContent is the guest-side half of the
// redaction guarantee. A plugin is an MCP server running inside the sandbox and
// its call arguments are summarised into a plugin.call event.
func FuzzSummarisePluginArgsNeverEchoesContent(f *testing.F) {
	f.Add("content", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldA==")
	f.Add("stdin", "the quick brown fox jumps over the lazy dog")
	f.Add("data", "0123456789abcdef0123456789abcdef")

	f.Fuzz(func(t *testing.T, key, payload string) {
		if len(payload) < 16 || !contentKeys[key] {
			t.Skip()
		}
		raw, err := json.Marshal(map[string]any{key: payload, "other": 1})
		if err != nil {
			t.Skip()
		}
		out := summarisePluginArgs(raw)
		if strings.Contains(out, payload) {
			t.Fatalf("summarisePluginArgs wrote a %d-byte %q argument into the record verbatim:\n%s",
				len(payload), key, out)
		}
	})
}

// FuzzSummarisePluginArgs is the ordinary robustness question, and the one that
// found the control-character hole this package shares with the host's copy.
func FuzzSummarisePluginArgs(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"cmd":"ls","content":"abc"}`))
	f.Add([]byte(`{"\n":0}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		out := summarisePluginArgs(json.RawMessage(raw))
		if strings.ContainsAny(out, "\n\r") {
			t.Fatalf("summarisePluginArgs produced a multi-line summary from %q:\n%q", raw, out)
		}
	})
}
