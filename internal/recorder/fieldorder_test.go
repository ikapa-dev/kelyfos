package recorder

import (
	"encoding/json"
	"strings"
	"testing"
)

// The order of Event's fields is frozen ABI, and this is what freezes it
// (P6-14).
//
// An event's digest is computed over the struct marshalled in declaration
// order, so **reordering these fields changes every digest KelyfOS has ever
// written**. Not the format, not the version — every chain, retroactively
// unverifiable. docs/events.md §3 has always said the order is the contract and
// pointed a reader at this struct; nothing checked that the struct still
// matched, and a field moved for tidiness would have been caught by no test in
// the tree.
//
// So the order is written down here, once, as the thing it is: an interface
// somebody else's implementation depends on. A change to this list is a change
// to the record format and needs the version bump docs/events.md describes —
// which is exactly the conversation this test exists to force.
//
// Adding a field at the **end** is safe and stays safe: it appears after
// everything here, and P6-6's digest-from-the-bytes fix is what makes an older
// reader tolerate one it does not know.
func TestTheEventFieldOrderIsFrozen(t *testing.T) {
	// Every field set to something non-empty, so `omitempty` hides none of them
	// and the marshalled order is the declared order in full.
	code, yes := 1, true
	e := Event{
		V: 1, Seq: 1, TS: "t", Sandbox: "s", Type: "x", Source: "host", Prev: "p", Hash: "h",
		Image: "i", Arch: "a", Kelyfos: "k", Argv: []string{"v"},
		BootMS: 1, Kernel: "k", Supervisor: "s", Overlay: &yes,
		Reason: "r", DurationMS: 1,
		Call: "c", Cmd: []string{"c"}, Cwd: "w", Via: "v", Stream: "s", Data: "d", Bytes: 1,
		Code: &code, Signal: "s", Error: &EvError{Kind: "k", Message: "m"},
		Path: "p", SHA256: "s",
		Host: "h", Port: 1, Allowed: &yes, Mode: "m", BytesIn: 1, BytesOut: 1,
		Name: "n",
		PID:  1, Comm: "c", RSSKiB: 1, MemMiB: 1,
		Budget: "b", BudgetMS: 1, ElapsedMS: 1,
		Agent: "a", Peer: "p", Kind: "k", Outcome: "o",
		CPUSeconds: 1, PeakRSSKiB: 1, NetInBytes: 1, NetOutBytes: 1,
		DiskReadBytes: 1, DiskWriteBytes: 1, VcpuCount: 1, CPUQuota: 1,
		Args:  "a",
		Tool:  "t",
		Added: 1, Modified: 1, Deleted: 1,
		Jailed:    &yes,
		GuestPort: 1,
		Profile:   "p",
	}
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		// The eight common fields docs/events.md §3 pins by name.
		"v", "seq", "ts", "sandbox", "type", "source", "prev", "hash",
		// Then the type-specific fields, in struct order.
		"image", "arch", "kelyfos", "argv",
		"boot_ms", "kernel", "supervisor", "overlay",
		"reason", "duration_ms",
		"call", "cmd", "cwd", "via", "stream", "data", "bytes", "code", "signal", "error",
		"path", "sha256",
		"host", "port", "allowed", "mode", "bytes_in", "bytes_out",
		"name",
		"pid", "comm", "rss_kib", "mem_mib",
		"budget", "budget_ms", "elapsed_ms",
		"agent", "peer", "kind", "outcome",
		"cpu_seconds", "peak_rss_kib", "net_in_bytes", "net_out_bytes",
		"disk_read_bytes", "disk_write_bytes", "vcpu_count", "cpu_quota_percent",
		"args",
		"tool",
		"added", "modified", "deleted",
		"jailed",
		"guest_port",
		"profile",
	}

	got := keysInOrder(t, string(body))
	if len(got) != len(want) {
		t.Errorf("the record has %d fields and this test knows %d.\n"+
			"  A field was added or removed. If it was ADDED AT THE END, add it to the end of\n"+
			"  `want` here and nothing else changes: an older reader tolerates a field it does\n"+
			"  not know (P6-6). If it was added anywhere ELSE, or removed, every digest KelyfOS\n"+
			"  has ever written just changed and no existing chain verifies.\n"+
			"  got:  %v\n  want: %v", len(got), len(want), got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the record's field order changed at position %d: %q where %q was expected.\n"+
				"  Every digest KelyfOS has ever written is computed over this order. Moving a field\n"+
				"  makes every existing chain report as modified — which is tamper detection firing\n"+
				"  on legitimate records, the loudest wrong answer this product can give.\n"+
				"  got:  %v\n  want: %v", i, got[i], want[i], got, want)
		}
	}
}

// keysInOrder reads the top-level keys of a JSON object in the order they were
// written, which json.Unmarshal into a map would throw away.
func keysInOrder(t *testing.T, body string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	if _, err := dec.Token(); err != nil { // the opening brace
		t.Fatal(err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("expected a key, got %v", tok)
		}
		keys = append(keys, key)
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}
