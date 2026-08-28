package recorder

import (
	"encoding/json"
	"fmt"
	"reflect"
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
		BlockedPackets: 1, // see the reflection assertion below
		Args:           "a",
		Tool:           "t",
		Added:          1, Modified: 1, Deleted: 1,
		Jailed:    &yes,
		GuestPort: 1,
		Profile:   "p",
		DiskBytes: 1, ScratchBytes: 1,
		NetMbpsRx: 1, NetMbpsTx: 1, DiskIOPS: 1, DiskMbps: 1,
		MaxRuntimeMS: 1, IdleTimeoutMS: 1,
		Allow: []string{"a"}, Ports: []int{1},
		Secrets:        []EvSecret{{Name: "n", Host: "h", Path: "p"}},
		Workspace:      "w",
		Plugins:        []string{"p"},
		Forwards:       []string{"f"},
		RootfsSHA256:   "r",
		KernelSHA256:   "k",
		Tools:          []string{"t"},
		ParentSession:  "s",
		Traceparent:    "t",
		Agents:         []EvAgent{{Name: "n", Sandbox: "s", Group: "g"}},
		Edges:          []string{"e"},
		StoreKeys:      []EvStoreKey{{Name: "n", Read: []string{"r"}, Write: []string{"w"}}},
		RecordPayloads: &yes,
		RedactedFields: 1,
	}

	// The fixture above must set every field on Event, not only the ones
	// `want` below already lists by name — otherwise a field inserted into
	// an omitempty-empty slot (rather than appended after the last one)
	// would marshal to nothing here and this test would never notice the
	// insertion, only ever compare the fields it was already told to expect.
	// The P7-2 review flagged exactly this landmine as something for P7-3 to
	// close ("insertion into an omitempty-empty slot is not caught") — and
	// this assertion, on its first real run, immediately found a second,
	// unrelated gap: BlockedPackets (F14/S15) was appended to Event after
	// this test was written and neither the fixture above nor `want` below
	// had ever gained it, so its position was never actually verified. Fixed
	// in the same commit rather than left for a sixth person to trip over.
	ev := reflect.ValueOf(e)
	for i := 0; i < ev.NumField(); i++ {
		if ev.Field(i).IsZero() {
			t.Fatalf("this test's fixture leaves Event.%s at its zero value — every field must be set "+
				"to something non-empty, or a field inserted into this now-empty slot (rather than "+
				"appended after the last one) could pass this test unnoticed", ev.Type().Field(i).Name)
		}
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
		"blocked_packets",
		"args",
		"tool",
		"added", "modified", "deleted",
		"jailed",
		"guest_port",
		"profile",
		// session.policy (P7-2, docs/policy-record.md §5) — positions 1-19,
		// normative per §9.2.
		"disk_bytes", "scratch_bytes",
		"net_mbps_rx", "net_mbps_tx", "disk_iops", "disk_mbps",
		"max_runtime_ms", "idle_timeout_ms",
		"allow", "ports", "secrets",
		"workspace", "plugins", "forwards",
		"rootfs_sha256", "kernel_sha256",
		"tools", "parent_session", "traceparent",
		// team.topology (P7-3, docs/policy-record.md §6) — positions 20-23,
		// normative per §9.2. cpu_quota_percent (already listed above) is
		// reused rather than repeated here.
		"agents", "edges", "store_keys", "record_payloads",
		// session.erasure's second counter (P7-17, F6) — appended after
		// everything above, which is what makes it safe.
		"redacted_fields",
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

	// The check above only ever looked at Event's own top-level keys:
	// keysInOrder decodes each value as an opaque json.RawMessage and
	// discards it, so an object-valued field (error) or an object-array
	// field (secrets, agents, store_keys) had its own internal key order
	// checked by nothing here. The review that reopened P7-3 (F3) proved
	// the gap: swapping EvAgent.Name and EvAgent.Sandbox left this whole
	// test green, even though it changes the hash digest of every
	// team.topology event ever written — the identical "field appended and
	// never inserted" question this test already asks at the top level,
	// one type down. Pre-existing for EvError/EvSecret since P6-14/P7-2;
	// P7-3 doubled the exposed surface by adding EvAgent and EvStoreKey,
	// which is what surfaced it.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	for key, nestedWant := range nestedFieldOrder {
		raw, ok := top[key]
		if !ok {
			t.Fatalf("the fixture's %q is absent from the marshalled event — this check needs it set", key)
		}
		if key == "error" {
			checkNestedOrder(t, key, raw, nestedWant)
			continue
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if len(elems) == 0 {
			t.Fatalf("the fixture's %q is an empty array — this check needs at least one element", key)
		}
		for i, el := range elems {
			checkNestedOrder(t, fmt.Sprintf("%s[%d]", key, i), el, nestedWant)
		}
	}
}

// nestedFieldOrder pins the key order EvError, EvSecret, EvAgent and
// EvStoreKey each marshal in. Each list is literal, deliberately not
// derived from reflect.TypeOf(EvAgent{}) or similar, for the same reason
// `want` above is literal: a reflection-derived expectation reorders itself
// in lockstep with a reordered struct and could never catch the reordering
// it exists to catch — it would still "expect" whatever order the same
// reordered struct actually produces.
var nestedFieldOrder = map[string][]string{
	"error":      {"kind", "message"},
	"secrets":    {"name", "host", "path"},
	"agents":     {"name", "sandbox", "group"},
	"store_keys": {"name", "read", "write"},
}

// checkNestedOrder asserts one JSON object's own key order matches want —
// keysInOrder is generic over any JSON object, not only Event's own top
// level, so this is the identical comparison TestTheEventFieldOrderIsFrozen
// makes above, applied one level down.
func checkNestedOrder(t *testing.T, path string, raw json.RawMessage, want []string) {
	t.Helper()
	got := keysInOrder(t, string(raw))
	if len(got) != len(want) {
		t.Fatalf("%s has %d fields and this test knows %d.\n  got:  %v\n  want: %v",
			path, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s's field order changed at position %d: %q where %q was expected — every\n"+
				"  digest computed over an event carrying this object just changed.\n"+
				"  got:  %v\n  want: %v", path, i, got[i], want[i], got, want)
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
