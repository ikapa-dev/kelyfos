package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeChainWithUnknownMember writes a chain in which one line carries a
// top-level member this build's Event struct does not have — what a chain
// written by a newer kelyfos looks like to this one.
//
// The digest is computed over the line as written, with `hash` emptied in
// place, rather than over a re-marshalled struct: that is what digestOfLine
// does for every read, and it is the whole reason a newer chain verifies on an
// older build instead of reporting every event as modified (P6-6, D44). So a
// chain built this way is a legitimate record, not a forgery — Verify agrees
// with it, which is the premise of this finding.
func writeChainWithUnknownMember(t *testing.T, root, id string, events []Event, at int, member string) {
	t.Helper()
	prev := ""
	var buf bytes.Buffer
	for i := range events {
		events[i].Seq = i + 1
		events[i].Prev = prev
		events[i].Hash = ""
		line, err := json.Marshal(events[i])
		if err != nil {
			t.Fatal(err)
		}
		if i == at {
			line = append(line[:len(line)-1], ',')
			line = append(line, member...)
			line = append(line, '}')
		}
		sum := sha256.Sum256(line)
		digest := hex.EncodeToString(sum[:])
		line = bytes.Replace(line, []byte(`"hash":""`), []byte(`"hash":"`+digest+`"`), 1)
		prev = digest
		buf.Write(line)
		buf.WriteByte('\n')
	}
	path := Path(root, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	// The premise: this is a chain that verifies as written.
	if _, _, err := Verify(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("the fixture chain does not verify, so it proves nothing: %v", err)
	}
}

// TestF6_EraseKeepsAFieldThisBuildDoesNotKnow.
//
// Verify recomputes a digest from the raw line precisely so that an older
// build reading a newer chain does not report a legitimate record as modified.
// Erase did not inherit the property: it went Read -> redact -> hash ->
// re-marshal, and Read is json.Unmarshal into Event, which drops every member
// the struct does not carry. The rewritten chain verifies, so nothing anywhere
// says a field was lost — an erasure run on an older build silently deleted
// part of the record it was meant to preserve.
func TestF6_EraseKeepsAFieldThisBuildDoesNotKnow(t *testing.T) {
	root := t.TempDir()
	const unknown = `"quarantined_by":"policy-v2"`
	writeChainWithUnknownMember(t, root, "f6", []Event{
		{Type: TypeCommandOutput, V: Version, TS: "2026-01-01T00:00:00.000Z", Sandbox: "f6",
			Data: "MARKER-guest-output", Bytes: 19},
		{Type: TypeSessionEnd, V: Version, TS: "2026-01-01T00:00:01.000Z", Sandbox: "f6", Reason: "shutdown"},
	}, 0, unknown)

	if _, err := Erase(root, "f6", "GDPR Article 17 request"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	blob := readFile(t, Path(root, "f6"))

	if !bytes.Contains(blob, []byte(unknown)) {
		t.Errorf("Erase dropped a member this build's Event struct does not carry.\n"+
			"An older build erasing a newer chain deletes part of the record, the rewritten chain\n"+
			"verifies, and nothing says so — the exact failure digestOfLine exists to prevent on reads.\n"+
			"chain:\n%s", blob)
	}
	// The erasure still did its job, and the result is still a chain.
	if bytes.Contains(blob, []byte("MARKER-guest-output")) {
		t.Error("the content that was supposed to be redacted survived")
	}
	if _, _, err := Verify(bytes.NewReader(blob)); err != nil {
		t.Fatalf("the rewritten chain does not verify: %v", err)
	}
}

// TestF6_EraseKeepsANestedFieldThisBuildDoesNotKnow is the same question one
// level down, which is where it is most likely to be asked: a newer build
// adding a member to EvError, EvSecret, EvAgent or EvStoreKey does not bump
// the schema version either, because docs/events.md says adding a field is not
// breaking. A rewrite that is lossless only at the top level would drop it.
func TestF6_EraseKeepsANestedFieldThisBuildDoesNotKnow(t *testing.T) {
	root := t.TempDir()
	const unknown = `"agents":[{"name":"planner","sandbox":"aa11bb22","region":"eu-central-1"}]`
	writeChainWithUnknownMember(t, root, "f6n", []Event{
		{Type: TypeTeamTopology, V: Version, TS: "2026-01-01T00:00:00.000Z", Sandbox: "f6n",
			Edges: []string{"planner -> worker"}},
		{Type: TypeCommandOutput, V: Version, TS: "2026-01-01T00:00:01.000Z", Sandbox: "f6n",
			Data: "MARKER-guest-output", Bytes: 19},
		{Type: TypeSessionEnd, V: Version, TS: "2026-01-01T00:00:02.000Z", Sandbox: "f6n", Reason: "shutdown"},
	}, 0, unknown)

	if _, err := Erase(root, "f6n", "GDPR Article 17 request"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	blob := readFile(t, Path(root, "f6n"))
	if !bytes.Contains(blob, []byte(`"region":"eu-central-1"`)) {
		t.Errorf("Erase dropped a member inside an object this build's structs do not carry:\n%s", blob)
	}
	if _, _, err := Verify(bytes.NewReader(blob)); err != nil {
		t.Fatalf("the rewritten chain does not verify: %v", err)
	}
}

// TestF6_EraseRefusesAChainFromANewerBuild is the one-line half of the fix,
// and it is first for a reason: a schema version this build has never seen
// means it cannot know which fields carry content, so it cannot know what to
// redact. Rewriting anyway is guessing at the one operation that must not
// guess. Refusing makes the skew impossible to hit silently rather than
// leaving it to the lossless rewrite to survive.
func TestF6_EraseRefusesAChainFromANewerBuild(t *testing.T) {
	root := t.TempDir()
	writeRawChain(t, root, "f6v", []Event{
		{Type: TypeCommandOutput, V: Version + 1, TS: "2026-01-01T00:00:00.000Z", Sandbox: "f6v",
			Data: "MARKER-guest-output", Bytes: 19},
		{Type: TypeSessionEnd, V: Version, TS: "2026-01-01T00:00:01.000Z", Sandbox: "f6v", Reason: "shutdown"},
	})
	before := readFile(t, Path(root, "f6v"))

	_, err := Erase(root, "f6v", "GDPR Article 17 request")
	if err == nil {
		t.Fatal("Erase rewrote a chain written by a newer kelyfos than this one")
	}
	if !strings.Contains(err.Error(), "newer kelyfos") {
		t.Errorf("Erase refused for the wrong reason: %v", err)
	}
	if after := readFile(t, Path(root, "f6v")); !bytes.Equal(before, after) {
		t.Error("a refused erasure still rewrote the file")
	}
}

// TestF6_TheErasureEventCountsFieldsAsWellAsEvents.
//
// `modified` counts events, and says so in the schema — an event with three
// redactable fields set counts once. That leaves an auditor with no number to
// compare against what a redaction should have touched, which is the check
// that would catch a field quietly falling out of coverage. The second counter
// is what makes that comparison possible.
//
// Read out of the raw line rather than through Event, so this test states the
// question the way a reader of the chain asks it — and so it runs on the
// commit before the field existed.
func TestF6_TheErasureEventCountsFieldsAsWellAsEvents(t *testing.T) {
	root := t.TempDir()
	writeRawChain(t, root, "f6c", []Event{
		// Two redactable fields on one event: cmd and cwd.
		{Type: TypeCommandStart, V: Version, TS: "2026-01-01T00:00:00.000Z", Sandbox: "f6c",
			Call: "c1", Cmd: []string{"curl", "https://api.example.com/"}, Cwd: "/work/jane"},
		// One on the next.
		{Type: TypeCommandOutput, V: Version, TS: "2026-01-01T00:00:01.000Z", Sandbox: "f6c",
			Data: "MARKER-guest-output", Bytes: 19},
		{Type: TypeSessionEnd, V: Version, TS: "2026-01-01T00:00:02.000Z", Sandbox: "f6c", Reason: "shutdown"},
	})

	events, err := Erase(root, "f6c", "GDPR Article 17 request")
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if events != 2 {
		t.Fatalf("Erase reported %d events redacted, want 2", events)
	}

	blob := readFile(t, Path(root, "f6c"))
	lines := strings.Split(strings.TrimSpace(string(blob)), "\n")
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatal(err)
	}
	if string(m["type"]) != `"`+TypeSessionErasure+`"` {
		t.Fatalf("the last line is not the erasure event: %s", lines[len(lines)-1])
	}
	if got := string(m["modified"]); got != "2" {
		t.Errorf("modified = %s, want 2 — the count of events touched", got)
	}
	got, ok := m["redacted_fields"]
	if !ok {
		t.Fatalf("the erasure event counts events and not fields, so there is no number an auditor "+
			"can compare against what a redaction should have touched:\n%s", lines[len(lines)-1])
	}
	if string(got) != "3" {
		t.Errorf("redacted_fields = %s, want 3 (cmd and cwd on one event, data on another)", string(got))
	}
}

// TestF6_EraseLeavesEveryUntouchedMemberByteForByte. The rewrite now works on
// the line rather than on a re-marshalled struct, so the members it does not
// redact must come out exactly as they went in — including ones a struct
// round-trip would have normalised away, such as a field written as an
// explicit zero that `omitempty` would drop.
func TestF6_EraseLeavesEveryUntouchedMemberByteForByte(t *testing.T) {
	root := t.TempDir()
	writeChainWithUnknownMember(t, root, "f6b", []Event{
		{Type: TypeCommandOutput, V: Version, TS: "2026-01-01T00:00:00.000Z", Sandbox: "f6b",
			Data: "MARKER-guest-output"},
		{Type: TypeSessionEnd, V: Version, TS: "2026-01-01T00:00:01.000Z", Sandbox: "f6b", Reason: "shutdown"},
	}, 0, `"bytes":0`)

	if _, err := Erase(root, "f6b", "GDPR Article 17 request"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	blob := readFile(t, Path(root, "f6b"))
	if !bytes.Contains(blob, []byte(`"bytes":0`)) {
		t.Errorf("an explicit zero the writer chose to record was dropped by the rewrite:\n%s", blob)
	}
	if _, _, err := Verify(bytes.NewReader(blob)); err != nil {
		t.Fatalf("the rewritten chain does not verify: %v", err)
	}
}

// The rewritten chain has to be readable by the thing that reads chains, not
// only by Verify: a line assembled member by member is a line nobody has
// parsed as an Event since it was built.
func TestF6_TheRewrittenChainStillReadsAsEvents(t *testing.T) {
	root := t.TempDir()
	argv, data, args, cmd := buildErasableChain(t, root, "f6r")
	if _, err := Erase(root, "f6r", "GDPR Article 17 request"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	blob := readFile(t, Path(root, "f6r"))
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("read back %d events, want 6", len(events))
	}
	for _, want := range []string{argv, data, args, cmd} {
		if strings.Contains(string(blob), want) {
			t.Errorf("erased content survived: %q", want)
		}
	}
	for i, e := range events {
		if e.Seq != i+1 {
			t.Errorf("event %d carries seq %d", i+1, e.Seq)
		}
		if e.V != Version || e.TS == "" || e.Sandbox != "f6r" {
			t.Errorf("event %d lost part of its common header: %+v", e.Seq, e)
		}
	}
	if _, _, err := Verify(bytes.NewReader(blob)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

}

// TestF6_EraseRefusesAMemberThatDiffersOnlyInCase is FuzzEraseRoundTrip's
// first find, kept as a named test so the finding is legible without reading a
// corpus file. The fuzzer's own minimised input is committed beside it, in
// testdata/fuzz/FuzzEraseRoundTrip/.
//
// encoding/json matches a member to a field by exact tag first and
// case-insensitively second. So a line carrying "Cmd" decodes into Cmd,
// redactEventFields replaces its content, and the fingerprint was written back
// under the canonical "cmd" — appending a member and leaving "Cmd", content
// intact, in the line beside its own fingerprint. Erase reported the event
// redacted. The content was still in the file.
func TestF6_EraseRefusesAMemberThatDiffersOnlyInCase(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members string
	}{
		// The fuzzer's own case: only the folded spelling is present.
		{"folded spelling alone", `"Cmd":["MARKER-guest-content"]`},
		// And from the other side: the exact member is what decodes, so a
		// redaction never reaches the folded one at all.
		{"both spellings", `"cmd":["ordinary"],"CMD":["MARKER-guest-content"]`},
		// One level down, inside *EvError.
		{"nested", `"error":{"kind":"tool","Message":"MARKER-guest-content"}`},
		// And inside an element of a struct slice.
		{"nested in a slice", `"store_keys":[{"Name":"MARKER-guest-content"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeChainWithUnknownMember(t, root, "f6case", []Event{
				{Type: TypeCommandStart, V: Version, TS: "2026-01-01T00:00:00.000Z", Sandbox: "f6case"},
				{Type: TypeCommandOutput, V: Version, TS: "2026-01-01T00:00:01.000Z", Sandbox: "f6case",
					Data: "something else that is redactable"},
				{Type: TypeSessionEnd, V: Version, TS: "2026-01-01T00:00:02.000Z", Sandbox: "f6case", Reason: "shutdown"},
			}, 0, tc.members)
			before := readFile(t, Path(root, "f6case"))

			_, err := Erase(root, "f6case", "GDPR Article 17 request")
			if err == nil {
				after := readFile(t, Path(root, "f6case"))
				if bytes.Contains(after, []byte("MARKER-guest-content")) {
					t.Fatalf("Erase reported success and left the content in the file:\n%s", after)
				}
				t.Fatalf("Erase accepted a line whose member name only folds to a field name:\n%s", after)
			}
			if !strings.Contains(err.Error(), "only in case") {
				t.Errorf("Erase refused for the wrong reason: %v", err)
			}
			if after := readFile(t, Path(root, "f6case")); !bytes.Equal(before, after) {
				t.Error("a refused erasure still rewrote the file")
			}
		})
	}
}
