package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Erase rewrites one session's own chain in place: every field known to
// carry guest-influenced or operator-supplied content is replaced with a
// fingerprint of what was there, its own sha256, rather than deleted or
// left alone (P7-5, D61). A new session.erasure event is appended recording
// that this ran, why, how many events it touched, and the chain head
// immediately before this rewrite began (S1) — so the erasure itself is
// part of the record rather than a silent edit, and so it can be
// distinguished from tampering rather than merely trusted by convention.
//
// This is the pattern D61 names file.write as the precedent for: a field
// recorded by digest rather than by content is not a compromise between
// GDPR Article 17 (erasure) and EU AI Act Article 12 (retention) — it is
// what lets both stand at once, because the chain that Article 12 requires
// stay intact and verifiable is a *structural* claim (what happened, when,
// how many events, in what order, which agent) that does not need the
// content Article 17 wants gone.
//
// **Which fields are content.** eraseExempt below is the single, explicit
// answer, and it is checked rather than assumed: TestEraseCoversEveryContentField
// (erase_test.go) walks every string and []string field reachable from
// Event — including *EvError's two and the three struct slices' own fields
// — puts a marker in each one alone, runs Erase, and fails with the
// field's own name if the marker survives a field this map does not name.
// That is the fix for the failure class this project has now hit four
// times in one week: clipLargestField missing Tools, internal/digest
// missing session.policy, internal/digest missing team.topology, and this
// task's own first pass missing Argv (B3) — a hand-maintained list nobody
// remembers to extend, closed the way P6-3 closed it for clipLargestField:
// reflection rather than memory, with the exemptions written down and
// tested rather than left to a reviewer to rediscover.
//
// Every event's Hash covers Prev, and Prev is the previous event's Hash, so
// a content change to one event cascades forward through every later one's
// Hash even when that later event's own content never moved — there is no
// way to redact a field in place and leave the rest of the chain's digests
// unchanged, the same way there is no way to edit one block in the middle
// of any hash chain without recomputing every block after it. So this
// rebuilds Seq, Prev and Hash for the whole chain from scratch rather than
// only from the first touched event onward: simpler, and no less correct,
// since a from-scratch rebuild is what "replacement record" (D61's own
// phrase) means.
//
// Refuses a chain that does not already verify: rewriting a broken chain
// would erase the evidence that it was broken, which is the one thing an
// erasure path must never do. Refuses an empty chain, a chain with nothing
// left to redact — including a chain every redactable field of which is
// already a fingerprint from an earlier erasure (B2) — and a chain that
// carries no session.end anywhere: that is the shape of a session still
// open, or still being written to, and erasing one is racing a writer
// (B1). `hasLiveRunDir` in host/sessions.go catches this for an ordinary
// sandbox whose own id names its run directory, but a team's chain and a
// `kelyfos serve-mcp` process's own audit chain are both opened under an id
// `sandbox.NewID()` mints that is never any sandbox's own id — so no run
// directory is ever named for it, and that guard alone cannot see either
// one is still live. Checking for session.end here, in the one place every
// caller of Erase goes through, closes that gap regardless of which door
// called it.
func Erase(root, sandboxID, reason string) (redacted int, err error) {
	path := Path(root, sandboxID)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	// The same exclusive lock Append takes, held for the whole read-rewrite:
	// a concurrent Append racing this rewrite is the one scenario that could
	// otherwise interleave a write with this one, and flock is what a
	// process actually still writing this session already respects. See
	// Recorder.catchUp (recorder.go) for the other half of what makes this
	// safe for a writer that already has the file open across this call.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return 0, fmt.Errorf("lock flight recorder: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)

	blob, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	_, preHead, err := Verify(bytes.NewReader(blob))
	if err != nil {
		return 0, fmt.Errorf("refusing to erase: chain does not verify: %w", err)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, fmt.Errorf("%s: empty chain, nothing to erase", sandboxID)
	}
	if !hasSessionEnd(events) {
		return 0, fmt.Errorf("%s: this chain has no session.end anywhere in it — it may still be "+
			"open, or a live process may still be writing to it, and erasing it would risk racing "+
			"that writer (a session paused with `kelyfos pause`, or one whose sandbox is still up, "+
			"is refused for the same reason before this is ever reached)", sandboxID)
	}

	// redacted counts events touched, not fields touched: an event with more
	// than one redactable field set still counts once.
	for i := range events {
		if redactEventFields(&events[i]) {
			redacted++
		}
	}
	if redacted == 0 {
		return 0, fmt.Errorf("%s: nothing to erase — no event carries a redactable field, or every "+
			"redactable field is already a fingerprint from an earlier erasure", sandboxID)
	}

	events = append(events, Event{
		Type: TypeSessionErasure, Source: SourceHost, Sandbox: sandboxID,
		Reason: reason, Modified: redacted,
		// SHA256 anchors this event to the exact chain it replaces (S1):
		// the Hash of the last event before this rewrite began, the same
		// value Verify returned above. Anyone holding an earlier export of
		// this chain (kelyfos verify --extract, or a report's own
		// <pre id="kelyfos-chain">) can compare it against this field and
		// confirm the erased chain is the honest successor of exactly the
		// chain they hold — not a fabrication built by rehashing from
		// event 1 with no erasure event at all, which verifies identically
		// to a real one without this anchor.
		SHA256: preHead,
		// Append is bypassed here on purpose — the whole chain is rehashed
		// below, not appended to — so this stamps what Append would have
		// stamped: V and TS. Left at their zero values (B4), a real erased
		// chain carried a session.erasure event with v:0 and ts:"", the
		// one event on the whole chain whose entire purpose is
		// accountability failing the invariant docs/events.md states for
		// every event on the chain.
		V:  Version,
		TS: time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
	})

	prev := ""
	for i := range events {
		events[i].Seq = i + 1
		events[i].Prev = prev
		events[i].Hash = ""
		digest, err := hashOf(events[i])
		if err != nil {
			return redacted, err
		}
		events[i].Hash = digest
		prev = digest
	}

	var buf bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return redacted, err
		}
		if len(line)+1 > MaxLine {
			return redacted, fmt.Errorf("event %d is %d bytes after erasure, over MaxLine — refusing to write a line no reader could read back",
				e.Seq, len(line)+1)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	// Rewritten in place, on the same fd this already holds locked — not via
	// a temp file and rename. A rename replaces the directory entry but
	// leaves any OTHER already-open fd on this file — a Recorder holding
	// this session's chain open across the erase — pointing at the OLD,
	// now-unlinked inode: its next catchUp saw no size change on that fd and
	// returned nil, and whatever it went on to "append" landed on an inode
	// nothing could ever read back. That is B1, reproduced on real, running
	// code: erase a chain a writer still holds open, and the writer's next
	// events vanish with no error anywhere. Writing the new content into the
	// SAME inode under the SAME lock means every fd still pointing at this
	// file sees the new bytes the moment the lock releases, because there is
	// only ever one inode to see. WriteAt happens before Truncate so that a
	// process that dies between the two leaves the new content whole with
	// stale bytes trailing it — a chain Verify can detect as broken — rather
	// than a Truncate that lands first and a crash before the write leaves
	// nothing at all.
	newSize := int64(buf.Len())
	if _, err := f.WriteAt(buf.Bytes(), 0); err != nil {
		return redacted, fmt.Errorf("rewrite the chain: %w", err)
	}
	if err := f.Truncate(newSize); err != nil {
		return redacted, fmt.Errorf("truncate the rewritten chain: %w", err)
	}
	if err := f.Sync(); err != nil {
		return redacted, fmt.Errorf("sync the rewritten chain: %w", err)
	}
	return redacted, nil
}

// hasSessionEnd reports whether any event in the chain is a session.end —
// not only the last one, because an already-erased chain's last event is
// session.erasure instead (see also host/verify.go's endsCleanly, fixed for
// the identical reason under B5).
func hasSessionEnd(events []Event) bool {
	for _, e := range events {
		if e.Type == TypeSessionEnd {
			return true
		}
	}
	return false
}

// eraseExempt is every field Erase leaves alone, keyed the way
// TestEraseCoversEveryContentField (erase_test.go) names it: the field's own
// name for one of Event's top-level fields, "Error.Kind"/"Error.Message" for
// *EvError's two, and "Secrets.Name" / "Agents.Sandbox" / "StoreKeys.Read"
// and so on for a struct slice's own element fields. The value is why, so an
// exemption is a decision on record rather than a name that is merely
// present.
//
// Two categories, and every entry says which:
//
//   - Protocol and schema values: the chain's own plumbing (the hash chain,
//     the type, the timestamp), and fields that only ever hold one of a
//     small, fixed set of values the code itself chose (an outcome, a mode,
//     a signal name) rather than text an operator typed or a guest
//     produced.
//   - Structural identifiers Article 12 needs kept: a session id, an
//     agent's own declared name, a digest standing in for content it
//     already does not hold. D61's own framing (docs/retention.md §1) is
//     what draws this line: "a session happened, at this time, with these
//     agents, in this many steps, in this order" is the claim Article 12
//     needs and Erase must not remove even when erasing everything else;
//     "what was said, written, or run" is what Article 17 targets and what
//     the fields NOT in this map redact.
var eraseExempt = map[string]string{
	// Chain plumbing and the common header — none of it is content.
	"V": "schema version", "Seq": "position in the chain",
	"TS": "a host-stamped timestamp", "Sandbox": "a KelyfOS-minted session id, never typed by an operator or a guest",
	"Type": "the event's own kind, a fixed enumeration", "Source": "host or guest, a fixed enumeration",
	"Prev": "the hash chain itself", "Hash": "the hash chain itself",

	// Platform identifiers, not content — the same category Kelyfos/Kernel/
	// Arch already are.
	"Image":   "a flavor name from a fixed, built catalog (base/dev), the same category as Arch and Kelyfos",
	"Arch":    "a platform identifier (aarch64/x86_64)",
	"Kelyfos": "the CLI's own version string",
	"Kernel":  "the guest kernel release string",

	"Supervisor": "the in-guest supervisor's own version string",

	// Reason is overwhelmingly a fixed enumeration across the event types
	// that carry it (session.end's shutdown/timeout/…, egress.attempt's
	// five refusal reasons, secret.withheld's five, team.message/refused's
	// four, team.store's six, team.spawn's five, plugin.crash's exit
	// reason) — and its one genuinely free-text use, session.erasure's own
	// -reason, is the operator's stated justification for THIS erasure and
	// must survive it by definition, or an erasure could not be audited at
	// all. A snapshot or paused-session name occasionally rides here too,
	// on session.start ("forked from <snapshot>") and session.resume (a
	// host-built diff of policy values) — the same category of
	// operator-chosen identifier Sandbox and ParentSession already are,
	// not typed content.
	"Reason": "mostly a fixed enumeration; its one free-text use (session.erasure's own -reason) must survive an erasure to remain auditable",

	"Call":   "a host-generated correlation id (\"c<nanotime>\"), never content",
	"Via":    "which door was used, a fixed enumeration",
	"Stream": "stdout or stderr, a fixed enumeration",
	"Signal": "an OS signal name, a fixed enumeration",

	"Error.Kind": "a fixed enumeration",
	// Error.Message was exempt here until F12, on the stated ground that it
	// was "generally a system-generated string (a timeout, a signal name)
	// with no established precedent for holding raw guest content the way
	// Data, Args and Cmd do". The precedent existed two files away, and the
	// exemption was simply wrong: host/servemcpaudit.go stored the first line
	// of a failed tool result here, and a failed sandbox_exec's result is
	// built out of the guest's own stdout — so every failed command in a
	// serve-mcp session left a line of its output in a field an erasure did
	// not touch. host/exec.go copies the guest supervisor's error string the
	// same way, and that one carries an agent-chosen path.
	//
	// The sources are being fixed too, and this is fixed anyway, because
	// either alone drifts: an exemption is what tells the next writer of a
	// field that it is a safe place to put a string. A genuinely
	// system-generated message loses nothing by being fingerprinted, and
	// Error.Kind — the fixed enumeration an auditor actually reads — is still
	// exempt above.

	"SHA256": "a digest, not the content it fingerprints — the exact pattern this whole mechanism generalises from file.write, and now also what session.erasure's own SHA256 anchors (S1)",

	"Mode":    "tunnelled/terminated/plain/direct_tls, a fixed enumeration",
	"Budget":  "max_runtime or idle_timeout, a fixed enumeration",
	"Kind":    "a fixed enumeration across every type that carries it (send/ask/reply, get/put/delete, spawn/despawn)",
	"Outcome": "a fixed enumeration (delivered/refused/unreachable/timeout, ok/error)",

	"Agent": "the team member's own declared name — the structural claim of who did this, which Article 12 needs kept even when what they did is redacted",

	"Profile": "a host-derived description of the confinement policy applied to the guest, not guest-typed text",

	"Plugins":  "configured plugin names from kelyfos.toml, a small operator-declared set like Tools",
	"Forwards": "\"<host-port>:<guest-port>\" pairs — structural port mappings, not content",

	"RootfsSHA256": "a digest", "KernelSHA256": "a digest",

	"Tools": "the fixed set of outward verbs usable against a machine — an enumeration this binary chose, not content",

	"ParentSession": "a KelyfOS-minted session id, structural like Sandbox",

	"Edges": "resolved \"from -> to\" pairs built entirely from Agent names, the same structural category Agent itself is exempt for",

	// The three struct slices' own fields. Secrets and Agents are exempt in
	// full; StoreKeys is the one mixed case (see redactStructSlice).
	"Secrets.Name": "a secret's env-var name is meant to remain forever, proving what was bound without ever showing its value (docs/policy-record.md §5) — the value itself is never recorded in any form, so there is nothing here for an erasure to remove",
	"Secrets.Host": "the domain a bound credential is scoped to — policy, not content",
	"Secrets.Path": "the path scope a bound credential is limited to — policy, not content",

	"Agents.Name":    "an agent's own declared name — the same structural category top-level Agent is exempt for",
	"Agents.Sandbox": "a KelyfOS-minted sandbox id, structural like Sandbox",
	"Agents.Group":   "the fork-template key — already a content hash, not raw content",

	"StoreKeys.Read":  "agent names with read access to the key — structural, the same category Agent is exempt for",
	"StoreKeys.Write": "agent names with write access to the key — structural, the same category Agent is exempt for",
}

// redactEventFields replaces every non-exempt string and []string field on e
// — its own top-level fields, *EvError's two, and the three struct slices'
// own fields — that currently holds content with a fingerprint of what was
// there, and reports whether it touched anything. eraseExempt above is the
// single source of truth for what it leaves alone.
//
// This walks Event by reflection rather than naming Data/Args/Cmd/Argv by
// hand, which is what B3 found wrong with the version of this function
// P7-5 shipped first: a hand-maintained list of four fields left Cwd, Path,
// Peer, Comm, Workspace, Host, Name, Allow, Agents, Edges and StoreKeys
// fully intact through an erasure, the identical shape of miss this
// project has now made three other times (clipLargestField's missing
// Tools, internal/digest's missing session.policy and team.topology).
// Reflection means a field added to Event next month is redacted the day
// it lands, whether or not anyone remembers to touch this file — the
// opposite failure mode from a list, and the one this schema's own history
// says to prefer.
func redactEventFields(e *Event) bool {
	touched := false
	v := reflect.ValueOf(e).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		name := t.Field(i).Name
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			if _, exempt := eraseExempt[name]; exempt {
				continue
			}
			if r := redactString(fv.String()); r != "" {
				fv.SetString(r)
				touched = true
			}

		case reflect.Slice:
			switch fv.Type().Elem().Kind() {
			case reflect.String:
				if _, exempt := eraseExempt[name]; exempt {
					continue
				}
				if fv.Len() == 0 {
					continue
				}
				if r := redactStrings(fv.Interface().([]string)); r != nil {
					fv.Set(reflect.ValueOf(r))
					touched = true
				}
			case reflect.Struct:
				if redactStructSlice(name, fv) {
					touched = true
				}
				// Any other element kind (Ports is []int) carries no text
				// content and is left to clipLargestField's own coverage.
			}

		case reflect.Ptr:
			if fv.IsNil() || fv.Type().Elem().Kind() != reflect.Struct {
				continue
			}
			sv := fv.Elem()
			st := sv.Type()
			for j := 0; j < sv.NumField(); j++ {
				sfv := sv.Field(j)
				if sfv.Kind() != reflect.String {
					continue
				}
				key := name + "." + st.Field(j).Name
				if _, exempt := eraseExempt[key]; exempt {
					continue
				}
				if r := redactString(sfv.String()); r != "" {
					sfv.SetString(r)
					touched = true
				}
			}
		}
	}
	return touched
}

// redactStructSlice is redactEventFields' special case for Event's three
// struct-slice fields (Secrets, Agents, StoreKeys), which reflect.Kind alone
// cannot route through the string/[]string cases above. Each is named
// explicitly, rather than walked generically, because the decision
// genuinely differs by field WITHIN StoreKeys (Name is content the same way
// team.store's own Peer is; Read and Write are not) in a way a purely
// generic walk would have to invent a convention for. A struct-slice field
// Event does not have today panics rather than silently doing nothing, so
// the day a fourth one is added this is found before it ships rather than
// by an adversarial review reading the diff — TestEraseCoversEveryContentField
// exercises every field of Secrets, Agents and StoreKeys by name and would
// hit this panic directly if it were ever reached in error.
func redactStructSlice(field string, fv reflect.Value) bool {
	switch field {
	case "Secrets", "Agents":
		// EvSecret{Name,Host,Path} and EvAgent{Name,Sandbox,Group} are all
		// exempt (eraseExempt) — nothing to do, named explicitly so this
		// switch stays exhaustive over every struct slice Event has rather
		// than falling through a default.
		return false
	case "StoreKeys":
		touched := false
		for i := 0; i < fv.Len(); i++ {
			nameField := fv.Index(i).FieldByName("Name")
			if r := redactString(nameField.String()); r != "" {
				nameField.SetString(r)
				touched = true
			}
		}
		return touched
	default:
		panic(fmt.Sprintf("redactStructSlice: Event gained a struct-slice field (%s) with no "+
			"redaction decision — add a case for it here, and matching entries in eraseExempt "+
			"for whichever of its own fields are not content", field))
	}
}

// erasedPrefix and erasedSuffix bracket the sha256 hex digest in the
// placeholder redactString and redactStrings write in place of erased
// content — "(erased — sha256:<64 hex characters>)", the same in-band-note
// shape clipLargestField already uses for a clipped field. isErasedPlaceholder
// below is what B2 needed and did not have: without it, running erase a
// second time hashed the placeholder itself rather than recognising it as
// already-redacted, silently replacing the real fingerprint with the hash
// of the note text and reporting a nonzero "redacted" count for a chain
// with nothing left to redact.
const (
	erasedPrefix = "(erased — sha256:"
	erasedSuffix = ")"
)

func erasedPlaceholder(sum [sha256.Size]byte) string {
	return erasedPrefix + hex.EncodeToString(sum[:]) + erasedSuffix
}

// isErasedPlaceholder reports whether s is already one of this function's
// own placeholders — checked structurally (prefix, suffix, and a valid
// 64-character hex digest between them) rather than by exact byte match
// against one freshly computed, since the point is to recognise a
// placeholder written by an EARLIER call with different content behind it.
func isErasedPlaceholder(s string) bool {
	if !strings.HasPrefix(s, erasedPrefix) || !strings.HasSuffix(s, erasedSuffix) {
		return false
	}
	hexPart := s[len(erasedPrefix) : len(s)-len(erasedSuffix)]
	if len(hexPart) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

// redactString computes s's sha256 and returns a placeholder embedding it.
// "" in means "" out: an already-empty field has nothing to redact and this
// is not counted as touched. A field that is already one of this function's
// own placeholders (B2) also returns "" — re-hashing a placeholder from an
// earlier erasure would replace the real fingerprint with the hash of the
// note text, permanently losing the one thing this mechanism exists to
// keep: proof of what was there. The reviewer reproduced this on the real
// CLI — running `kelyfos sessions erase` twice on the same session reported
// a second, nonzero redaction count and silently destroyed every
// fingerprint from the first run.
func redactString(s string) string {
	if s == "" || isErasedPlaceholder(s) {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return erasedPlaceholder(sum)
}

// redactStrings is redactString for a []string field, collapsing it to one
// placeholder element the way clipStrings already collapses an oversized
// one. The digest is computed over a length-prefixed encoding of the
// elements (S5, documented in docs/retention.md §5 and docs/events.md)
// rather than joining them with a delimiter first: this function's first
// draft joined with a plain space, which made ["a b", "c"] and
// ["a", "b", "c"] fingerprint identically — collision-prone by
// construction, since any single fixed delimiter can appear inside an
// element unless something upstream forbids it, and nothing here does.
// Prefixing each element with its own byte length before concatenating is
// injective: the encoded bytes for one slice can only be split back into
// elements one way, so two slices that are not element-for-element
// identical can never encode to the same bytes, whatever those elements
// contain.
//
// A slice that is already a single element matching this function's own
// placeholder shape (B2, the same check redactString makes) returns nil
// rather than re-hashing it.
func redactStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	if len(s) == 1 && isErasedPlaceholder(s[0]) {
		return nil
	}
	var buf bytes.Buffer
	var lenBuf [8]byte
	for _, e := range s {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(e)))
		buf.Write(lenBuf[:])
		buf.WriteString(e)
	}
	sum := sha256.Sum256(buf.Bytes())
	return []string{erasedPlaceholder(sum)}
}
