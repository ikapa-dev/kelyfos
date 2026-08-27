package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Erase rewrites one session's own chain in place: every field known to
// carry guest-influenced or operator-supplied content — Data, Args, Cmd and
// Argv — is replaced with a fingerprint of what was there, its own sha256,
// rather than deleted or left alone (P7-5, D61). A new session.erasure event
// is appended recording that this ran, why, and how many events it touched,
// so the erasure itself is part of the record rather than a silent edit —
// the same "a policy ceiling nobody can see being enforced is a ceiling
// nobody can audit" reasoning this product already applies to a refused
// call or a blocked connection, applied here to its own history.
//
// Argv earned its place here the way the other three did not have to argue
// for it: `kelyfos run --workspace . -- claude "summarise this: jane's
// email is ..."` is the shape this product's own docs use as the canonical
// example (`kelyfos run --workspace . --allow github.com -- claude`), and
// the trailing command becomes part of session.start's own Argv — the
// host's own os.Args, not a guest's, but no less capable of carrying
// exactly the content Article 17 targets for it.
//
// This is the pattern D61 names file.write as the precedent for: a field
// recorded by digest rather than by content is not a compromise between
// GDPR Article 17 (erasure) and EU AI Act Article 12 (retention) — it is
// what lets both stand at once, because the chain that Article 12 requires
// stay intact and verifiable is a *structural* claim (what happened, when,
// how many events, in what order) that does not need the content Article 17
// wants gone.
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
// phrase) means. Every field this function does not touch — V, TS,
// Sandbox, Type, Source, Agent, and everything else about what happened —
// survives unchanged.
//
// Refuses a chain that does not already verify: rewriting a broken chain
// would erase the evidence that it was broken, which is the one thing an
// erasure path must never do. Refuses an empty chain, and a chain with
// nothing to redact, rather than writing a no-op erasure event that
// changes nothing but claims something happened.
func Erase(root, sandboxID, reason string) (redacted int, err error) {
	path := Path(root, sandboxID)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	// The same exclusive lock Append takes, held for the whole read-rewrite-
	// rename: a concurrent Append racing this rewrite is the one scenario
	// that could lose an event (its write landing on the file this renames
	// over rather than the one that replaces it), and flock is what a
	// process actually still writing this session already respects.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return 0, fmt.Errorf("lock flight recorder: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)

	blob, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	if _, _, err := Verify(bytes.NewReader(blob)); err != nil {
		return 0, fmt.Errorf("refusing to erase: chain does not verify: %w", err)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, fmt.Errorf("%s: empty chain, nothing to erase", sandboxID)
	}

	// redacted counts events touched, not fields touched: an event with
	// more than one of these fields set (not a shape any type on this
	// schema produces today, but nothing here assumes it stays that way)
	// still counts once.
	for i := range events {
		e := &events[i]
		touched := false
		if r := redactString(e.Data); r != "" {
			e.Data = r
			touched = true
		}
		if r := redactString(e.Args); r != "" {
			e.Args = r
			touched = true
		}
		if r := redactStrings(e.Cmd); r != nil {
			e.Cmd = r
			touched = true
		}
		if r := redactStrings(e.Argv); r != nil {
			e.Argv = r
			touched = true
		}
		if touched {
			redacted++
		}
	}
	if redacted == 0 {
		return 0, fmt.Errorf("%s: nothing to erase — no event carries a redactable field (data, args, cmd or argv)", sandboxID)
	}

	events = append(events, Event{
		Type: TypeSessionErasure, Source: SourceHost, Sandbox: sandboxID,
		Reason: reason, Modified: redacted,
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

	// Written to a temp file in the same directory, then renamed into
	// place — the same crash-safety pattern storeTemplate already uses for
	// the fork-template cache: a process that dies mid-write leaves the
	// temp file and an untouched original, never a half-erased chain.
	tmp := path + ".erasing"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		_ = os.Remove(tmp)
		return redacted, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return redacted, err
	}
	return redacted, nil
}

// redactString computes s's sha256 and returns a placeholder embedding it —
// the in-band note this codebase already uses for a clipped field
// (clipLargestField's "...(clipped from N bytes)"), applied here to an
// erased one instead. "" in means "" out: an already-empty field has
// nothing to redact and this is not counted as touched.
func redactString(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("(erased — sha256:%s)", hex.EncodeToString(sum[:]))
}

// redactStrings is redactString for a []string field, collapsing it to one
// placeholder element the way clipStrings already collapses an oversized
// one — the digest is over the joined elements, matching how clipStrings
// itself measures "the content" of a string slice.
func redactStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	sum := sha256.Sum256([]byte(strings.Join(s, " ")))
	return []string{fmt.Sprintf("(erased — sha256:%s)", hex.EncodeToString(sum[:]))}
}
