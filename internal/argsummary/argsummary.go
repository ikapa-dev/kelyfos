// Package argsummary renders an MCP tool call's arguments for an audit
// record.
//
// Two callers need this: the outward door (host/servemcpaudit.go, a client
// calling this server) and the inward one (supervisor/pluginhost.go, an agent
// calling a plugin). Both write to a chain a person is meant to be able to
// trust, and both need the same two guarantees on the way in — an argument
// that carries content is replaced by its size and never its value, and
// nothing a caller sends, however shaped, can grow a record line past what
// its readers can read back. Until this package existed the two doors kept
// separate copies of that logic, in exact lock-step by discipline rather than
// by construction — an edit to one that missed the other would have made a
// supervisor-recorded plugin call redact differently from a host-recorded
// tool call, with nothing to catch the drift (F12).
package argsummary

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// ContentKeys are the arguments a record must never hold, because they carry
// content rather than intent. The rule is the one file.write already
// follows: what was written is recorded by size and digest, never by value.
//
// `data` is here because a guest's `upload` carries base64 file contents
// under that name. The promise this map exists to keep — that an argument
// carrying content is replaced "including on a tool that does not exist yet"
// — only holds if both callers use the same list, which is the point of
// sharing it rather than declaring it twice.
var ContentKeys = map[string]bool{"content": true, "stdin": true, "data": true}

// The bounds that keep a record line readable.
//
// Nothing upstream of either caller bounds what a client or a plugin-calling
// agent puts in a tool call, and every reader downstream of the record — the
// flight recorder's own scanner, and the supervisor's events channel to the
// host — is smaller than an MCP frame. A call carrying megabytes under any
// key, or spread across enough short arguments, therefore has to be bounded
// here, on the line, rather than trusted to arrive small.
//
// Neither number changes what a real call renders. 120 bytes is the cap the
// string branch has always applied, and no built-in tool declares an
// object-valued or deeply nested argument. 4 KiB is far above anything a
// legitimate call renders and well below the smallest reader's line cap.
const (
	MaxArgBytes  = 120
	MaxArgsBytes = 4 << 10
	// An array's whole rendering, deliberately far above MaxArgBytes: the
	// egress allowlist arrives as an array and is recorded nowhere else, so
	// cutting it short loses the only note of what an agent asked to reach.
	// MaxArgsBytes still bounds the joined line however this is spent.
	MaxArrayBytes = 1 << 10
)

// Summarise renders a call's arguments for the record.
//
// It walks whatever it was given rather than knowing the tools, so an
// argument added later — by either caller — is visible in the log without
// anyone remembering to add it here, and an argument that carries content is
// replaced by its size on whatever tool it appears on, including a tool that
// does not exist yet.
func Summarise(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Unparseable arguments are a fact about the call, and the call is
		// still recorded: malformed JSON is exactly the kind of thing a
		// transcript should show.
		return fmt.Sprintf("<unparseable, %d bytes>", len(raw))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		v := m[k]
		if ContentKeys[k] {
			parts = append(parts, k+"="+contentSize(v))
			continue
		}
		parts = append(parts, proto.SafeText(k)+"="+compactValue(v))
	}
	out := strings.Join(parts, " ")
	if len(out) > MaxArgsBytes {
		// The last bound, and the one that holds however the caller shaped
		// the call: a key is as unbounded as a value, and an object may have
		// as many of them as fit in the frame.
		return fmt.Sprintf("%s…(%d bytes)", ClipUTF8(out, MaxArgsBytes), len(out))
	}
	return out
}

// ClipUTF8 cuts s to at most n bytes without leaving half a rune at the end.
//
// A summary is marshalled into a record and printed to a terminal. A
// trailing fragment of a multi-byte character is neither: json.Marshal would
// replace it with U+FFFD in the line that gets hashed, and the terminal would
// show something else again. Dropping the fragment costs at most three bytes
// of a summary that has already said how long the whole thing was.
func ClipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 {
		// DecodeLastRuneInString reports (RuneError, 1) for a broken tail and
		// (U+FFFD, 3) for a replacement character that is genuinely there, so
		// a character the JSON decoder already substituted is kept.
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// contentSize is what an argument carrying content is replaced by: its size,
// and never its value.
//
// The rule is about the key and not about the type the caller chose to put
// under it. A string is measured as itself; anything else — an object, an
// array, a number — is measured as the JSON it arrived as. Recognising only a
// string here would have left the redaction guarantee decided by the caller,
// who picks the shape as well as the bytes: the same content wrapped in an
// object fell through to compactValue, whose last resort was json.Marshal
// with no length to stop at, and was written into the record whole under the
// one key this code promises never to hold by value. That last resort is
// bounded now too, but a bounded rendering of content is still content: the
// key is what decides, and under these three names nothing is rendered at
// all.
func contentSize(v any) string {
	if s, ok := v.(string); ok {
		return fmt.Sprintf("<%d bytes>", len(s))
	}
	blob, err := json.Marshal(v)
	if err != nil {
		// A value that came out of json.Unmarshal marshals again, so there is
		// no known way here. If one is ever found, the half of the promise
		// worth keeping is the half that withholds.
		return "<withheld>"
	}
	return fmt.Sprintf("<%d bytes>", len(blob))
}

// compactValue renders one argument. Long values are truncated with their
// full length named, so a log line stays a line and still says what it was
// cut from.
//
// Every branch is bounded, not only the string one. The cap here was once the
// string branch's alone, which left an argument's size decided by the type
// the caller chose to send: the same bytes inside an object went to the
// default branch and were marshalled whole, and the same bytes spread across
// an array were rendered element by element with nothing counting them.
func compactValue(v any) string {
	switch t := v.(type) {
	case string:
		if len(t) > MaxArgBytes {
			return fmt.Sprintf("%q…(%d bytes)", t[:MaxArgBytes], len(t))
		}
		return proto.SafeText(t)
	case []any:
		parts := make([]string, 0, len(t))
		used := 0
		for i, e := range t {
			// The budget is generous rather than tight, because the thing
			// most often carried in an array here is the egress allowlist —
			// and that is recorded nowhere else. A 120-byte budget spent
			// across the whole array cut a real eight-domain list short,
			// which is audit fidelity lost on ordinary traffic to bound a
			// case the 4 KiB clip on the joined line already bounds (P6-28).
			// Checked before the element rather than after it, so an array
			// always renders at least its first.
			if used >= MaxArrayBytes {
				parts = append(parts, fmt.Sprintf("…(%d more)", len(t)-i))
				break
			}
			s := compactValue(e)
			used += len(s) + 1
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		blob, err := json.Marshal(v)
		if err != nil {
			return "?"
		}
		if len(blob) > MaxArgBytes {
			// In practice an object: a bool renders in five bytes and a null
			// in four, and nothing else reaches here. Quoted rather than cut
			// raw, because %q escapes a rune the cut ran through as well as
			// anything the marshalled JSON left unescaped.
			return fmt.Sprintf("%q…(%d bytes)", blob[:MaxArgBytes], len(blob))
		}
		return string(blob)
	}
}
