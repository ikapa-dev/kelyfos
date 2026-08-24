package report

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"strings"
)

// The record travels inside the page, and this is how it gets in and out.
//
// A report that renders a verdict about itself is asking a reader to trust a
// sentence the file wrote. What makes the page evidence instead is that the
// record it was rendered from is *in* it, in a form a verifier can take back
// out byte-for-byte: an event's digest is computed over the bytes as written
// (recorder.digestOfLine), so anything that alters one byte on the way in or
// out breaks every event after it.
//
// Hence base64 rather than the JSONL itself. html/template escapes a text node
// correctly, but every line of JSON carries `"` and would come out as `&#34;`,
// so an extractor would have to reverse HTML escaping exactly to recover the
// preimage — a second escaping implementation, on the one path where being
// almost right reads as tamper detection firing. It also keeps the page
// honestly self-contained: a session that reached a URL would otherwise put
// that URL in a file whose whole claim is that it fetches nothing.
//
// And hence template.HTML on the payload, which is the one place in this
// package that opts out of escaping and needs its reason written down.
// html/template escapes `+` to `&#43;` in element text — measured, not assumed
// — and `+` is an ordinary base64 character. Left as a plain string, the island
// would be silently corrupted for any record whose encoding happens to contain
// one, and the reader would be told an untouched record had been modified: the
// exact false alarm the first half of P6-6 removed, moved to the export.
//
// Opting out is safe here because of what produces the value rather than
// because of what it looks like. base64.StdEncoding emits only [A-Za-z0-9+/=]
// and this adds newlines — no `<`, no `>`, no `&`, no quote — so the payload
// cannot open a tag, an entity or an attribute no matter what the guest wrote.
// TestTheIslandIsOnlyEverBase64 pins that, because the argument is about the
// encoder and an encoder can be changed.
//
// The alternative was base64url, whose alphabet html/template leaves alone. It
// was rejected: `base64 -d` is on every machine and `basenc --base64url` is not
// on macOS at all, and the reader with nothing but sed and base64 is who the
// island exists for.
const (
	// chainOpen is the only thing a verifier looks for. Extraction is a
	// byte-level search rather than HTML parsing on purpose: a verifier that
	// had to parse HTML to find the record would be a second browser, and a
	// reader with nothing but sed should be able to do the same thing.
	chainOpen  = `<pre id="kelyfos-chain">`
	chainClose = `</pre>`

	// chainWrap keeps the island readable when a reader opens the details
	// element and looks at it, and costs nothing: base64 decoders ignore
	// newlines, including the base64(1) on the machine of a reader who does not
	// have KelyfOS.
	chainWrap = 76
)

// ErrNoChain is returned for a file that carries no record: not an export, or
// an export written before v1.0, when the page carried no evidence at all.
var ErrNoChain = errors.New("no KelyfOS record embedded in this file")

// embedChain renders a flight recorder as the island's payload.
//
// It starts on its own line, which is not cosmetic: the page prints a sed
// one-liner for a reader who has no KelyfOS, and that one-liner drops the first
// and last lines of the range. A payload sharing a line with the opening tag
// would lose its first 76 characters to instructions this file published
// itself.
func embedChain(raw []byte) template.HTML {
	enc := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/chainWrap + 1)
	for i := 0; i < len(enc); i += chainWrap {
		end := min(i+chainWrap, len(enc))
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return template.HTML(b.String()) //nolint:gosec // base64 only; see the note above
}

// ExtractChain takes the flight recorder back out of an exported report.
//
// It refuses an ambiguous file rather than choosing between two records. A page
// with two islands is not a page whose second island is a decoy — it is a file
// nobody's exporter wrote, and picking one would be answering a question the
// reader did not ask.
func ExtractChain(page []byte) ([]byte, error) {
	if n := bytes.Count(page, []byte(chainOpen)); n == 0 {
		return nil, ErrNoChain
	} else if n > 1 {
		return nil, fmt.Errorf("this file carries %d embedded records; a report carries one", n)
	}
	rest := page[bytes.Index(page, []byte(chainOpen))+len(chainOpen):]
	end := bytes.Index(rest, []byte(chainClose))
	if end < 0 {
		return nil, errors.New("the embedded record in this file is never closed")
	}
	// Whitespace is the line wrapping this package added, and nothing else: the
	// base64 alphabet has none. Dropping it here is what lets a reader reflow
	// the island by hand — or extract it with sed — and still have it verify.
	payload := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, string(rest[:end]))
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("the embedded record is not readable: %w", err)
	}
	return raw, nil
}
