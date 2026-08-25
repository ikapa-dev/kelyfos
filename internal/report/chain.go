package report

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"strconv"
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

// Claimed is what a page says about the record it carries: the three values a
// reader would write down or repeat to somebody else.
//
// They are read back out and checked against the record because the page is
// where they can be edited. A reader is told to compare the head against one
// they were given separately, and a head the file can quietly change is a
// reader following an instruction into a trap. Checking them is bounded — three
// values, each a function of the bytes — which is what distinguishes it from
// checking the rendered timeline, where the list of things to compare has no
// end and a partial answer would invite a reader to treat the rest as checked.
type Claimed struct {
	Head    string
	Events  string
	Session string
	// Fingerprint is the signing key's digest as the page prints it.
	//
	// It is here because P6-19's exam found it was the one trust-bearing value
	// the page renders and nothing compared: the banner tells a reader the
	// fingerprint "means something only if you recognise it from somewhere other
	// than this page" — that is, it is the value the reader is instructed to act
	// on — and a page whose fingerprint had been swapped for one the reader
	// trusts still verified clean. Worse, deleting its marker passed where
	// deleting any of the other three failed closed.
	Fingerprint string
}

// ClaimsIn reads the values a page states about its own record.
//
// A missing marker is reported as empty rather than skipped silently. Every page
// this package writes carries all three, so absence is not "an older format" —
// it is a page somebody edited, and deleting an id to switch off a check is
// exactly the edit the check exists to catch.
func ClaimsIn(page []byte) Claimed {
	return Claimed{
		Head:        marked(page, "kelyfos-head"),
		Events:      marked(page, "kelyfos-events"),
		Session:     marked(page, "kelyfos-session"),
		Fingerprint: marked(page, "kelyfos-fingerprint"),
	}
}

// marked pulls the text out of the one element carrying an id. Two of them is
// no answer rather than the first answer, for the reason ExtractChain refuses a
// page with two islands.
func marked(page []byte, id string) string {
	for _, tag := range []string{"code", "span"} {
		open := []byte(`<` + tag + ` id="` + id + `">`)
		if bytes.Count(page, open) != 1 {
			continue
		}
		rest := page[bytes.Index(page, open)+len(open):]
		if end := bytes.Index(rest, []byte("</"+tag+">")); end >= 0 {
			return string(rest[:end])
		}
	}
	return ""
}

// Disagree lists the values the page states that the record does not support.
//
// An absent marker counts as a disagreement rather than as nothing to check.
// Every page this package writes carries all three, so a missing one is a page
// that was edited — and switching a check off by deleting an id, leaving the
// visible number in place, is the neatest version of the edit this exists to
// catch.
func (c Claimed) Disagree(head string, events int, chain []byte, fingerprint string) []string {
	var bad []string
	check := func(what, stated, actual string) {
		switch {
		case stated == "":
			bad = append(bad, fmt.Sprintf("the page states no %s; every KelyfOS export states one", what))
		case stated != actual:
			bad = append(bad, fmt.Sprintf("the page says %s %s; the record says %s", what, stated, actual))
		}
	}
	check("chain head", c.Head, head)
	check("event count", c.Events, strconv.Itoa(events))

	// The session is the record's own `sandbox`, which every event carries and
	// every digest covers. Taken from the first event: a chain whose events
	// disagree among themselves about it is a separate question, and one this
	// verifier does not yet ask.
	session := ""
	if i := bytes.Index(chain, []byte(`"sandbox":"`)); i >= 0 {
		rest := chain[i+len(`"sandbox":"`):]
		if j := bytes.IndexByte(rest, '"'); j >= 0 {
			session = string(rest[:j])
		}
	}
	check("session", c.Session, session)

	// The fingerprint, but only when the page carries a signature at all: an
	// unsigned export prints no fingerprint and must not be told it is missing
	// one. When there IS a signature, the printed fingerprint has to be the
	// fingerprint of the key that actually made it — otherwise the page can name
	// a key the reader trusts while being signed by a key they have never seen,
	// which is the whole of what this value was for (P6-19).
	if fingerprint != "" {
		switch {
		case c.Fingerprint == "":
			bad = append(bad, "the page states no signing key fingerprint; every signed KelyfOS export states one")
		case c.Fingerprint != fingerprint:
			// Worded apart from the others on purpose: this one does not come
			// from the record. The record says nothing about who exported it —
			// the signature does — so "the record says" would be wrong here in
			// the one place a reader is deciding whom to believe.
			bad = append(bad, fmt.Sprintf(
				"the page names signing key fingerprint %s; the signature on it was made by %s",
				c.Fingerprint, fingerprint))
		}
	} else if c.Fingerprint != "" {
		bad = append(bad, "the page names a signing key fingerprint and carries no signature to match it against")
	}
	return bad
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
