package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// Fuzz targets for the export's data island (P6-3, P6-6).
//
// An exported report is the one file in this product a *stranger* hands you and
// asks you to open. Everything else the CLI parses was written by this machine;
// this was written by whoever sent it. So the boundary P6-3 declared hostile —
// anything arriving from outside — now runs through here, and the extractor is
// the first thing that touches it.

// FuzzExtractChain asserts the property the feature rests on: what comes out of
// a page is what went into it.
//
// The absence of a panic is the cheap half. The half that matters is that
// extraction is lossless, because an event's digest is computed over the line
// as written — a single byte changed on the way in or out would make a
// legitimate record report as tampered with, which is the false alarm the first
// half of P6-6 existed to remove.
func FuzzExtractChain(f *testing.F) {
	f.Add([]byte(""), []byte(""))
	f.Add([]byte(`{"seq":1}`+"\n"), []byte("<html></html>"))
	f.Add([]byte(`{"data":"</pre><pre id=\"kelyfos-chain\">"}`+"\n"), []byte("<h1>report</h1>"))
	f.Add([]byte{0x00, 0xff, '\n'}, []byte("<!-- comment -->"))
	f.Add(bytes.Repeat([]byte("a"), 1000), []byte(chainOpen+chainClose))

	f.Fuzz(func(t *testing.T, record, around []byte) {
		// A page is the island with arbitrary bytes on either side of it, which
		// is what a report is: a page of markup with the record inside.
		page := string(around) + chainOpen + string(embedChain(record)) + chainClose + string(around)
		got, err := ExtractChain([]byte(page))
		if err != nil {
			// The only honest reason to refuse this page is that the
			// surrounding bytes carried a second opening marker — the
			// ambiguity rule, doing its job.
			if strings.Contains(string(around), chainOpen) {
				return
			}
			t.Fatalf("a page built from a record refused to give it back: %v", err)
		}
		if !bytes.Equal(got, record) {
			t.Fatalf("extraction changed the record:\n in %q\nout %q", record, got)
		}
	})
}

// FuzzExtractChainRefusesRatherThanPanics runs the extractor over bytes nobody
// generated from a record — a file a stranger sent, or a file that is not a
// report at all. Any answer is acceptable except a crash, and except returning
// something for a file that carries no record.
func FuzzExtractChainRefusesRatherThanPanics(f *testing.F) {
	f.Add("<html><body>nothing here</body></html>")
	f.Add(chainOpen)
	f.Add(chainOpen + chainClose)
	f.Add(chainOpen + "!!!!" + chainClose)
	f.Add(chainOpen + "AAAA" + chainClose + chainOpen + "BBBB" + chainClose)
	f.Add(chainClose + chainOpen)

	f.Fuzz(func(t *testing.T, page string) {
		got, err := ExtractChain([]byte(page))
		if err != nil {
			return
		}
		if !strings.Contains(page, chainOpen) {
			t.Fatalf("extracted %d bytes from a file with no island", len(got))
		}
	})
}

// FuzzMarkedRefusesAmbiguity is marked()'s own contract, fuzzed directly: it
// may answer only when an id names exactly one element — <code> or <span>,
// counted together — anywhere in the page. This is the property the
// cross-tag fallback bug broke: two occurrences split across the two tag
// kinds (one <code>, one <span>) is exactly as ambiguous as two of the same
// tag, and the old code answered anyway once it fell through to the second
// tag kind and found a lone match there.
//
// Seeded with the six real marker ids, because those are the only ids
// marked() is ever actually asked about (chain.go's ClaimsIn, sign.go's
// SignatureIn) — an attacker gains nothing by targeting an id nothing reads.
func FuzzMarkedRefusesAmbiguity(f *testing.F) {
	ids := []string{
		"kelyfos-head", "kelyfos-events", "kelyfos-session",
		"kelyfos-fingerprint", "kelyfos-signature", "kelyfos-signing-key",
	}
	for _, id := range ids {
		f.Add([]byte(`<code id="`+id+`">a</code>`), id)
		f.Add([]byte(`<span id="`+id+`">a</span>`), id)
		f.Add([]byte(`<code id="`+id+`">a</code><code id="`+id+`">b</code>`), id)
		// The exact bug shape: one of each tag kind for the same id.
		f.Add([]byte(`<code id="`+id+`">a</code><span id="`+id+`">b</span>`), id)
		f.Add([]byte(`<div id="`+id+`">a</div>`), id)
	}
	f.Add([]byte(""), "kelyfos-fingerprint")

	f.Fuzz(func(t *testing.T, page []byte, id string) {
		total := bytes.Count(page, []byte(`<code id="`+id+`">`)) +
			bytes.Count(page, []byte(`<span id="`+id+`">`))
		got := marked(page, id)
		if total != 1 && got != "" {
			t.Fatalf("marked(page, %q) = %q, want \"\" for a combined tag count of %d", id, got, total)
		}
	})
}

// FuzzGenuineEditDoesNotBothDisagreeAndPass is the review's own literal ask:
// "no edit to a genuine page produces one that both disagrees visually and
// passes." It starts from one real, signed render — RenderSigned over a real
// chain, exactly as an operator would produce — and fuzzes injecting one
// extra, differently-valued occurrence of one of the six marker ids: which
// id, which tag kind carries the injection, what replacement text it holds,
// and where in the byte stream it lands.
//
// "Caught" means two different things, because Disagree and the cryptographic
// signature check cover different halves of the page, and the split is not
// incidental to this test — it is how the real verify path is built
// (host/verify.go: Disagree runs first; sig.Check runs only once Disagree
// finds nothing wrong). Disagree inspects Claimed (Head, Events, Session,
// Fingerprint) and the fingerprint SignatureIn derives from the signing key,
// so tampering kelyfos-head, -events, -session, -fingerprint or
// -signing-key in a way that actually changes what marked() reports is
// asserted against Disagree. kelyfos-signature (Sig) is not part of Claimed
// and Disagree never looks at it by design — the signature bytes are checked
// cryptographically instead — so that one id is asserted against
// Signature.Check, not Disagree; asserting Disagree there would be the wrong
// -direction assertion the review warned against, since Disagree was never
// meant to see it.
//
// Comparing marked()'s actual before/after answer (rather than the raw
// injected text) is what a naive text diff would miss: an injection placed
// mid-tag can corrupt the genuine occurrence instead of adding a second one,
// and the only ground truth for "did this visibly change anything" is what
// marked() itself now reports.
func FuzzGenuineEditDoesNotBothDisagreeAndPass(f *testing.F) {
	chain := chainOf(f, []recorder.Event{
		ev(recorder.TypeSessionStart, ""),
		ev(recorder.TypeSessionEnd, ""),
	})
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := RenderSigned(&buf, "s1", chain, key)
	if err != nil {
		f.Fatal(err)
	}
	genuine := buf.Bytes()
	_, head, err := recorder.Verify(bytes.NewReader(chain))
	if err != nil {
		f.Fatal(err)
	}
	if bad := ClaimsIn(genuine).Disagree(head, n, chain, SignatureIn(genuine).Fingerprint()); len(bad) != 0 {
		f.Fatalf("the fixture's own genuine render disagrees with itself: %v", bad)
	}

	ids := []string{
		"kelyfos-head", "kelyfos-events", "kelyfos-session",
		"kelyfos-fingerprint", "kelyfos-signature", "kelyfos-signing-key",
	}
	tags := []string{"code", "span"}

	// The review's exact reproduction recipe: a hidden <span> for
	// kelyfos-fingerprint carrying the true value, which is what turns the
	// duplicated, edited <code> into a page that still verifies.
	f.Add(3, 1, ClaimsIn(genuine).Fingerprint, len(genuine))
	f.Add(0, 0, "0000000000000000000000000000000000000000000000000000000000000000", 0)
	f.Add(4, 0, "deadbeef", len(genuine))
	f.Add(5, 1, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", len(genuine)/2)

	f.Fuzz(func(t *testing.T, idIdx, tagIdx int, injected string, pos int) {
		id := ids[fuzzMod(idIdx, len(ids))]
		tag := tags[fuzzMod(tagIdx, len(tags))]
		p := fuzzMod(pos, len(genuine)+1)

		insertion := []byte(`<` + tag + ` id="` + id + `">` + injected + `</` + tag + `>`)
		tampered := []byte(string(genuine[:p]) + string(insertion) + string(genuine[p:]))

		if id == "kelyfos-signature" {
			before, after := SignatureIn(genuine).Sig, SignatureIn(tampered).Sig
			if before == after {
				return // no visible change to the page's claim; nothing to catch
			}
			if _, err := SignatureIn(tampered).Check(chain, head); err == nil {
				t.Fatalf("injecting a %s kelyfos-signature changed the page's claimed signature (%q -> %q) "+
					"and it still checked out cryptographically", tag, before, after)
			}
			return
		}

		before, after := fuzzDerivedValue(id, genuine), fuzzDerivedValue(id, tampered)
		if before == after {
			return // a legitimate "still agrees" case, not a counterexample
		}
		bad := ClaimsIn(tampered).Disagree(head, n, chain, SignatureIn(tampered).Fingerprint())
		if len(bad) == 0 {
			t.Fatalf("injecting a %s %s at byte %d changed what the page claims (%q -> %q) "+
				"but Disagree found nothing wrong", tag, id, p, before, after)
		}
	})
}

// fuzzDerivedValue is the value Disagree actually compares for id, read back
// out of page the same way ClaimsIn/SignatureIn read it for the real verify
// path.
func fuzzDerivedValue(id string, page []byte) string {
	switch id {
	case "kelyfos-head":
		return ClaimsIn(page).Head
	case "kelyfos-events":
		return ClaimsIn(page).Events
	case "kelyfos-session":
		return ClaimsIn(page).Session
	case "kelyfos-fingerprint":
		return ClaimsIn(page).Fingerprint
	case "kelyfos-signing-key":
		return SignatureIn(page).Fingerprint()
	default:
		return ""
	}
}

func fuzzMod(n, m int) int {
	if m <= 0 {
		return 0
	}
	r := n % m
	if r < 0 {
		r += m
	}
	return r
}
