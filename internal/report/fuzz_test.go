package report

import (
	"bytes"
	"strings"
	"testing"
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
