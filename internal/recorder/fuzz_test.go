package recorder

import (
	"bytes"
	"os"
	"testing"
)

// Fuzz targets for the flight recorder (P6-3).
//
// The chain is hostile input by two separate routes, and the second is the one
// that matters. The first is ordinary: the file was written by an earlier run,
// and a run can end badly. The second arrives with P6-6 — an exported session
// report is a file a stranger hands you and asks you to believe, and
// `kelyfos verify` will run exactly this code over exactly those bytes. A
// parser that can be made to crash is a denial of the audit story; a parser
// that can be made to *agree* with a forged chain is worse.

// FuzzVerifyAgreesWithRead asserts the property the product depends on rather
// than merely the absence of a panic.
//
// Verify and Read parse the same format for different purposes: one checks the
// chain, the other renders it. If Verify accepts a file, Read must agree about
// what is in it — same count, no error. A divergence means the verified thing
// and the displayed thing are not the same thing, which is precisely the gap a
// forged report would live in.
func FuzzVerifyAgreesWithRead(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(`{"seq":1,"type":"session.start"}` + "\n"))
	f.Add([]byte("not json\n"))
	f.Add([]byte(`{"seq":1,"prev":"","hash":"deadbeef","type":"session.start"}` + "\n"))
	f.Add([]byte(`{"seq":2,"type":"session.end"}` + "\n"))
	f.Add([]byte(`{"seq":1,"type":"session.start"}` + "\n" + `{"seq":2,"type":"session.end"}` + "\n"))
	f.Add(validChain(f, 3))

	f.Fuzz(func(t *testing.T, data []byte) {
		n, verr := Verify(bytes.NewReader(data))
		if verr != nil {
			// A refusal is a correct outcome. Verify's own count is a prefix
			// length and is not required to mean anything once it has failed.
			return
		}
		events, rerr := Read(bytes.NewReader(data))
		if rerr != nil {
			t.Fatalf("Verify accepted %d events but Read refused the same bytes: %v", n, rerr)
		}
		if len(events) != n {
			t.Fatalf("Verify counted %d events and Read found %d in the same bytes", n, len(events))
		}
	})
}

// validChain builds a real chain so the corpus contains at least one input that
// reaches past the first hash check. A seed that always fails at line one
// teaches the fuzzer nothing about the interesting half of the function.
//
// It goes through the real Recorder rather than hand-rolling the chaining. A
// hand-built seed would encode this test's belief about how events are stamped,
// and if that belief drifted from Append the seed would quietly stop being a
// valid chain — which is the one property it exists to have.
func validChain(f *testing.F, n int) []byte {
	f.Helper()
	root := f.TempDir()
	rec, err := Open(root, "fuzzseed")
	if err != nil {
		f.Fatalf("opening the seed recorder: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := rec.Append(Event{Type: TypeSessionStart}); err != nil {
			f.Fatalf("building the seed chain: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		f.Fatalf("closing the seed recorder: %v", err)
	}
	blob, err := os.ReadFile(Path(root, "fuzzseed"))
	if err != nil {
		f.Fatalf("reading the seed chain back: %v", err)
	}
	if _, err := Verify(bytes.NewReader(blob)); err != nil {
		f.Fatalf("the seed chain this test built does not verify: %v", err)
	}
	return blob
}
