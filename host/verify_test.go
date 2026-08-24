package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
)

// exportedSession writes a real chain, exports it, and hands back both — the
// record and the page that carries it.
func exportedSession(t *testing.T) (chain []byte, page []byte) {
	t.Helper()
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	code := 0
	for _, e := range []recorder.Event{
		{Type: recorder.TypeSessionStart, Image: "dev", Arch: "aarch64"},
		{Type: recorder.TypeCommandStart, Call: "c1", Cmd: []string{"echo", "hi"}, Via: "exec"},
		{Type: recorder.TypeCommandExit, Call: "c1", Code: &code},
		{Type: recorder.TypeSessionEnd, Reason: "shutdown"},
	} {
		if err := rec.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	rec.Close()

	chain, err = os.ReadFile(recorder.Path(root, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := report.Render(&buf, "s1", chain); err != nil {
		t.Fatal(err)
	}
	return chain, buf.Bytes()
}

// The record a reader gets out of a report is the file the host wrote. Not
// equivalent to it, not a re-serialisation of it: the same bytes, because the
// digests are computed over the bytes.
func TestTheRecordSurvivesTheRoundTripThroughAReport(t *testing.T) {
	chain, page := exportedSession(t)
	got, kind, err := recordIn(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("the record taken out of the report is not the record that went in")
	}
	if !strings.Contains(kind, "report") {
		t.Errorf("the provenance line does not say where the record came from: %q", kind)
	}
	if _, _, err := recorder.Verify(bytes.NewReader(got)); err != nil {
		t.Errorf("the extracted record does not verify: %v", err)
	}
}

// A flight recorder is the other thing a reader might be holding — the one the
// person who ran the session has on disk — and the same command has to take it,
// or the two of them are checking different things with different tools.
func TestARawRecordIsRecognisedAsItself(t *testing.T) {
	chain, _ := exportedSession(t)
	got, kind, err := recordIn(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("a flight recorder was not passed through unchanged")
	}
	if !strings.Contains(kind, "flight recorder") {
		t.Errorf("the provenance line does not say what the file is: %q", kind)
	}
	// Leading whitespace is what a file gains when somebody pastes it around.
	if _, _, err := recordIn(append([]byte("\n  \n"), chain...)); err != nil {
		t.Errorf("a record with leading whitespace was not recognised: %v", err)
	}
}

// A file that is not an export at all gets told so. "Verification failed" for a
// holiday photo is the wrong sentence, and it is the sentence that would make
// somebody believe their audit trail had been edited.
func TestAFileWithNoRecordIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		blob string
	}{
		{"not a report", "<html><body>hello</body></html>"},
		{"an export from before v1.0", "<h1>KelyfOS session report</h1><div class=\"chain ok\">intact</div>"},
		{"empty", ""},
	} {
		_, _, err := recordIn([]byte(tc.blob))
		if err == nil {
			t.Errorf("%s: a record was found in a file that has none", tc.name)
			continue
		}
		for _, want := range []string{"no KelyfOS record in this file", "before v1.0", "newer", "log --verify"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not mention %q: %v", tc.name, want, err)
			}
		}
	}
}

// Editing the page and leaving the record alone is the attack this feature
// cannot catch, and the honest thing is to know exactly what happens: the
// record still verifies, and the replay disagrees with the page. The product's
// claim is worded to match, so this test pins the wording as much as the
// behaviour.
func TestEditingThePageLeavesTheRecordVerifiableAndDisagreeing(t *testing.T) {
	_, page := exportedSession(t)
	doctored := bytes.Replace(page, []byte("echo hi"), []byte("echo ok"), 1)
	if bytes.Equal(page, doctored) {
		t.Fatal("the test did not manage to edit the page")
	}
	chain, _, err := recordIn(doctored)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recorder.Verify(bytes.NewReader(chain)); err != nil {
		t.Fatalf("editing the visible page broke the record, which it cannot: %v", err)
	}
	// What the reader is told to do: render the record itself and compare. The
	// record says what it always said, and the page in their hands does not.
	var honest bytes.Buffer
	if err := report.Render(&honest, "s1", chain); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(honest.Bytes(), []byte("echo hi")) {
		t.Error("the record followed the page's edit")
	}
	if !bytes.Contains(doctored, []byte("echo ok")) {
		t.Fatal("the doctored page does not carry the edit this test is about")
	}
	if !bytes.Contains(doctored, []byte("checks the record, not this rendering")) &&
		!bytes.Contains(doctored, []byte("not this rendering")) {
		t.Error("the page does not warn that verification covers the record rather than the rendering")
	}
}

// The chain head is the same string wherever it is printed: on the page, by the
// exporter, and by the verifier. A reader comparing two of them is doing the
// only cross-check an unsigned report supports, so the three must not drift.
func TestTheHeadIsTheSameEverywhereItIsPrinted(t *testing.T) {
	chain, page := exportedSession(t)
	_, head, err := recorder.Verify(bytes.NewReader(chain))
	if err != nil {
		t.Fatal(err)
	}
	if head == "" {
		t.Fatal("no head for a chain that verifies")
	}
	if !bytes.Contains(page, []byte(head)) {
		t.Error("the page does not print the head of the record it carries")
	}
	extracted, _, err := recordIn(page)
	if err != nil {
		t.Fatal(err)
	}
	_, again, err := recorder.Verify(bytes.NewReader(extracted))
	if err != nil || again != head {
		t.Errorf("the head differs between the record and the report: %s vs %s (%v)", head, again, err)
	}
}

// The export writes a file that its own verifier accepts. Obvious, and worth a
// test: the two halves are written in different packages, and every other
// assertion here would still pass if they agreed with each other about a format
// nothing else could read.
func TestExportProducesAFileItsOwnVerifierAccepts(t *testing.T) {
	chain, _ := exportedSession(t)
	root := t.TempDir()
	src := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(src, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "report.html")
	if err := exportSession("s1", src, dest); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := recordIn(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("the exported file does not carry the record it was made from")
	}
}
