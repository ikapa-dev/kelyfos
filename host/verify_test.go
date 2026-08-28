package main

import (
	"bytes"
	"crypto/ed25519"
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
	if _, err := report.Render(&buf, "s1", chain); err != nil {
		t.Fatal(err)
	}
	return chain, buf.Bytes()
}

// The same session, exported with a signature, for the checks that are about
// who exported a report rather than about what it records.
func signedExportedSession(t *testing.T) (chain []byte, page []byte) {
	t.Helper()
	chain, _ = exportedSession(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := report.RenderSigned(&buf, "s1", chain, priv); err != nil {
		t.Fatal(err)
	}
	return chain, buf.Bytes()
}

// The record a reader gets out of a report is the file the host wrote. Not
// equivalent to it, not a re-serialisation of it: the same bytes, because the
// digests are computed over the bytes.
func TestTheRecordSurvivesTheRoundTripThroughAReport(t *testing.T) {
	chain, page := exportedSession(t)
	got, kind, fromReport, err := recordIn(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("the record taken out of the report is not the record that went in")
	}
	if !fromReport {
		t.Error("a report was not recognised as one")
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
	got, kind, fromReport, err := recordIn(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("a flight recorder was not passed through unchanged")
	}
	if fromReport {
		t.Error("a raw flight recorder was treated as a report making claims about itself")
	}
	if !strings.Contains(kind, "flight recorder") {
		t.Errorf("the provenance line does not say what the file is: %q", kind)
	}
	// Leading whitespace is what a file gains when somebody pastes it around.
	if _, _, _, err := recordIn(append([]byte("\n  \n"), chain...)); err != nil {
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
	} {
		_, _, _, err := recordIn([]byte(tc.blob))
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
	chain, _, _, err := recordIn(doctored)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recorder.Verify(bytes.NewReader(chain)); err != nil {
		t.Fatalf("editing the visible page broke the record, which it cannot: %v", err)
	}
	// What the reader is told to do: render the record itself and compare. The
	// record says what it always said, and the page in their hands does not.
	var honest bytes.Buffer
	if _, err := report.Render(&honest, "s1", chain); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(honest.Bytes(), []byte("echo hi")) {
		t.Error("the record followed the page's edit")
	}
	if !bytes.Contains(doctored, []byte("echo ok")) {
		t.Fatal("the doctored page does not carry the edit this test is about")
	}
	for _, want := range []string{"The timeline below is not", "from the record by the exporter"} {
		if !bytes.Contains(doctored, []byte(want)) {
			t.Errorf("the page does not warn that its timeline is unchecked: missing %q", want)
		}
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
	extracted, _, _, err := recordIn(page)
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
	if err := exportSession("s1", src, dest, ""); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	got, _, _, err := recordIn(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("the exported file does not carry the record it was made from")
	}
}

// A page that lies about the record it carries is caught, which is the whole
// reason the page marks the values it states.
//
// The head is the one number the product tells a reader to write down and
// compare against a head they were given separately. A file that can quietly
// change it is a file that turns that instruction into a trap — so of all the
// numbers on the page, this is the one that cannot be left unchecked.
func TestAPageThatLiesAboutItsRecordIsCaught(t *testing.T) {
	chain, page := exportedSession(t)
	_, head, err := recorder.Verify(bytes.NewReader(chain))
	if err != nil {
		t.Fatal(err)
	}

	honest := report.ClaimsIn(page)
	if bad := honest.Disagree(head, 4, chain, ""); len(bad) > 0 {
		t.Fatalf("an untouched export disagrees with itself: %v", bad)
	}

	lie := bytes.Replace(page, []byte(head), bytes.Repeat([]byte("9"), 64), 1)
	if bytes.Equal(lie, page) {
		t.Fatal("the test did not manage to edit the stated head")
	}
	bad := report.ClaimsIn(lie).Disagree(head, 4, chain, "")
	if len(bad) == 0 {
		t.Error("a page stating a head the record does not support was accepted")
	}

	// Deleting the marker rather than changing the number is the neater edit,
	// and it must not be the one that works.
	stripped := bytes.Replace(page, []byte(` id="kelyfos-head"`), nil, 1)
	if bad := report.ClaimsIn(stripped).Disagree(head, 4, chain, ""); len(bad) == 0 {
		t.Error("deleting the marker switched the check off")
	}

	// The count and the session are checked on the same footing. The edits are
	// aimed at the marked elements rather than at the first occurrence of the
	// text: the session id is also in the <title>, and editing that changes
	// nothing the record can contradict.
	for _, edit := range [][2]string{
		{`<code id="kelyfos-events">4</code>`, `<code id="kelyfos-events">400</code>`},
		{`<span id="kelyfos-session">s1</span>`, `<span id="kelyfos-session">s2</span>`},
	} {
		doctored := bytes.Replace(page, []byte(edit[0]), []byte(edit[1]), 1)
		if bytes.Equal(doctored, page) {
			t.Fatalf("the page does not mark %q, so this test proves nothing", edit[0])
		}
		if bad := report.ClaimsIn(doctored).Disagree(head, 4, chain, ""); len(bad) == 0 {
			t.Errorf("a page edited %q was accepted", edit[0])
		}
	}
}

// A record cut short at its end verifies, and the product says so rather than
// implying it caught everything. This pins the behaviour the claim now matches:
// truncation there breaks nothing, because nothing after the cut exists to
// break.
func TestARecordCutShortAtItsEndStillVerifies(t *testing.T) {
	chain, _ := exportedSession(t)
	lines := bytes.SplitAfter(chain, []byte("\n"))
	short := bytes.Join(lines[:2], nil)

	n, head, err := recorder.Verify(bytes.NewReader(short))
	if err != nil {
		t.Fatalf("a truncated chain was rejected, so the documented limit is wrong: %v", err)
	}
	if n != 2 {
		t.Errorf("verified %d events, want 2", n)
	}
	_, full, _ := recorder.Verify(bytes.NewReader(chain))
	if head == full {
		t.Error("truncation did not change the head, so the head cannot distinguish them")
	}

	// And the observation the reader is given instead: this record does not end
	// where a finished session ends.
	if endsCleanly(short) {
		t.Error("a truncated record was reported as ending cleanly")
	}
	if !endsCleanly(chain) {
		t.Error("a session that ended was not reported as ending cleanly")
	}
}

// TestErasedSessionStillEndsCleanly is B5's direct repro: kelyfos sessions
// erase appends session.erasure AFTER session.end, so a session that
// closed perfectly cleanly and was later erased used to have endsCleanly
// look only at the last event — session.erasure — and report exactly the
// sentence a genuinely truncated record gets: "the chain cannot tell those
// apart." That is the wrong answer on precisely the records most likely to
// be scrutinised, and docs/retention.md's own claim that "kelyfos verify
// after an erasure reports the chain intact, the same as before" was false
// until this was fixed.
func TestErasedSessionStillEndsCleanly(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "erased-clean")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeCommandOutput, Data: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Erase(root, "erased-clean", "test"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	blob, err := os.ReadFile(recorder.Path(root, "erased-clean"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if events[len(events)-1].Type != recorder.TypeSessionErasure {
		t.Fatalf("last event is %q, want %q — this test needs an erased chain to mean anything",
			events[len(events)-1].Type, recorder.TypeSessionErasure)
	}
	if !endsCleanly(blob) {
		t.Error("an erased chain whose session actually ended cleanly was reported as possibly cut short")
	}
}

// An empty file is an empty flight recorder, which is what a process that died
// before its first append leaves behind — recorder.Open creates one. It used to
// be refused as "not a flight recorder", which sends its owner looking for the
// wrong problem: the file is exactly what it should be, and it is the *chain*
// that has nothing in it.
func TestAnEmptyFileIsAnEmptyRecordAndNotAMysteryFile(t *testing.T) {
	// The shapes a recorder actually leaves: a file with nothing in it. A file
	// of spaces is not one of them, and a verifier that shrugged at it would be
	// being lenient about a file that has been through something.
	for _, blob := range []string{"", "\n\n"} {
		chain, kind, fromReport, err := recordIn([]byte(blob))
		if err != nil {
			t.Fatalf("%q was not recognised as a flight recorder: %v", blob, err)
		}
		if fromReport || !strings.Contains(kind, "flight recorder") {
			t.Errorf("%q was classified as %q", blob, kind)
		}
		// And the chain rule then says the true thing about it.
		n, head, err := verifiedChain(chain)
		if err == nil {
			t.Errorf("%q verified as a chain: %d events, head %q", blob, n, head)
		} else if !strings.Contains(err.Error(), "nothing here to verify") {
			t.Errorf("%q refused for the wrong reason: %v", blob, err)
		}
	}
}

// A chain with events in it is not empty, and the rule must not swallow it.
func TestTheEmptyRuleDoesNotSwallowARealChain(t *testing.T) {
	chain, _ := exportedSession(t)
	n, head, err := verifiedChain(chain)
	if err != nil || n != 4 || head == "" {
		t.Errorf("a real chain was refused: %d events, head %q, %v", n, head, err)
	}
}

// A failed export leaves the destination alone.
//
// The regression this pins was mine: moving the parse inside Render put
// os.Create ahead of it, so a record with one unparseable line emptied whatever
// report was already at that path and then wrote nothing. A host killed
// mid-write is enough to produce such a record.
func TestAFailedExportDoesNotDestroyWhatWasAlreadyThere(t *testing.T) {
	chain, _ := exportedSession(t)
	root := t.TempDir()
	src := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(src, append(chain, []byte("NOT JSON AT ALL\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "report.html")
	const previous = "last week's report, which somebody may still need"
	if err := os.WriteFile(dest, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := exportSession("s1", src, dest, ""); err == nil {
		t.Fatal("an unparseable record exported without complaint")
	}
	if got := read(t, dest); got != previous {
		t.Errorf("the failed export destroyed the file that was there: %q", got)
	}
	// And it left nothing behind either.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".kelyfos-export-") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// The count the command prints is the count the page shows. It used to be
// recorder.Verify's own count, which is the length of the verified prefix — so
// on a broken chain the summary disagreed with the page it had just written,
// about that page.
func TestTheExportsCountIsThePagesCount(t *testing.T) {
	chain, _ := exportedSession(t)
	broken := bytes.Replace(chain, []byte(`"source":"host"`), []byte(`"source":"gues"`), 1)
	if bytes.Equal(broken, chain) {
		t.Fatal("the test did not manage to break the chain")
	}
	if n, _, err := recorder.Verify(bytes.NewReader(broken)); err == nil || n >= 4 {
		t.Fatalf("the fixture is not a mid-chain break: %d events, %v", n, err)
	}

	root := t.TempDir()
	src := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(src, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "report.html")
	if err := exportSession("s1", src, dest, ""); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if stated := report.ClaimsIn(page).Events; stated != "4" {
		t.Errorf("the page states %q events for a 4-event record", stated)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A page cannot name a signing key it was not signed with (P6-19).
//
// The exam found this by fuzzing the page's fields one at a time, which is how
// it should have been found and is not how it should have shipped. The report's
// banner prints the signing key's fingerprint and tells the reader it "means
// something only if you recognise the fingerprint from somewhere other than this
// page" — so it is the one value on the page a reader is instructed to act on.
// It was the one value nothing compared: swapping it for the fingerprint of a
// key the reader genuinely trusts left `kelyfos verify` reporting a fully clean
// result, and deleting its marker altogether passed where deleting any of the
// other three markers failed closed.
//
// What makes it a trust defect rather than a cosmetic one is the pairing: the
// page prints sha256(key) and `verify` prints the raw key hex, and no document
// bridges the two — so a reader who wanted to cross-check by hand had no
// documented way to do it either.
func TestAPageCannotNameASigningKeyItWasNotSignedWith(t *testing.T) {
	chain, page := signedExportedSession(t)
	_, head, err := recorder.Verify(bytes.NewReader(chain))
	if err != nil {
		t.Fatal(err)
	}
	real := report.SignatureIn(page).Fingerprint()
	if real == "" {
		t.Fatal("the fixture is not signed, so this test proves nothing")
	}

	if bad := report.ClaimsIn(page).Disagree(head, 4, chain, real); len(bad) > 0 {
		t.Fatalf("an untouched signed export disagrees with itself: %v", bad)
	}

	// The attack: keep the signature, swap the displayed fingerprint for one the
	// reader recognises. Nothing about the record changes.
	trusted := strings.Repeat("ab", 32)
	forged := bytes.Replace(page, []byte(real), []byte(trusted), 1)
	if bytes.Equal(forged, page) {
		t.Fatal("the test did not manage to edit the displayed fingerprint")
	}
	if bad := report.ClaimsIn(forged).Disagree(head, 4, chain, real); len(bad) == 0 {
		t.Error("a page naming a key it was not signed with was accepted — " +
			"which is the whole of what the fingerprint was for")
	}

	// And deleting the marker must not be the edit that works, on the same
	// footing as the other three.
	stripped := bytes.Replace(page, []byte(` id="kelyfos-fingerprint"`), nil, 1)
	if bad := report.ClaimsIn(stripped).Disagree(head, 4, chain, real); len(bad) == 0 {
		t.Error("deleting the fingerprint marker switched the check off")
	}
}
