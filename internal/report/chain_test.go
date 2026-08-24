package report

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// The bytes that go in are the bytes that come out. Everything else in this
// feature rests on it: an event's digest is computed over the line as written,
// so a round trip that changed one byte would make a legitimate record report
// as tampered with.
func TestTheIslandRoundTripsByteForByte(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(""),
		[]byte("{}\n"),
		[]byte(`{"v":1,"data":"<script>&\"'"}` + "\n"),
		bytes.Repeat([]byte(`{"v":1,"pad":"aaaaaaaa"}`+"\n"), 500),
		{0x00, 0xff, 0xfe, '\n'}, // not UTF-8, and still evidence
	} {
		page := chainOpen + string(embedChain(raw)) + chainClose
		got, err := ExtractChain([]byte(page))
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("round trip changed the record:\n in %q\nout %q", raw, got)
		}
	}
}

// The island survives the template, including the characters the template would
// rather rewrite.
//
// This is the test that was missing when the island was first written, and its
// absence hid a real defect: html/template escapes `+` to `&#43;` in element
// text, `+` is an ordinary base64 character, and a round-trip test that never
// went through the template passed anyway. The record below is chosen to force
// both `+` and `/` into the encoding — `~` and `?` at the right offsets are what
// produce them — so the test fails if the payload is ever left to the escaper
// again.
func TestTheIslandSurvivesTheTemplate(t *testing.T) {
	e := ev(recorder.TypeFileWrite, "")
	e.Path = strings.Repeat("~?", 200)
	e.Bytes = 7
	chain := chainOf(t, []recorder.Event{e})

	if enc := string(embedChain(chain)); !strings.Contains(enc, "+") || !strings.Contains(enc, "/") {
		t.Fatalf("the fixture does not force the characters this test is about: + %v / %v",
			strings.Contains(enc, "+"), strings.Contains(enc, "/"))
	}

	var buf bytes.Buffer
	if err := Render(&buf, "s1", chain); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	if strings.Contains(page, "&#43;") {
		t.Error("the template escaped the island's + characters")
	}
	got, err := ExtractChain([]byte(page))
	if err != nil {
		t.Fatalf("the island did not survive rendering: %v", err)
	}
	if !bytes.Equal(got, chain) {
		t.Error("the record changed on its way through the template")
	}
	if _, _, err := recorder.Verify(bytes.NewReader(got)); err != nil {
		t.Errorf("a record that went through a report no longer verifies: %v", err)
	}
}

// The island is only ever base64 and newlines, which is the whole reason its
// payload is allowed to skip escaping. The argument is about the encoder, and an
// encoder can be changed, so it is pinned here rather than left in a comment.
func TestTheIslandIsOnlyEverBase64(t *testing.T) {
	e := ev(recorder.TypeCommandOutput, "")
	e.Call, e.Stream = "c1", "stdout"
	e.Data = base64.StdEncoding.EncodeToString(
		[]byte(`<script>alert(1)</script> & "quotes" 'and' <pre id="kelyfos-chain"> ~?~?`))
	page := render(t, []recorder.Event{e})

	start := strings.Index(page, chainOpen) + len(chainOpen)
	payload := page[start : start+strings.Index(page[start:], chainClose)]
	for i, r := range payload {
		ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' || r == '\n'
		if !ok {
			t.Fatalf("the island carries %q at offset %d — it is not base64 any more", r, i)
		}
	}
}

// A reader with no KelyfOS pulls the island out with sed and base64(1), and the
// island is wrapped, so whitespace must not matter. This is that path, done the
// way a person would do it by hand.
func TestTheIslandSurvivesBeingReflowedByHand(t *testing.T) {
	raw := bytes.Repeat([]byte(`{"v":1,"seq":1}`+"\n"), 40)
	payload := string(embedChain(raw))
	if !strings.Contains(payload, "\n") {
		t.Fatal("the island is not wrapped, so this test proves nothing")
	}
	for _, mangled := range []string{
		strings.ReplaceAll(payload, "\n", ""),
		strings.ReplaceAll(payload, "\n", "\r\n"),
		strings.ReplaceAll(payload, "\n", "\n   "),
		"\n\n" + payload + "\n  \n",
	} {
		got, err := ExtractChain([]byte(chainOpen + mangled + chainClose))
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if !bytes.Equal(got, raw) {
			t.Error("reflowing the island changed the record")
		}
	}
}

// Every way the extraction can fail says which one it is, because "verification
// failed" for a file that is not an export at all is the wrong sentence.
func TestExtractionRefusesRatherThanGuesses(t *testing.T) {
	island := chainOpen + string(embedChain([]byte("{}\n"))) + chainClose
	for _, tc := range []struct {
		name, page, want string
	}{
		{"not an export", "<html><body>hello</body></html>", "no KelyfOS record"},
		{"an export from before v1.0", "<h1>KelyfOS session report</h1>", "no KelyfOS record"},
		{"two records", island + island, "carries 2 embedded records"},
		{"never closed", chainOpen + "e30K", "never closed"},
		{"not base64", chainOpen + "not base64!!" + chainClose, "not readable"},
	} {
		_, err := ExtractChain([]byte(tc.page))
		if err == nil {
			t.Errorf("%s: extracted a record from a file that has none", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error is %q, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// A page with a second island hidden in a place a reader would not look — a
// command's recorded output — must not exist in the first place: html/template
// escapes it, so what lands in the file is text and not markup. This asserts
// the escaping rather than assuming it, because the extractor's "exactly one"
// rule is only as good as the guest's inability to write a second one.
func TestTheGuestCannotWriteASecondIsland(t *testing.T) {
	start := ev(recorder.TypeCommandStart, "")
	start.Call, start.Cmd, start.Via = "c1", []string{"cat", "forged"}, "exec"
	out := ev(recorder.TypeCommandOutput, "")
	out.Call, out.Stream = "c1", "stdout"
	out.Data = base64.StdEncoding.EncodeToString([]byte(chainOpen + "ZmFrZQo=" + chainClose))
	page := render(t, []recorder.Event{start, out})
	if n := strings.Count(page, chainOpen); n != 1 {
		t.Fatalf("%d islands in the page — recorded output reached the file as markup", n)
	}
	raw, err := ExtractChain([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if n, _, err := recorder.Verify(bytes.NewReader(raw)); err != nil || n != 2 {
		t.Errorf("the extracted record is not the session's: %d events, %v", n, err)
	}
}

// The page carries no verdict on itself. This is the defect P6-6 exists to fix:
// the export used to render the exporter's own conclusion as a green badge, and
// a reader had nothing to check it against.
func TestThePagePassesNoVerdictOnItself(t *testing.T) {
	page := render(t, []recorder.Event{ev(recorder.TypeSessionStart, "")})
	for _, gone := range []string{"audit chain intact", "events verified", "✓", "chain ok"} {
		if strings.Contains(page, gone) {
			t.Errorf("the page still certifies itself: found %q", gone)
		}
	}
	if !strings.Contains(page, "does not verify itself") {
		t.Error("the page does not say that it does not verify itself")
	}
	if !strings.Contains(page, "kelyfos verify") {
		t.Error("the page does not say how somebody else would check it")
	}
}

// The head printed on the page is the head of the record embedded in it. A page
// quoting a head from anywhere else would be the badge again, wearing a hex
// string.
func TestThePrintedHeadIsTheEmbeddedRecordsHead(t *testing.T) {
	page := render(t, []recorder.Event{
		ev(recorder.TypeSessionStart, ""),
		ev(recorder.TypeSessionEnd, ""),
	})
	raw, err := ExtractChain([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	_, head, err := recorder.Verify(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the record the page carries does not verify: %v", err)
	}
	if head == "" || !strings.Contains(page, head) {
		t.Errorf("the page does not print the head of the record it carries (%s)", head)
	}
}

// A broken chain still exports, still carries its record, and says the
// exporter's own check failed — with no head, because a head off a line nobody
// could check is a number a reader would quote.
func TestABrokenChainIsReportedAndStillCarried(t *testing.T) {
	good := chainOf(t, []recorder.Event{
		ev(recorder.TypeSessionStart, ""),
		ev(recorder.TypeCommandStart, ""),
	})
	broken := bytes.Replace(good, []byte(`"source":"host"`), []byte(`"source":"gues"`), 1)
	if bytes.Equal(good, broken) {
		t.Fatal("the test did not manage to break the chain")
	}
	var buf bytes.Buffer
	if err := Render(&buf, "s1", broken); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	if !strings.Contains(page, "exporter's own check of this record failed") {
		t.Error("a broken chain exported without saying so")
	}
	if !strings.Contains(page, "has been modified") {
		t.Error("the page does not say what was wrong")
	}
	raw, err := ExtractChain([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, broken) {
		t.Error("the page did not carry the record it was rendered from")
	}
}
