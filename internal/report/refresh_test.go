package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// generatedStamp is renderView's own "generated <timestamp>" text, which
// ticks over with the wall clock — normalized out before comparing two pages
// rendered microseconds apart, so a comparison does not go flaky on the rare
// run that straddles a second boundary between the two calls.
var generatedStamp = regexp.MustCompile(`generated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC`)

func stripGenerated(s string) string { return generatedStamp.ReplaceAllString(s, "generated X") }

// P7-9: RenderRefreshable is the one place the exported page can be told to
// carry a <meta http-equiv="refresh"> tag, which is the whole mechanism that
// lets --refresh's atomic rewrites reach an already-open browser tab with no
// socket anywhere in the path. These tests are the RENDER checklist's own
// demand made concrete: the tag is a number computed in Go, present exactly
// when asked for and never otherwise.
func TestRenderRefreshableAddsTheMetaTagOnlyWhenAskedFor(t *testing.T) {
	events := []recorder.Event{ev(recorder.TypeSessionStart, ""), ev(recorder.TypeCommandStart, "")}
	chain := chainOf(t, events)

	var live bytes.Buffer
	if _, err := RenderRefreshable(&live, "s1", chain, nil, 5); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live.String(), `<meta http-equiv="refresh" content="5">`) {
		t.Errorf("refreshSeconds=5 did not produce the tag:\n%s", live.String())
	}

	var still bytes.Buffer
	if _, err := RenderRefreshable(&still, "s1", chain, nil, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(still.String(), `http-equiv="refresh"`) {
		t.Errorf("refreshSeconds=0 produced a refresh tag anyway:\n%s", still.String())
	}

	var signed bytes.Buffer
	if _, err := RenderSigned(&signed, "s1", chain, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(signed.String(), `http-equiv="refresh"`) {
		t.Errorf("an ordinary RenderSigned export carries a refresh tag:\n%s", signed.String())
	}
	// RenderSigned is documented as RenderRefreshable with refreshSeconds=0 —
	// the two must produce identical pages (modulo the "generated" timestamp,
	// which ticks over with the wall clock between the two calls), or one of
	// them is lying about being the other.
	if stripGenerated(signed.String()) != stripGenerated(still.String()) {
		t.Errorf("RenderSigned and RenderRefreshable(...,0) disagree:\nRenderSigned:\n%s\nRenderRefreshable:\n%s",
			signed.String(), still.String())
	}
}

// A negative refreshSeconds is not a longer interval, it is a caller's bug —
// and {{if .RefreshSeconds}} in the template is a non-zero check, so a raw
// negative number would render content="-5" if this clamp were missing.
func TestRenderRefreshableClampsANegativeIntervalToNoTag(t *testing.T) {
	chain := chainOf(t, []recorder.Event{ev(recorder.TypeSessionStart, "")})
	var buf bytes.Buffer
	if _, err := RenderRefreshable(&buf, "s1", chain, nil, -5); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `http-equiv="refresh"`) {
		t.Errorf("a negative refreshSeconds produced a refresh tag:\n%s", buf.String())
	}
}

// The human-readable note beside the tag only makes sense on a page that
// carries the tag — a static export claiming a tab will "reload itself" when
// nothing will ever rewrite it again would be exactly the kind of small,
// pointless lie this page's own design refuses everywhere else.
func TestRenderRefreshableNoteFollowsTheTag(t *testing.T) {
	chain := chainOf(t, []recorder.Event{ev(recorder.TypeSessionStart, "")})

	var live bytes.Buffer
	if _, err := RenderRefreshable(&live, "s1", chain, nil, 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live.String(), "reloads itself every 2s") {
		t.Errorf("the live note is missing when refreshSeconds > 0:\n%s", live.String())
	}

	var still bytes.Buffer
	if _, err := RenderSigned(&still, "s1", chain, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(still.String(), "reloads itself every") {
		t.Errorf("the live note appears on a page with no refresh tag:\n%s", still.String())
	}
}
