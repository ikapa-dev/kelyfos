package report

import (
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// P7-17/F20, the F9 rider: an `egress.attempt` refused for reason=foreign_peer
// carries who knocked in Event.Peer and nothing else — the request was never
// parsed, so there is no host and no port. Nothing rendered that field, so the
// exported report showed a blocked egress to an empty host and the one fact
// worth recording stayed in the chain.
func TestF20_TheReportSaysWhoTheRefusedForeignPeerWas(t *testing.T) {
	blocked := false
	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-28T10:00:00.000Z"},
		{Type: recorder.TypeEgressAttempt, TS: "2026-08-28T10:00:01.000Z",
			Allowed: &blocked, Reason: "foreign_peer", Peer: "127.0.0.1:54321"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-28T10:00:02.000Z"},
	}
	html := render(t, events)
	if !strings.Contains(html, "127.0.0.1:54321") {
		t.Error("the report does not say who connected to the proxy")
	}
	if !strings.Contains(html, "foreign_peer") {
		t.Error("the report does not say why the connection was refused")
	}
}

// The same on the lane view, which a team's report draws instead of the flat
// timeline. Two agents, so buildLanes produces lanes at all.
func TestF20_TheLaneViewSaysWhoTheRefusedForeignPeerWas(t *testing.T) {
	blocked := false
	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-28T10:00:00.000Z"},
		{Type: recorder.TypeSessionReady, Agent: "master", TS: "2026-08-28T10:00:01.000Z"},
		{Type: recorder.TypeSessionReady, Agent: "worker-1", TS: "2026-08-28T10:00:01.100Z"},
		{Type: recorder.TypeEgressAttempt, Agent: "worker-1", TS: "2026-08-28T10:00:02.000Z",
			Allowed: &blocked, Reason: "foreign_peer", Peer: "127.0.0.1:54321"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-28T10:00:03.000Z"},
	}
	html := render(t, events)
	if !strings.Contains(html, `class="lanes"`) {
		t.Fatal("the fixture did not produce a lane view")
	}
	if strings.Count(html, "127.0.0.1:54321") < 2 {
		t.Errorf("the lane view does not say who connected to the proxy (found %d occurrences, want the timeline's and the lane's)",
			strings.Count(html, "127.0.0.1:54321"))
	}
}

// The review's rider also said Event.Peer is "not SafeText'd anywhere in
// internal/report". This asserts the opposite, because it is the opposite: the
// template routes Row.Title, Row.Detail and every run-map label through the
// `safe` function (internal/report/report.go's FuncMap), so a value reaching a
// page through any of them is sanitised at render whether or not the code that
// built the row called safe itself. Pinned as a test rather than argued in a
// commit message, because "it is covered somewhere else" is exactly the claim
// that should have to fail loudly when it stops being true.
func TestF20_APeerCarryingAControlByteNeverReachesThePageRaw(t *testing.T) {
	const hostile = "\x1b[2J\x1b[3Jpwned"
	blocked := false
	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-28T10:00:00.000Z"},
		{Type: recorder.TypeSessionReady, Agent: "master", TS: "2026-08-28T10:00:01.000Z"},
		{Type: recorder.TypeSessionReady, Agent: "worker-1", TS: "2026-08-28T10:00:01.100Z"},
		{Type: recorder.TypeEgressAttempt, Agent: "worker-1", TS: "2026-08-28T10:00:02.000Z",
			Allowed: &blocked, Reason: "foreign_peer", Peer: hostile},
		{Type: recorder.TypeTeamMessage, Agent: "master", Peer: hostile, Kind: "send",
			Bytes: 3, TS: "2026-08-28T10:00:03.000Z"},
		{Type: recorder.TypeTeamStore, Agent: "master", Peer: hostile, Kind: "get",
			Outcome: "refused", Reason: "denied", TS: "2026-08-28T10:00:04.000Z"},
		{Type: recorder.TypeTeamSpawn, Agent: "master", Peer: hostile, Kind: "spawn",
			Outcome: "delivered", TS: "2026-08-28T10:00:05.000Z"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-28T10:00:06.000Z"},
	}
	html := render(t, events)
	// The fixture reached the page at all, escaped — without this the check
	// below would pass on an empty report.
	if !strings.Contains(html, `pwned`) {
		t.Fatal("the hostile peer never reached the page; this test would pass vacuously")
	}
	for i := 0; i < len(html); i++ {
		if isRawControlByte(html[i]) {
			t.Fatalf("a raw control byte reached the page at offset %d: %q",
				i, html[max(0, i-40):min(len(html), i+40)])
		}
	}
}
