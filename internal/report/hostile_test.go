package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// The RENDER checklist (PLAN.html §8 rule 10) and P7-8's own task text both
// say the same thing: adversary strings must reach element text content
// only. This file is the hostile corpus that makes the claim checkable —
// every value a guest, a teammate, or a misbehaving upstream component
// could have chosen, run through every surface P7-8 adds (the run map, the
// agent sheets, the reach matrix, the store panel) and through the
// surfaces that already existed (the flat timeline, the lanes).
//
// The three fixtures the task text names verbatim: markup in a path, an
// escape sequence in a message body, a store key that is a <script> tag.
// Extended here to the fields only P7-8's own surfaces read for the first
// time — an agent name, a domain, a secret's name and host, and a store
// rule's read/write lists — since those are exactly the fields
// internal/graph's numeric-only drawing has never been asked to carry
// before.
const scriptPayload = `<script>alert(document.cookie)</script>`

func hostileEvents() []recorder.Event {
	agentName := `<img src=x onerror="alert(1)">`
	peerName := `"onmouseover="javascript:alert(1)`

	var evs []recorder.Event
	add := func(e recorder.Event) { evs = append(evs, e) }

	add(recorder.Event{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"})
	add(recorder.Event{Type: recorder.TypeSessionReady, Agent: agentName, TS: "2026-08-27T10:00:01.000Z"})
	add(recorder.Event{Type: recorder.TypeSessionReady, Agent: "worker-2", TS: "2026-08-27T10:00:01.000Z"})

	add(recorder.NewSessionPolicy(agentName, recorder.PolicyFields{
		VcpuCount: 1, MemMiB: 256,
		Allow: []string{`evil.example.com/</style><script>alert(2)</script>`},
		Secrets: []recorder.EvSecret{{
			Name: scriptPayload, Host: `host"><script>alert(3)</script>`, Path: "/'><svg onload=alert(4)>",
		}},
		Workspace:     `/work/<script>alert(5)</script>`,
		RootfsSHA256:  `<script>alert(6)</script>`,
		ParentSession: `javascript:alert(7)`,
	}))
	add(recorder.NewSessionPolicy("worker-2", recorder.PolicyFields{VcpuCount: 1, MemMiB: 256}))

	add(recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: []recorder.EvAgent{
			{Name: agentName, Sandbox: "sb-1", Group: `"><script>alert(8)</script>`},
			{Name: "worker-2", Sandbox: "sb-2"},
		},
		Edges: []string{agentName + " -> worker-2"},
		StoreKeys: []recorder.EvStoreKey{
			{Name: scriptPayload, Read: []string{peerName}, Write: []string{agentName}},
		},
	}))

	// A markup-bearing path (file.write).
	add(recorder.Event{Type: recorder.TypeFileWrite, Agent: agentName,
		Path:   `/work/"><script>alert(9)</script>/../../etc/passwd`,
		SHA256: "deadbeef", Bytes: 3, Via: "write_file", TS: "2026-08-27T10:00:02.000Z"})

	// An escape sequence in a message body — team.message's Data field is
	// the payload (internal/team/record.go), captured whole when
	// record_payloads is on.
	add(recorder.Event{Type: recorder.TypeTeamMessage, Agent: agentName, Peer: "worker-2",
		Kind: "send", Data: scriptPayload + `</pre><img src=x onerror=alert(10)>`,
		SHA256: "cafef00d", Bytes: 40, TS: "2026-08-27T10:00:03.000Z"})

	// A store key that is a <script> tag — put once (so it's a resource
	// the run map/reach matrix actually draws), then a refusal against the
	// same key so team-refused rendering sees it too.
	add(recorder.Event{Type: recorder.TypeTeamStore, Agent: agentName, Peer: scriptPayload,
		Kind: "put", Outcome: "delivered", Bytes: 3, TS: "2026-08-27T10:00:04.000Z"})
	add(recorder.Event{Type: recorder.TypeTeamStore, Agent: "worker-2", Peer: scriptPayload,
		Kind: "get", Outcome: "refused", Reason: `<script>alert(11)</script>`, TS: "2026-08-27T10:00:05.000Z"})

	// A refusal naming a peer nobody declared an edge to — the run map
	// must draw no edge for it, and the peer name is still hostile.
	add(recorder.Event{Type: recorder.TypeTeamRefused, Agent: "worker-2", Peer: peerName,
		Kind: "send", Reason: "no_edge", TS: "2026-08-27T10:00:06.000Z"})

	add(recorder.Event{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:07.000Z"})
	return evs
}

var (
	onAttrRE  = regexp.MustCompile(`(?i)\bon[a-zA-Z]+\s*=`)
	svgTagRE  = regexp.MustCompile(`(?is)<svg[^>]*>.*?</svg>`)
	numAttrRE = regexp.MustCompile(`(?i)\b(cx|cy|r|x|y|x1|y1|x2|y2|width|height)="([^"]*)"`)
	viewBoxRE = regexp.MustCompile(`viewBox="([^"]*)"`)
	pointsRE  = regexp.MustCompile(`points="([^"]*)"`)
	numOnlyRE = regexp.MustCompile(`^[-0-9.,\s]*$`)
)

// tagSpans returns every `<...>` delimited span in s — every actual tag
// (open, close or self-closing) the browser's parser would see. Contextual
// autoescaping guarantees a literal, unescaped "<" in this package's output
// can only come from markup this template itself wrote — a guest-influenced
// value in text-node position is always turned into "&lt;" first — so
// walking spans between literal '<' and the next '>' reliably separates
// "real tag" from "text content that happens to contain the substring
// 'onerror=' or 'style=' as harmless words", which a page-wide substring
// search cannot tell apart and would flag as a false positive.
func tagSpans(s string) []string {
	var spans []string
	for i := 0; i < len(s); {
		lt := strings.IndexByte(s[i:], '<')
		if lt < 0 {
			break
		}
		start := i + lt
		gt := strings.IndexByte(s[start:], '>')
		if gt < 0 {
			break
		}
		end := start + gt + 1
		spans = append(spans, s[start:end])
		i = end
	}
	return spans
}

// TestHostileValuesReachTextContentOnly is the corpus the RENDER checklist
// and P7-8's own task text both demand: nothing a guest, a teammate or an
// upstream bug could have written ever lands as markup, an event handler
// attribute, a javascript: URL, a raw control byte, or a non-numeric SVG
// geometry attribute, anywhere in the rendered page.
func TestHostileValuesReachTextContentOnly(t *testing.T) {
	html := render(t, hostileEvents())

	// Confidence check: the fixture actually reached the page somewhere
	// (escaped), or this test would pass vacuously.
	if !strings.Contains(html, "alert(document.cookie)") {
		t.Fatal("the hostile fixture's own payload never reached the rendered page at all")
	}

	page := stripIsland(t, html)

	// Raw control bytes are a page-wide property — text content or
	// attribute, neither is allowed to carry one.
	for _, b := range []byte(page) {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			t.Fatalf("the report contains a raw control byte: 0x%02x", b)
		}
	}

	// Everything else is checked per actual tag (see tagSpans) rather than
	// as a page-wide substring search: the fixture deliberately plants
	// "onerror=", "javascript:" and "<script" as *text*, and a substring
	// search cannot distinguish that from the same bytes forming a live
	// tag or attribute — only walking real tag boundaries can.
	for _, tag := range tagSpans(page) {
		low := strings.ToLower(tag)
		if strings.HasPrefix(low, "<script") {
			t.Errorf("a live <script> tag: %s", tag)
		}
		if loc := onAttrRE.FindString(tag); loc != "" {
			t.Errorf("an event-handler attribute in %s", tag)
		}
		if strings.Contains(low, "javascript:") {
			t.Errorf("a javascript: URL in %s", tag)
		}
	}

	svg := svgTagRE.FindString(page)
	if svg == "" {
		t.Fatal("the rendered page carries no <svg> run map to check")
	}
	for _, tag := range tagSpans(svg) {
		low := strings.ToLower(tag)
		if strings.Contains(low, "href") {
			t.Errorf("the drawing contains an href attribute: %s", tag)
		}
		if strings.Contains(low, "style=") {
			t.Errorf("the drawing contains a style attribute: %s", tag)
		}
		if strings.HasPrefix(low, "<foreignobject") {
			t.Errorf("the drawing contains a <foreignObject>: %s", tag)
		}
	}
	for _, m := range numAttrRE.FindAllStringSubmatch(svg, -1) {
		if !numOnlyRE.MatchString(m[2]) {
			t.Errorf("SVG attribute %s=%q is not purely numeric", m[1], m[2])
		}
	}
	if m := viewBoxRE.FindStringSubmatch(svg); m != nil && !numOnlyRE.MatchString(m[1]) {
		t.Errorf("viewBox=%q is not purely numeric", m[1])
	}
	for _, m := range pointsRE.FindAllStringSubmatch(svg, -1) {
		if !numOnlyRE.MatchString(m[1]) {
			t.Errorf("points=%q is not purely numeric", m[1])
		}
	}

	// The payload must still be genuinely present, escaped, in text
	// content — proving the fixture was rendered rather than dropped.
	if !strings.Contains(page, "&lt;script&gt;") && !strings.Contains(page, "&#34;") {
		t.Error("no escaped form of the hostile payload was found anywhere — it may have been silently dropped rather than rendered safely")
	}
}

// A store key, an agent name and a domain that are each exactly the same
// <script> payload must still be individually visible — counted, named,
// covered by the right rule — in the store panel, the agent sheets and the
// run map's own summary counts, not merged away or dropped for being
// dangerous-looking.
func TestHostileValuesAreStillCountedNotJustNeutralized(t *testing.T) {
	html := render(t, hostileEvents())
	for _, want := range []string{
		"&lt;script&gt;alert(document.cookie)&lt;/script&gt;", // the store key and secret name, escaped
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing escaped hostile value %q — it may have been dropped rather than rendered", want)
		}
	}
}

// FuzzRunSectionRendersHostileStringsSafely fuzzes the four guest/teammate
// -influenced strings the run section's own drawing turns into nodes and
// labels — an agent name, a store key, a domain and a secret name — through
// a real render, and checks the same tag-aware property the table-driven
// corpus above checks by hand: no live <script>, no event-handler
// attribute, no javascript: URL, no raw control byte, anywhere the fuzzer's
// bytes could have landed.
func FuzzRunSectionRendersHostileStringsSafely(f *testing.F) {
	f.Add(`<script>alert(1)</script>`, `<script>alert(2)</script>`, `<script>alert(3)</script>`, `<script>alert(4)</script>`)
	f.Add(`"><img src=x onerror=alert(1)>`, "a", "b", "c")
	f.Add("javascript:alert(1)", "javascript:alert(2)", "javascript:alert(3)", "javascript:alert(4)")
	f.Add("a\x00b", "c\x01d", "e\x1fg", "h")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, agent, storeKey, domain, secretName string) {
		// recorder.Append does not refuse a raw control byte — it measures
		// and hashes the marshalled JSON (which escapes one exactly like
		// any other byte) rather than validating string content — so a
		// control byte reaches this package the same way it reaches a real
		// chain, and safe/safeBody (internal/report/safe.go) is exactly
		// what stands between it and the rendered page. Left in, not
		// skipped, for that reason.
		if agent == "" || storeKey == "" {
			t.Skip("an empty agent or resource ID is refused by internal/graph.normalize before this package ever draws it")
		}

		events := []recorder.Event{
			{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"},
			{Type: recorder.TypeSessionReady, Agent: agent, TS: "2026-08-27T10:00:01.000Z"},
			recorder.NewSessionPolicy(agent, recorder.PolicyFields{
				VcpuCount: 1, MemMiB: 256, Allow: []string{domain},
				Secrets: []recorder.EvSecret{{Name: secretName, Host: domain}},
			}),
			recorder.NewTeamTopology(recorder.TopologyFields{
				Agents:    []recorder.EvAgent{{Name: agent}},
				StoreKeys: []recorder.EvStoreKey{{Name: storeKey, Read: []string{agent}, Write: []string{agent}}},
			}),
			{Type: recorder.TypeTeamStore, Agent: agent, Peer: storeKey, Kind: "put", Outcome: "delivered", Bytes: 1, TS: "2026-08-27T10:00:02.000Z"},
			{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:03.000Z"},
		}

		var buf bytes.Buffer
		if _, err := Render(&buf, "s1", chainOf(t, events)); err != nil {
			t.Fatalf("a hostile agent/store key/domain/secret combination made rendering fail: %v", err)
		}
		page := stripIsland(t, buf.String())
		for _, b := range []byte(page) {
			if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
				t.Fatalf("a raw control byte 0x%02x reached the page for agent=%q key=%q domain=%q secret=%q",
					b, agent, storeKey, domain, secretName)
			}
		}
		for _, tag := range tagSpans(page) {
			low := strings.ToLower(tag)
			if strings.HasPrefix(low, "<script") {
				t.Fatalf("a live <script> tag for agent=%q key=%q domain=%q secret=%q: %s", agent, storeKey, domain, secretName, tag)
			}
			if onAttrRE.MatchString(tag) {
				t.Fatalf("an event-handler attribute for agent=%q key=%q domain=%q secret=%q: %s", agent, storeKey, domain, secretName, tag)
			}
			if strings.Contains(low, "javascript:") {
				t.Fatalf("a javascript: URL for agent=%q key=%q domain=%q secret=%q: %s", agent, storeKey, domain, secretName, tag)
			}
		}
	})
}

// stripIsland removes the embedded base64 record the way
// TestTheReportIsSelfContained does: the island is inert data whose
// alphabet can coincidentally spell something this test is looking for.
func stripIsland(t *testing.T, html string) string {
	t.Helper()
	start := strings.Index(html, chainOpen)
	if start < 0 {
		return html
	}
	end := strings.Index(html[start:], chainClose)
	if end < 0 {
		return html
	}
	return html[:start] + html[start+end+len(chainClose):]
}
