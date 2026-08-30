package report

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// isRawControlByte is every byte-checking loop's own copy of safe.go's
// isDangerousControl, restated on a byte rather than a rune (a page is
// scanned as raw bytes here, not decoded runes) — including 0x7f, which
// safe.go's own comment explicitly claims to handle and an earlier version
// of these loops did not check for.
func isRawControlByte(b byte) bool {
	if b == '\t' || b == '\n' || b == '\r' {
		return false
	}
	return b < 0x20 || b == 0x7f
}

// isDangerousRune is the same restatement one level up, on a decoded rune, for
// the half of safe.go's predicate a byte loop structurally cannot see
// (P7-17/F1): a right-to-left override is three bytes of UTF-8, none of them a
// control byte, and it reorders how the whole line renders. Kept beside the
// byte loop rather than replacing it, because the byte loop is what catches an
// invalid-UTF-8 stray that never decodes to a rune at all.
func isDangerousRune(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r < 0x20 || r == 0x7f || !unicode.IsPrint(r)
}

// The RENDER checklist (CONTRIBUTING.md, "How a change is verified") and P7-8 both
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

// bidiPayload is the Trojan Source fixture (P7-17/F1): U+202E, the
// right-to-left override, in front of a word that then renders as
// "acceptable" and compares as its reverse. Every other fixture in this file
// is markup or an ASCII control byte, which is exactly why the Cf category
// went unnoticed until the review named it.
const bidiPayload = "\u202eelbatpecca"

func hostileEvents() []recorder.Event {
	agentName := `<img src=x onerror="alert(1)">`
	peerName := `"onmouseover="javascript:alert(1)`
	// The reviewer's own proof-of-concept: an OSC title-set escape sequence,
	// plus SOH/US/DEL for broader C0-range coverage. \x1b and \x07 are what
	// actually rewrite a terminal's title bar; the rest are here so any one
	// of safe.go's blocked bytes has a real carrier in this corpus.
	controlPayload := "\x1b]0;pwned\x07 normal text stays readable \x01\x1f\x7f end"

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

	// A REAL control/ANSI byte sequence, not HTML markup — safeBody's own
	// reason to exist, and its own review's exact proof-of-concept: an OSC
	// title-set escape (`\x1b]0;pwned\x07`) plus a scattering of other C0
	// bytes and DEL. Without a fixture that actually puts one of these into
	// Output/Data, safeBody could be silently reverted to a no-op and
	// nothing in this file would notice — every other fixture here is HTML
	// escaping, which only exercises safe. Routed through both surfaces
	// safeBody covers: a command's captured output, and a message body.
	add(recorder.Event{Type: recorder.TypeCommandStart, Agent: agentName,
		Call: "c1", Cmd: []string{"echo", "hi"}, Via: "exec", TS: "2026-08-27T10:00:03.100Z"})
	add(recorder.Event{Type: recorder.TypeCommandOutput, Agent: agentName,
		Call: "c1", Stream: "stdout",
		Data: base64.StdEncoding.EncodeToString([]byte(controlPayload)),
		TS:   "2026-08-27T10:00:03.200Z"})
	exitCode := 0
	add(recorder.Event{Type: recorder.TypeCommandExit, Agent: agentName,
		Call: "c1", Code: &exitCode, TS: "2026-08-27T10:00:03.300Z"})

	add(recorder.Event{Type: recorder.TypeTeamMessage, Agent: "worker-2", Peer: agentName,
		Kind: "reply", Data: controlPayload,
		SHA256: "f00dbaad", Bytes: len(controlPayload), TS: "2026-08-27T10:00:03.400Z"})

	// P7-17/F1: the same corpus, in the Trojan Source shape rather than the
	// markup one. A right-to-left override reorders how a line renders
	// without changing a byte of its logical content, so a reader of this
	// report sees a command, a key and a body that are not the ones the
	// record holds — and until F1 widened the predicate to unicode.IsPrint,
	// every fixture in this file was ASCII and nothing here would have
	// noticed. Routed through all three shapes the review named: a store key,
	// a command, and a body.
	add(recorder.Event{Type: recorder.TypeCommandStart, Agent: agentName,
		Call: "c2", Cmd: []string{"rm", "-rf", "/work/" + bidiPayload},
		Via: "exec", TS: "2026-08-27T10:00:03.500Z"})
	add(recorder.Event{Type: recorder.TypeCommandOutput, Agent: agentName,
		Call: "c2", Stream: "stdout",
		Data: base64.StdEncoding.EncodeToString([]byte("removed " + bidiPayload + "\n")),
		TS:   "2026-08-27T10:00:03.600Z"})
	add(recorder.Event{Type: recorder.TypeCommandExit, Agent: agentName,
		Call: "c2", Code: &exitCode, TS: "2026-08-27T10:00:03.700Z"})
	add(recorder.Event{Type: recorder.TypeTeamStore, Agent: agentName, Peer: bidiPayload,
		Kind: "put", Outcome: "delivered", Bytes: 9, TS: "2026-08-27T10:00:03.800Z"})
	add(recorder.Event{Type: recorder.TypeTeamMessage, Agent: agentName, Peer: "worker-2",
		Kind: "send", Data: "the change is " + bidiPayload,
		SHA256: "b1d1b1d1", Bytes: 24, TS: "2026-08-27T10:00:03.900Z"})
	add(recorder.Event{Type: recorder.TypeEgressAttempt, Agent: agentName,
		Host: bidiPayload + ".example.com", Port: 443, Mode: "tunnelled",
		Reason: "not_in_allowlist", TS: "2026-08-27T10:00:03.950Z"})

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
	// attribute, neither is allowed to carry one. 0x7f (DEL) is checked
	// alongside the C0 range: safe.go's own isDangerousControl treats it
	// the same as a control byte, and a check that only covered < 0x20
	// would miss a regression there.
	for _, b := range []byte(page) {
		if isRawControlByte(b) {
			t.Fatalf("the report contains a raw control byte: 0x%02x", b)
		}
	}
	// And the rune-level half of the same predicate (P7-17/F1): every fixture
	// in this file was ASCII until the bidi ones above, so a byte loop was the
	// whole check and the Cf category went unseen.
	for _, r := range page {
		if isDangerousRune(r) {
			t.Fatalf("the report contains U+%04X, which safe.go's own predicate rejects", r)
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
	// P7-17/F1: the Trojan Source shape, in all four fields at once.
	f.Add(bidiPayload, bidiPayload, bidiPayload+".example.com", bidiPayload)
	f.Add("worker\u2068-1", "findings/\u2069", "exam\u200bple.com", "TOKEN\u00ad")

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
			if isRawControlByte(b) {
				t.Fatalf("a raw control byte 0x%02x reached the page for agent=%q key=%q domain=%q secret=%q",
					b, agent, storeKey, domain, secretName)
			}
		}
		for _, r := range page {
			if isDangerousRune(r) {
				t.Fatalf("U+%04X reached the page for agent=%q key=%q domain=%q secret=%q",
					r, agent, storeKey, domain, secretName)
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

// Review finding 1: session.policy and the earlier session.ready/
// session.start/session.end fields all come off the guest's own boot
// handshake or a host-side reason string — but safe.go's own doc comment
// claimed "the two template functions every guest-influenced value in
// reportHTML is routed through" before Image, Arch, Kernel, Supervisor and
// EndReason actually were. All five in one fixture, with the reviewer's
// own proof-of-concept payload (an OSC title-set escape) plus HTML markup,
// so a regression here shows up as either a raw control byte or a live
// tag reaching the page.
func TestSummaryHeaderFieldsRenderSafely(t *testing.T) {
	hostile := "\x1b]0;pwned\x07<script>alert(1)</script>"
	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, Image: hostile, Arch: hostile, TS: "2026-08-27T10:00:00.000Z"},
		{Type: recorder.TypeSessionReady, Kernel: hostile, Supervisor: hostile, TS: "2026-08-27T10:00:01.000Z"},
		{Type: recorder.TypeResourceTimeout, Budget: hostile, TS: "2026-08-27T10:00:01.500Z"},
		{Type: recorder.TypeSessionEnd, Reason: hostile, TS: "2026-08-27T10:00:02.000Z"},
	}
	html := render(t, events)
	page := stripIsland(t, html)

	for _, b := range []byte(page) {
		if isRawControlByte(b) {
			t.Fatalf("a raw control byte 0x%02x reached the page via a session header field", b)
		}
	}
	for _, tag := range tagSpans(page) {
		if strings.HasPrefix(strings.ToLower(tag), "<script") {
			t.Errorf("a live <script> tag from a session header field: %s", tag)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the hostile header payload never appeared, escaped, anywhere — it may have been dropped rather than rendered")
	}
}

// The one guest-influenced field the run section itself can carry outside
// the map/sheets/matrix/store panel proper: RunNote, populated from
// internal/graph's own error text when a chain is too inconsistent to
// draw (review finding 5). Tested directly against the template, the way
// TestSummaryHeaderFieldsRenderSafely tests View's other string fields,
// rather than by trying to manufacture a real graph.Layout failure.
func TestRunNoteRendersSafely(t *testing.T) {
	v := View{RunNote: `<script>alert(1)</script>` + "\x1b]0;pwned\x07"}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, b := range []byte(html) {
		if isRawControlByte(b) {
			t.Fatalf("a raw control byte 0x%02x reached the page via RunNote", b)
		}
	}
	for _, tag := range tagSpans(html) {
		if strings.HasPrefix(strings.ToLower(tag), "<script") {
			t.Errorf("a live <script> tag from RunNote: %s", tag)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("RunNote's escaped form never appeared — it may have been dropped rather than rendered")
	}
}

// A hostile SessionID — the caller-supplied argument to Render, not
// anything folded from the chain — goes through the same {{safe}} the
// review asked for (finding 1). Tested with a direct Render call since the
// shared render(t, events) helper always passes the fixed "s1".
func TestHostileSessionIDRendersSafely(t *testing.T) {
	hostile := "\x1b]0;pwned\x07<script>alert(1)</script>"
	events := []recorder.Event{ev(recorder.TypeSessionStart, "")}
	var buf bytes.Buffer
	if _, err := Render(&buf, hostile, chainOf(t, events)); err != nil {
		t.Fatal(err)
	}
	page := stripIsland(t, buf.String())
	for _, b := range []byte(page) {
		if isRawControlByte(b) {
			t.Fatalf("a raw control byte 0x%02x reached the page via SessionID", b)
		}
	}
	for _, tag := range tagSpans(page) {
		if strings.HasPrefix(strings.ToLower(tag), "<script") {
			t.Errorf("a live <script> tag from SessionID: %s", tag)
		}
	}
}

// Review finding 6: a domain and a store key sharing one literal name must
// draw as two distinct nodes of the right kinds, not collapse into one —
// addRes used to dedupe on ResourceID alone, with no Kind folded into
// identity, so whichever of the two addRes saw second silently vanished
// and the first kept the wrong label for it.
func TestDomainAndStoreKeySharingALiteralNameStayDistinct(t *testing.T) {
	const shared = "shared.example"
	events := []recorder.Event{
		{Type: recorder.TypeSessionReady, Agent: "alice", TS: "2026-08-27T10:00:00.000Z"},
		recorder.NewSessionPolicy("alice", recorder.PolicyFields{
			VcpuCount: 1, MemMiB: 1, Allow: []string{shared},
		}),
		recorder.NewTeamTopology(recorder.TopologyFields{
			Agents:    []recorder.EvAgent{{Name: "alice"}},
			StoreKeys: []recorder.EvStoreKey{{Name: shared, Read: []string{"alice"}, Write: []string{"alice"}}},
		}),
		{Type: recorder.TypeTeamStore, Agent: "alice", Peer: shared, Kind: "put", Outcome: "delivered", Bytes: 1, TS: "2026-08-27T10:00:01.000Z"},
	}
	d := digest.Walk(events)
	sec := buildRunSection(d)
	if sec.Note != "" {
		t.Fatalf("run section could not be built: %s", sec.Note)
	}
	if sec.Map == nil {
		t.Fatal("no run map for a team with a domain and a store key")
	}
	if sec.Map.DomainCount != 1 || sec.Map.StoreCount != 1 {
		t.Errorf("DomainCount=%d StoreCount=%d, want exactly one of each — "+
			"a domain and a store key named %q must not collapse into one node",
			sec.Map.DomainCount, sec.Map.StoreCount, shared)
	}
	var sawDomain, sawStore bool
	for _, n := range sec.Map.Nodes {
		if n.Label != shared {
			continue
		}
		switch n.Kind {
		case "domain":
			sawDomain = true
		case "store":
			sawStore = true
		default:
			t.Errorf("a node labelled %q has kind %q, want domain or store", shared, n.Kind)
		}
	}
	if !sawDomain {
		t.Error("no domain node labelled " + shared)
	}
	if !sawStore {
		t.Error("no store node labelled " + shared)
	}
}

// Phase 7's own exit checkpoint (acceptance item 8) names three fixtures
// this file did not yet have, none of them a new escaping mechanism — a key
// at the documented 1 KiB ceiling, a 64-character agent name, and a session
// whose aggregate size is around 200 MB. All three exercise safe/safeBody
// and html/template's own contextual escaping exactly the way every fixture
// above does; they are here because length and aggregate scale are their
// own dimension a single short adversarial string does not cover — a
// truncation, an off-by-one in a length-prefixed buffer, or a fast path that
// skips escaping past some size would all be invisible to the fixtures
// above and visible to these.

// A store key name at exactly docs/teams.md §3's own ceiling ("a key at
// most 1 KiB"), built from scriptPayload plus padding rather than a
// hand-counted literal so the length is right even if scriptPayload's own
// text changes. Run through the store panel, the run map and the reach
// matrix — every surface that draws a store key.
func TestOneKiBStoreKeyRendersSafely(t *testing.T) {
	const storeKeyCeiling = 1024
	if len(scriptPayload) > storeKeyCeiling {
		t.Fatal("scriptPayload no longer fits under the 1 KiB ceiling this fixture assumes")
	}
	hostileKey := scriptPayload + strings.Repeat("k", storeKeyCeiling-len(scriptPayload))
	if len(hostileKey) != storeKeyCeiling {
		t.Fatalf("fixture key is %d bytes, want exactly %d", len(hostileKey), storeKeyCeiling)
	}

	events := []recorder.Event{
		{Type: recorder.TypeSessionReady, Agent: "alice", TS: "2026-08-27T10:00:00.000Z"},
		recorder.NewSessionPolicy("alice", recorder.PolicyFields{VcpuCount: 1, MemMiB: 256}),
		recorder.NewTeamTopology(recorder.TopologyFields{
			Agents:    []recorder.EvAgent{{Name: "alice"}},
			StoreKeys: []recorder.EvStoreKey{{Name: hostileKey, Read: []string{"alice"}, Write: []string{"alice"}}},
		}),
		{Type: recorder.TypeTeamStore, Agent: "alice", Peer: hostileKey, Kind: "put", Outcome: "delivered", Bytes: 1, TS: "2026-08-27T10:00:01.000Z"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:02.000Z"},
	}
	html := render(t, events)
	if !strings.Contains(html, "alert(document.cookie)") {
		t.Fatal("the 1 KiB key's payload never reached the rendered page at all")
	}
	page := stripIsland(t, html)
	for _, b := range []byte(page) {
		if isRawControlByte(b) {
			t.Fatalf("a raw control byte 0x%02x reached the page via a 1 KiB store key", b)
		}
	}
	for _, tag := range tagSpans(page) {
		low := strings.ToLower(tag)
		if strings.HasPrefix(low, "<script") {
			t.Errorf("a live <script> tag from a 1 KiB store key: %s", tag)
		}
		if onAttrRE.MatchString(tag) {
			t.Errorf("an event-handler attribute from a 1 KiB store key: %s", tag)
		}
		if strings.Contains(low, "javascript:") {
			t.Errorf("a javascript: URL from a 1 KiB store key: %s", tag)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(document.cookie)&lt;/script&gt;") {
		t.Error("the 1 KiB key's escaped payload never appeared — it may have been truncated or dropped rather than rendered")
	}
}

// A 64-character agent name — long enough to be a real "long identifier"
// case distinct from every short fixture above, through the run map, the
// agent sheets and the reach matrix all at once (every surface that draws
// an agent node).
func Test64CharacterAgentNameRendersSafely(t *testing.T) {
	const agentNameLen = 64
	onerrorPayload := `<img src=x onerror=alert(98)>`
	if len(onerrorPayload) > agentNameLen {
		t.Fatal("onerrorPayload no longer fits under the 64-character length this fixture assumes")
	}
	hostileAgent := onerrorPayload + strings.Repeat("a", agentNameLen-len(onerrorPayload))
	if len(hostileAgent) != agentNameLen {
		t.Fatalf("fixture agent name is %d bytes, want exactly %d", len(hostileAgent), agentNameLen)
	}

	events := []recorder.Event{
		{Type: recorder.TypeSessionReady, Agent: hostileAgent, TS: "2026-08-27T10:00:00.000Z"},
		recorder.NewSessionPolicy(hostileAgent, recorder.PolicyFields{
			VcpuCount: 1, MemMiB: 256, Allow: []string{"example.com"},
		}),
		recorder.NewTeamTopology(recorder.TopologyFields{
			Agents: []recorder.EvAgent{{Name: hostileAgent}},
		}),
		{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:01.000Z"},
	}
	html := render(t, events)
	if !strings.Contains(html, "onerror=alert(98)") {
		t.Fatal("the 64-character agent name's payload never reached the rendered page at all")
	}
	page := stripIsland(t, html)
	for _, b := range []byte(page) {
		if isRawControlByte(b) {
			t.Fatalf("a raw control byte 0x%02x reached the page via a 64-character agent name", b)
		}
	}
	for _, tag := range tagSpans(page) {
		low := strings.ToLower(tag)
		if strings.HasPrefix(low, "<script") {
			t.Errorf("a live <script> tag from a 64-character agent name: %s", tag)
		}
		if onAttrRE.MatchString(tag) {
			t.Errorf("an event-handler attribute from a 64-character agent name: %s", tag)
		}
	}
	if !strings.Contains(page, "&lt;img src=x onerror=alert(98)&gt;") {
		t.Error("the 64-character agent name's escaped payload never appeared — it may have been truncated or dropped rather than rendered")
	}
}

// A session whose aggregate recorded size is around 200 MB — not a single
// line over recorder.MaxLine (8 MiB), which clipLargestField already guards
// and internal/recorder's own hostile tests already cover, but a chain this
// package's renderer has to walk, decode and escape in full. Built from
// forty command.output events at 5 MiB raw each (comfortably under MaxLine
// once base64-encoded), one of which buries a real hostile payload and a
// real control byte in the middle of several megabytes of benign filler —
// checking both that rendering does not fail or silently truncate at this
// scale, and that the same escaping still applies when the payload is
// nowhere near the start or end of the text it sits in.
func TestTwoHundredMegabyteSessionRendersSafely(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: skipping the ~200 MB fixture")
	}
	const (
		eventCount  = 40
		fillerBytes = 5 << 20 // 5 MiB raw per event
	)
	hostile := "\x1b]0;pwned\x07" + scriptPayload + `"><img src=x onerror=alert(200)>`

	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"},
		{Type: recorder.TypeSessionReady, Agent: "bulk-agent", TS: "2026-08-27T10:00:01.000Z"},
	}
	var totalRaw int
	for i := 0; i < eventCount; i++ {
		filler := strings.Repeat("x", fillerBytes)
		if i == eventCount/2 {
			// Buried well inside the chunk, not at either edge.
			half := fillerBytes / 2
			filler = filler[:half] + hostile + filler[half:]
		}
		totalRaw += len(filler)
		call := "c" + strconv.Itoa(i)
		events = append(events,
			recorder.Event{Type: recorder.TypeCommandStart, Agent: "bulk-agent",
				Call: call, Cmd: []string{"cat"}, Via: "exec", TS: "2026-08-27T10:00:02.000Z"},
			recorder.Event{Type: recorder.TypeCommandOutput, Agent: "bulk-agent",
				Call: call, Stream: "stdout",
				Data: base64.StdEncoding.EncodeToString([]byte(filler)),
				TS:   "2026-08-27T10:00:02.100Z"},
		)
	}
	events = append(events, recorder.Event{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:03.000Z"})

	if totalRaw < 200<<20-(10<<20) {
		t.Fatalf("fixture only assembled %d raw bytes, want around 200 MB", totalRaw)
	}

	html := render(t, events)
	if len(html) < totalRaw {
		t.Fatalf("rendered page is only %d bytes for %d bytes of raw content — content may have been silently truncated at scale", len(html), totalRaw)
	}
	if !strings.Contains(html, "alert(document.cookie)") {
		t.Fatal("the buried payload never reached the rendered page at ~200 MB scale — it may have been dropped or truncated")
	}
	page := stripIsland(t, html)
	for _, b := range []byte(page) {
		if isRawControlByte(b) {
			t.Fatalf("a raw control byte 0x%02x reached a ~200 MB page", b)
		}
	}
	for _, tag := range tagSpans(page) {
		low := strings.ToLower(tag)
		if strings.HasPrefix(low, "<script") {
			t.Errorf("a live <script> tag buried in a ~200 MB page: %.80s", tag)
		}
		if onAttrRE.MatchString(tag) {
			t.Errorf("an event-handler attribute buried in a ~200 MB page: %.80s", tag)
		}
		if strings.Contains(low, "javascript:") {
			t.Errorf("a javascript: URL buried in a ~200 MB page: %.80s", tag)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(document.cookie)&lt;/script&gt;") {
		t.Error("the buried payload's escaped form never appeared — it may have been dropped rather than rendered")
	}
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
