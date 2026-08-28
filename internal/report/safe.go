package report

import (
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// safe and safeBody are the two template functions every guest-influenced
// value in reportHTML is routed through — found necessary while building
// P7-8's own hostile corpus: html/template's contextual HTML escaping
// covers `< > & ' "`, the five characters with meaning to an HTML parser,
// and nothing else. It does not touch a raw control byte, so an agent name,
// a store key or a path carrying one (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F,
// 0x7F) reached the rendered page unescaped before this file existed — true
// of the flat timeline and the lane view (Cmd, Path, Title, Detail) exactly
// as much as of the run map, the agent sheets, the reach matrix and the
// store panel this task adds. Fixed once, here, rather than once per
// surface, for the same reason this project has fixed this class of defect
// in one place every other time it has found it (SafeText's own doc
// comment; the MCP argument summarisers, S19).
//
// safe is proto.SafeText, reused rather than duplicated: every short,
// identity-like field this package renders — an agent name, a domain, a
// store key, a secret's name or host, a path, a title — is exactly the
// class of string SafeText already exists for (a boot line, an OOM
// victim's process name), so a second implementation of the same rule
// would be the third copy P6-3's own postmortem already named as the
// pattern to stop repeating.
func safe(s string) string { return proto.SafeText(s) }

// safeBody is the one guest-influenced field shape SafeText's own behaviour
// is the wrong fit for: a command's captured output and a team message's
// body, both meant to read as pre-formatted, potentially multi-line text —
// this report's own <pre> blocks, docs/events.md's own transcript. Quoting
// the whole blob on one stray control byte (a \r from a progress bar, an
// ESC from colourised output — both routine in real command output) would
// turn genuinely useful, multi-line content into an unreadable, single-line,
// backslash-escaped wall of text: a much larger regression than the
// property being defended against. \t, \n and \r are kept; every other
// byte below 0x20, and 0x7f, is replaced with U+FFFD — visible, inert, and
// never a byte a browser or a terminal could read as a control code.
func safeBody(s string) string {
	if !strings.ContainsFunc(s, isDangerousControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isDangerousControl(r) {
			b.WriteRune('�')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isDangerousControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r < 0x20 || r == 0x7f
}
