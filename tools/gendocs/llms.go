package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/docsize"
)

// llms.txt and llms-full.txt (E3-2).
//
// llms.txt follows the llmstxt.org specification, read at v2 (dated August 2026
// by llmstxt.org/changes.md) rather than remembered. Its grammar is: an optional
// BOM, then an H1 with the project name — "the only required section" — then a
// single-line blockquote summary, then zero or more non-heading markdown blocks,
// then zero or more H2 sections whose every bullet is a markdown link with an
// optional ": notes" after it. Two constraints are easy to miss and are obeyed
// here deliberately: the prose block may contain no headings, and every bullet
// under an H2 must be a link, because the spec's own reference parser calls
// .groupdict() on the match and raises on a line that is not one.
//
// One v2 change worth recording, since v1 knowledge is wrong about it: the
// "Optional" section no longer has mechanical meaning. In v1 it told the
// llms_txt2ctx expander what to drop; that tooling left the proposal, and the
// section is now a naming convention for secondary links. It is used that way
// below and nothing depends on it being honoured.
//
// The two files answer different questions and are not versions of each other.
// llms.txt is an index: a machine that can fetch a URL reads it to decide which
// document it needs. llms-full.txt is the opposite bet — one file with
// everything in it, for a machine that would rather spend context than make a
// round trip, or that has no network at all.
//
// Both are generated, for the reason the whole epic exists: a hand-maintained
// index of a repository's documentation is a list of files that were true once.

// rawBase is where a fetching client is sent. Raw URLs rather than the rendered
// GitHub page, because the consumer here is a program: it wants the Markdown,
// not a page of HTML with the Markdown inside it.
const rawBase = "https://raw.githubusercontent.com/p4r4n0rm4l/KelyfOS/main/"

// doc is one file, with the one-line summary that goes beside its link.
type doc struct {
	Path    string
	Title   string
	Summary string
	Full    bool // include the whole text in llms-full.txt
}

// The order is the order a reader should meet them: what it is, then whether to
// trust it, then how to use it, then the exact names.
func docSet() []doc {
	return []doc{
		{Path: "README.md", Title: "KelyfOS", Full: true,
			Summary: "what it is, the quickstart, and the shape of a policy file"},
		{Path: "docs/compatibility.md", Title: "The compatibility promise", Full: true,
			Summary: "what v1.0 promises will not move, what is explicitly allowed to, and how anything is deprecated before it is removed"},
		{Path: "docs/upgrading.md", Title: "Upgrading", Full: true,
			Summary: "what breaks between versions and what to do about it — the pre-v0.9 snapshot, the writable trees, and what has never broken"},
		{Path: "docs/threat-model.md", Title: "Threat model", Full: true,
			Summary: "what is defended and what is not — read before trusting it with anything"},
		{Path: "docs/resources.md", Title: "Resource limits", Full: true,
			Summary: "how much machine an agent gets: units, precedence, and what enforces each cap"},
		{Path: "docs/networking.md", Title: "Egress", Full: true,
			Summary: "why a sandbox has no NIC by default, what --allow builds, and why there is no DNS"},
		{Path: "docs/teams.md", Title: "Agent teams", Full: true,
			Summary: "several agents on one host: the schema, the broker, the store, the budget"},
		{Path: "docs/denials.md", Title: "Refusals", Full: true,
			Summary: "why every refusal names its own fix, and what the ID in brackets is for"},
		{Path: "docs/events.md", Title: "Flight recorder", Full: true,
			Summary: "the audit record: why the host writes it, and what the hash chain proves"},
		{Path: "docs/protocol.md", Title: "Host/guest protocol", Full: true,
			Summary: "the vsock transport, the port map, and every channel's messages"},
		{Path: "docs/mcp-surface.md", Title: "The MCP surface", Full: true,
			Summary: "MCP in both directions: kelyfos as a tool for any client, and plugins inside the guest"},
		{Path: "docs/hardening.md", Title: "Hardening", Full: true,
			Summary: "what a compromised agent can reach, what each layer takes away, and — the longer half — what remains"},
		{Path: "docs/host-seccomp.md", Title: "The host syscall filter", Full: true,
			Summary: "which filter is around the VMM process, how that is proved from the kernel's own copy, and every syscall it permits"},
		{Path: "docs/e2b-shim.md", Title: "E2B-compatible shim", Full: true,
			Summary: "the REST subset for existing E2B SDK code, and what it deliberately omits"},
		{Path: "docs/cookbook.md", Title: "Cookbook", Full: true,
			Summary: "complete recipes, each one a script CI runs on a real machine"},
		{Path: "docs/integrating.md", Title: "Building on KelyfOS", Full: true,
			Summary: "for putting KelyfOS inside something else: the four ways in, orchestrator patterns, and the mistakes people actually make"},
		{Path: "docs/qol.md", Title: "Daily-driver quality of life", Full: true,
			Summary: "the shell, the diff, pause and resume, port forwarding and notifications — written before the code, with the places the built thing differed marked"},
		{Path: "docs/policy-record.md", Title: "The policy record", Full: true,
			Summary: "session.policy and team.topology, written before the code: every field, its position in the frozen hash order, which door writes it, and what it omits"},
		{Path: "docs/retention.md", Title: "Retention and erasure", Full: true,
			Summary: "the [sessions] retention_days floor, kelyfos sessions prune, the size warning, and kelyfos sessions erase's replacement-record pattern"},
		{Path: "docs/otlp.md", Title: "Mapping the chain to a standard, without adopting it", Full: true,
			Summary: "how kelyfos log --export-otlp maps a session's chain to OTLP-JSON spans, why the mapping is versioned apart from the flight recorder and never an input to kelyfos verify, and what is deliberately not mapped"},
		{Path: "docs/README.md", Title: "Documentation map", Full: true,
			Summary: "what every document is, and — deliberately — where each is still thin"},
	}
}

// The generated half. Listed separately because these are the pages a machine
// should reach for when it needs an exact name rather than an explanation.
func referenceSet() []doc {
	return []doc{
		{Path: "docs/reference/cli.md", Title: "CLI reference", Full: true,
			Summary: "every command and flag, with types and defaults"},
		{Path: "docs/reference/config.md", Title: "kelyfos.toml reference", Full: true,
			Summary: "every key the policy file takes, and every key it refuses"},
		{Path: "docs/reference/tools.md", Title: "MCP tools", Full: true,
			Summary: "every tool a guest exposes, with its input schema"},
		{Path: "docs/reference/events.md", Title: "Event types", Full: true,
			Summary: "every flight-recorder event, with its payload fields"},
		{Path: "docs/reference/exit-codes.md", Title: "Exit codes", Full: true,
			Summary: "what each status the CLI returns means"},
		{Path: "docs/reference/denials.md", Title: "Denials", Full: true,
			Summary: "every refusal KelyfOS makes, with the fix line each one carries"},
		{Path: "docs/reference/profiles.md", Title: "Guest confinement profiles", Full: true,
			Summary: "per flavor, the trees a spawned process may write and the syscalls it is refused"},
	}
}

// llmsIndex writes llms.txt: an H1, a blockquote summary, optional prose, then
// H2 sections of Markdown links with a description after a colon. Nothing else
// is allowed at the top level, so everything a reader needs that is not a link
// goes in the prose block between the blockquote and the first H2.
// No build version appears in either file, and that is deliberate rather than an
// omission. `git describe` changes on every commit and on a dirty tree, so a
// version stamped here would make the two files differ from the committed ones
// on the very next commit — and the CI drift gate would then fail every build
// until somebody regenerated, which is the opposite of what a drift gate is for.
// The README carries the release the project is on, and it is inside
// llms-full.txt.
func llmsIndex(fullTokens int) string {
	var b strings.Builder
	b.WriteString("# KelyfOS\n\n")
	b.WriteString("> A minimal guest operating system for Firecracker microVMs, whose PID 1 is an " +
		"MCP server. An agent attached to a sandbox reaches it only through tools: there is no " +
		"shell login, no SSH, and no network interface at all unless the policy names a domain. " +
		"Credentials stay on the host and are attached by an egress proxy, so the value never " +
		"exists inside the guest. Every tool call, every file write and every connection attempt " +
		"is recorded by the host in a hash-chained log the guest cannot edit.\n\n")

	b.WriteString("Single host, no control plane, no hosted service. `kelyfos run` boots one sandbox; " +
		"`kelyfos team up` boots a declared graph of them with the paths between them enforced by " +
		"a host broker. Everything is configured by a committed `kelyfos.toml` and flags that may " +
		"ask for less than it allows, never more.\n\n")
	b.WriteString("The reference pages are generated from the source on every commit and CI fails " +
		"when they disagree with it, so a flag or a key found there exists. The concept pages are " +
		"written by hand.\n\n")
	// "not hardened yet" was retired at P5-4 everywhere a person looks, and
	// survived here for a release because it is generated: the drift gate keeps
	// llms.txt in step with this line, so it kept a retracted claim consistently
	// wrong. A generated string is not checked by anything that reads the docs.
	b.WriteString("Apache-2.0. Single-host developer tool, not a multi-tenant sandbox for hostile " +
		"code. From v0.9 the VMM runs under the jailer with its own syscall filter proved in " +
		"force, and everything the guest spawns is confined by Landlock and a syscall refusal " +
		"list; an agent is still root inside its own guest, and the VM rather than the chroot " +
		"is the boundary. The threat model below is explicit about which is which.\n\n")

	section := func(title string, docs []doc) {
		b.WriteString("## " + title + "\n\n")
		for _, d := range docs {
			fmt.Fprintf(&b, "- [%s](%s%s): %s\n", d.Title, rawBase, d.Path, d.Summary)
		}
		b.WriteString("\n")
	}
	section("Docs", docSet())
	section("Reference", referenceSet())

	// Secondary links. The spec asks that links point at LLM-friendly content,
	// so the two plan files say in their own descriptions that they are HTML —
	// a consumer can then decide, rather than discovering it after a fetch.
	b.WriteString("## Optional\n\n")
	// The size is computed and rounded to the nearest thousand, so an ordinary
	// documentation edit does not churn this line while a real change to the
	// bulk of the file still shows up.
	fmt.Fprintf(&b, "- [Everything in one file](%sllms-full.txt): every page above concatenated, "+
		"roughly %dk tokens, for a client that would rather spend context than fetch\n",
		rawBase, (fullTokens+500)/1000)
	fmt.Fprintf(&b, "- [Build plan and decision log](%sPLAN.html): HTML. Every phase and "+
		"every decision with its rationale, and the command output behind each claim\n", rawBase)
	fmt.Fprintf(&b, "- [Feature plan and decision log](%sPLAN-FEATURES.html): HTML. The epics "+
		"after the build plan, same protocol\n", rawBase)
	return b.String()
}

// llmsFull concatenates everything. Each document keeps its own heading levels
// and is introduced by a rule and a path, so a reader can tell where it came
// from and quote it back accurately.
func llmsFull(repo string) (string, error) {
	var b strings.Builder
	b.WriteString("# KelyfOS — the whole documentation set\n\n")
	b.WriteString("This is `llms-full.txt`: every documentation page in one file, for a client that\n" +
		"would rather spend context than make a round trip. It is **not part of the llms.txt\n" +
		"specification** — llmstxt.org defines `llms.txt`, an index of links, and mentions this\n" +
		"file nowhere. `llms-full.txt` is a convention the ecosystem settled on around the spec,\n" +
		"and what follows is that convention: each page introduced by a block naming its title,\n" +
		"its source URL and what it covers, then the page itself, unabridged.\n\n")
	b.WriteString("Apache-2.0. Generated by `make docs`: every page below is the committed file,\n" +
		"and the reference pages are themselves generated from the source with CI failing on\n" +
		"drift. The release this describes is in the README's status block, immediately below.\n\n")
	b.WriteString("Contents, in reading order:\n\n")
	all := append(docSet(), referenceSet()...)
	for _, d := range all {
		fmt.Fprintf(&b, "- `%s` — %s\n", d.Path, d.Summary)
	}
	b.WriteString("\n")

	for _, d := range all {
		if !d.Full {
			continue
		}
		body, err := os.ReadFile(filepath.Join(repo, d.Path))
		if err != nil {
			return "", fmt.Errorf("assembling llms-full.txt: %w", err)
		}
		fmt.Fprintf(&b, "\n\n---\ntitle: %s\nurl: %s%s\ndescription: %s\n---\n\n",
			d.Title, rawBase, d.Path, d.Summary)
		b.WriteString(strings.TrimRight(absoluteLinks(string(body), d.Path), "\n"))
		b.WriteString("\n")
	}
	return b.String(), nil
}

// The token estimate's ratio, and the function that applies it, live in
// internal/docsize — because `tools/tokens` prints the same number for the same
// file and the two used to hold separate constants that merely agreed (P6-17).
const charsPerToken = docsize.CharsPerToken

func tokenEstimate(s string) int { return docsize.Estimate(s) }

// absoluteLinks rewrites a document's relative Markdown links so they still work
// once the document has been lifted out of the tree it was written in.
//
// A reader of llms-full.txt has no filesystem: "[the threat model](threat-model.md)"
// resolves against nothing, and an agent that follows it fetches a 404 or, worse,
// invents what it would have said. Resolving against the source file's own
// directory turns every one of them into a URL that answers.
func absoluteLinks(body, from string) string {
	dir := path.Dir(from)
	return mdLink.ReplaceAllStringFunc(body, func(m string) string {
		g := mdLink.FindStringSubmatch(m)
		text, target := g[1], g[2]
		switch {
		case target == "",
			strings.HasPrefix(target, "#"),
			strings.Contains(target, "://"),
			strings.HasPrefix(target, "mailto:"):
			return m
		}
		frag := ""
		if i := strings.IndexByte(target, '#'); i >= 0 {
			target, frag = target[:i], target[i:]
		}
		if target == "" { // a bare fragment after all
			return m
		}
		// A link to a directory means its README. GitHub renders one for a
		// human; raw.githubusercontent serves files only, so without this the
		// one directory link in the tree becomes the only dangling link in the
		// file.
		if strings.HasSuffix(target, "/") {
			target += "README.md"
		}
		return "[" + text + "](" + rawBase + path.Clean(path.Join(dir, target)) + frag + ")"
	})
}

// Deliberately narrow: a link whose text has no brackets of its own and whose
// target has no spaces or parentheses. A cleverer pattern would start matching
// things that are not links, and this file is generated on every commit.
var mdLink = regexp.MustCompile(`\[([^\]\[]*)\]\(([^)\s]*)\)`)
