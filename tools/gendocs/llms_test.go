package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// llms.txt is checked against the llmstxt.org grammar rather than against a
// reading of it. The patterns below are the spec's own reference parser,
// transcribed from llmstxt.org (spec v2, dated August 2026 by its changes page):
//
//	^#\s*(?P<title>.+?$)\n+(?:^>\s*(?P<summary>.+?$)$)?\n+(?P<info>.*)
//	^##\s*(.*?$)                                       — splits the file lists
//	-\s*\[(?P<title>[^\]]+)\]\((?P<url>[^\)]+)\)(?::\s*(?P<desc>.*))?
//
// The last one is where a real file usually fails, and the failure is not
// graceful: the reference implementation calls .groupdict() on the match, so a
// bullet that is not a link raises rather than being skipped. A prose bullet
// under an H2 would therefore break the very tools this file exists to serve.
var (
	specHead    = regexp.MustCompile(`(?m)^#\s*(.+?)$`)
	specQuote   = regexp.MustCompile(`(?m)^>\s*(.+?)$`)
	specSection = regexp.MustCompile(`(?m)^##\s*(.*?)$`)
	specLink    = regexp.MustCompile(`-\s*\[([^\]]+)\]\(([^)]+)\)(?::\s*(.*))?`)
	anyHeading  = regexp.MustCompile(`(?m)^#{1,6}\s`)
)

func TestLLMsIndexFollowsTheSpec(t *testing.T) {
	doc := llmsIndex(48000)

	// An H1 with the project name, first, and exactly one of them.
	lines := strings.Split(doc, "\n")
	if !strings.HasPrefix(lines[0], "# ") {
		t.Fatalf("the first line must be the H1: %q", lines[0])
	}
	if n := len(specHead.FindAllString(doc, -1)) - len(specSection.FindAllString(doc, -1)); n != 1 {
		t.Errorf("want exactly one H1, found %d", n)
	}

	// The summary is a single-line blockquote directly after the H1. The
	// reference pattern matches one line, so a wrapped blockquote is not a
	// summary as far as a consumer is concerned.
	if lines[1] != "" || !strings.HasPrefix(lines[2], "> ") {
		t.Fatalf("the blockquote must follow the H1 after one blank line, got %q / %q",
			lines[1], lines[2])
	}
	if q := specQuote.FindAllString(doc, -1); len(q) != 1 {
		t.Errorf("want exactly one blockquote line, found %d — a wrapped summary is not captured", len(q))
	}

	// Everything between the blockquote and the first H2 is free prose, and the
	// spec allows "any type except headings" there.
	firstH2 := specSection.FindStringIndex(doc)
	if firstH2 == nil {
		t.Fatal("no H2 file-list section at all")
	}
	intro := doc[strings.Index(doc, "\n> ")+1 : firstH2[0]]
	if h := anyHeading.FindString(intro); h != "" {
		t.Errorf("the intro block contains a heading, which ends it early: %q", strings.TrimSpace(h))
	}

	// Every bullet under every H2 has to be a link, or the spec's own parser
	// raises on it.
	body := doc[firstH2[0]:]
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "-") {
			continue
		}
		m := specLink.FindStringSubmatch(trimmed)
		if m == nil {
			t.Errorf("a bullet in a file list is not a link, which breaks the reference parser:\n  %s", trimmed)
			continue
		}
		if !strings.HasPrefix(m[2], "https://") {
			t.Errorf("link %q is not absolute; a consumer has no base to resolve it against", m[2])
		}
		if strings.TrimSpace(m[3]) == "" {
			t.Errorf("link %q has no description — allowed by the grammar, and the spec's own "+
				"guidelines ask for one", m[1])
		}
	}

	// "The file itself stays small enough to fit in context." A conformant
	// index that has to be summarised before use has missed the point.
	if len(doc) > 16<<10 {
		t.Errorf("llms.txt is %d bytes; it is an index and belongs well under 16 KiB", len(doc))
	}
}

// Every path llms.txt advertises has to be a file this repository actually has,
// or the index sends a reader to a 404 that it will then guess the contents of.
func TestLLMsIndexLinksResolve(t *testing.T) {
	// The test runs in its own package directory; the repository is two above.
	const root = "../.."
	for _, d := range append(docSet(), referenceSet()...) {
		if strings.Contains(d.Path, "..") || strings.HasPrefix(d.Path, "/") {
			t.Errorf("%q is not a repository-relative path", d.Path)
			continue
		}
		if d.Title == "" || d.Summary == "" {
			t.Errorf("%q needs both a title and a summary to appear in the index", d.Path)
		}
		if _, err := os.Stat(filepath.Join(root, d.Path)); err != nil {
			t.Errorf("llms.txt advertises %s and this repository has no such file: %v", d.Path, err)
		}
	}
}
