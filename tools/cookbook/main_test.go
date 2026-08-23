package main

import (
	"os"
	"strings"
	"testing"
)

// The real cookbook has to extract, and every recipe in it has to be one CI
// runs. This is the check that runs on every commit; dev/cookbook.sh is the one
// that runs the scripts.
func TestTheRealCookbookExtracts(t *testing.T) {
	body, err := os.ReadFile("../../docs/cookbook.md")
	if err != nil {
		t.Fatal(err)
	}
	recipes, err := parse(string(body))
	if err != nil {
		t.Fatalf("docs/cookbook.md does not extract: %v", err)
	}
	if len(recipes) < 7 {
		t.Errorf("E3-3 names seven recipes and the cookbook has %d", len(recipes))
	}
	for _, r := range recipes {
		if !strings.HasPrefix(r.Script, "#!/usr/bin/env bash\n") {
			t.Errorf("%s: extracted script has no interpreter line", r.Name)
		}
		if !strings.Contains(r.Script, "kelyfos ") {
			t.Errorf("%s: a recipe that never runs kelyfos is documenting something else", r.Name)
		}
	}
}

func TestParseRejectsWhatItShould(t *testing.T) {
	ok := "<!-- recipe: a -->\n\n```bash\nset -euo pipefail\nkelyfos version\n```\n"
	if _, err := parse(ok); err != nil {
		t.Fatalf("a well-formed recipe was rejected: %v", err)
	}

	for name, doc := range map[string]string{
		"a shell block with no marker": "```bash\nset -euo pipefail\nkelyfos version\n```\n",
		"a marker with no block":       "<!-- recipe: a -->\n\nsome prose\n",
		"a duplicate name":             ok + "\n" + ok,
		"a script with no set -e":      "<!-- recipe: a -->\n\n```bash\nkelyfos version\n```\n",
		"an unclosed block":            "<!-- recipe: a -->\n\n```bash\nset -euo pipefail\n",
		"nothing at all":               "# just prose\n",
	} {
		if _, err := parse(doc); err == nil {
			t.Errorf("%s was accepted and should not have been", name)
		}
	}
}

// A block fenced as something other than a shell needs no marker: it is an
// illustration, and the cookbook has to be able to show one.
func TestNonShellBlocksAreLeftAlone(t *testing.T) {
	doc := "```toml\n[team]\nname = \"x\"\n```\n\n" +
		"<!-- recipe: a -->\n\n```bash\nset -euo pipefail\nkelyfos version\n```\n"
	got, err := parse(doc)
	if err != nil {
		t.Fatalf("a toml illustration broke extraction: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("want 1 recipe, got %d", len(got))
	}
}
