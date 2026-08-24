package main

import (
	"flag"
	"strings"
	"testing"
	"time"
)

// The generated reference is only as complete as this parser, and CI cannot
// catch a gap in it: `make docs` compares the generator's output against the
// committed file, so a flag the generator never sees is missing from both and
// the two agree. That is how `kelyfos log -f` stayed undocumented — defined in
// the source, named in the usage prose, absent from docs/reference/cli.md, and
// green the whole time.
//
// So the fixture is not written by hand. It is produced by the `flag` package
// itself, because the bug was a disagreement with how `flag` formats a line and
// a hand-written imitation would have reproduced the misunderstanding instead
// of the behaviour.
func printDefaultsOf(t *testing.T, define func(fs *flag.FlagSet)) string {
	t.Helper()
	fs := flag.NewFlagSet("kelyfos test", flag.ContinueOnError)
	var out strings.Builder
	fs.SetOutput(&out)
	define(fs)
	fs.PrintDefaults()
	return out.String()
}

func TestParseFlagsSeesEveryShapeFlagPrints(t *testing.T) {
	text := printDefaultsOf(t, func(fs *flag.FlagSet) {
		fs.Bool("f", false, "alias for --follow")
		fs.Bool("follow", false, "keep reading as events arrive")
		fs.String("sandbox", "", "sandbox id (default: the only running one)")
		fs.Int("n", 4, "how many")
		fs.Duration("timeout", 15*time.Second, "give up after this long")
	})

	got := map[string]Flag{}
	for _, f := range parseFlags(text) {
		got[f.Name] = f
	}

	for _, name := range []string{"f", "follow", "sandbox", "n", "timeout"} {
		if _, ok := got[name]; !ok {
			t.Errorf("-%s is missing from the parsed flags; the reference would not document it\n%s", name, text)
		}
	}

	// The one that was broken, checked for more than presence: a one-letter
	// boolean carries its usage on the same line, so a parser that finds the
	// name and loses the text is only half fixed.
	if f := got["f"]; f.Doc != "alias for --follow" {
		t.Errorf("-f doc = %q, want %q", f.Doc, "alias for --follow")
	}
	if f := got["f"]; f.Type != "boolean" {
		t.Errorf("-f type = %q, want boolean", f.Type)
	}

	// And the shapes that already worked, so the fix cannot have traded one
	// gap for another.
	if f := got["sandbox"]; f.Type != "string" || f.Doc == "" {
		t.Errorf("-sandbox parsed as %+v, want a string flag with a doc", f)
	}
	if f := got["n"]; f.Type != "int" || f.Default != "4" {
		t.Errorf("-n parsed as %+v, want an int flag defaulting to 4", f)
	}
	if f := got["timeout"]; f.Type != "duration" || f.Default != "15s" {
		t.Errorf("-timeout parsed as %+v, want a duration flag defaulting to 15s", f)
	}
}

// A one-letter boolean with a non-zero default is the one variant of the
// same-line form that also carries a "(default …)" tail. Nothing in the CLI has
// this shape today, which is exactly why it is worth pinning: the next one-letter
// flag someone adds should not have to rediscover it.
func TestParseFlagsSplitsTheDefaultOffASameLineFlag(t *testing.T) {
	text := printDefaultsOf(t, func(fs *flag.FlagSet) {
		fs.Bool("v", true, "say more")
	})
	flags := parseFlags(text)
	if len(flags) != 1 {
		t.Fatalf("parsed %d flags from %q, want 1", len(flags), text)
	}
	if flags[0].Doc != "say more" {
		t.Errorf("doc = %q, want %q", flags[0].Doc, "say more")
	}
	if flags[0].Default != "true" {
		t.Errorf("default = %q, want %q", flags[0].Default, "true")
	}
}
