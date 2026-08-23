// Command cookbook takes the runnable recipes out of docs/cookbook.md (E3-3).
//
// The cookbook is written as prose with scripts in it, and the scripts are the
// documentation: what CI runs is the same text a reader copies. That is the
// whole point of the task, and it only holds if extraction is exact — so this
// program refuses rather than guesses. A shell block with no recipe marker
// above it is an error, because a runnable-looking block that CI never runs is
// precisely the recipe that quietly stops working.
//
//	cookbook -in docs/cookbook.md -list          names, one per line
//	cookbook -in docs/cookbook.md -out <dir>     one <name>.sh per recipe
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	in := flag.String("in", "docs/cookbook.md", "the cookbook to read")
	out := flag.String("out", "", "directory to write one script per recipe")
	list := flag.Bool("list", false, "print the recipe names and stop")
	flag.Parse()

	body, err := os.ReadFile(*in)
	if err != nil {
		die(err)
	}
	recipes, err := parse(string(body))
	if err != nil {
		die(fmt.Errorf("%s: %w", *in, err))
	}
	if err := checkCount(string(body), len(recipes)); err != nil {
		die(fmt.Errorf("%s: %w", *in, err))
	}
	if *list {
		for _, r := range recipes {
			fmt.Println(r.Name)
		}
		return
	}
	if *out == "" {
		fmt.Printf("%s: %d recipes, all extractable\n", *in, len(recipes))
		return
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die(err)
	}
	for _, r := range recipes {
		path := filepath.Join(*out, r.Name+".sh")
		if err := os.WriteFile(path, []byte(r.Script), 0o755); err != nil {
			die(err)
		}
	}
	fmt.Printf("%s: wrote %d recipes to %s\n", *in, len(recipes), *out)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "cookbook:", err)
	os.Exit(1)
}

// Recipe is one runnable script, with the name its marker gave it.
type Recipe struct {
	Name   string
	Script string
	Line   int
}

var (
	marker = regexp.MustCompile(`^<!--\s*recipe:\s*([a-z0-9][a-z0-9-]*)\s*-->$`)
	fence  = regexp.MustCompile("^```(\\w*)$")
)

// parse walks the document once. A marker must be followed, after at most one
// blank line, by a fenced shell block; anything else is an error naming the
// line, which is the same stance the toml parser takes and for the same reason.
func parse(doc string) ([]Recipe, error) {
	lines := strings.Split(doc, "\n")
	var out []Recipe
	seen := map[string]int{}

	for i := 0; i < len(lines); i++ {
		m := marker.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			// A shell block with no marker is the failure this exists to catch.
			if f := fence.FindStringSubmatch(strings.TrimSpace(lines[i])); f != nil && isShell(f[1]) {
				if !markerAbove(lines, i) {
					return nil, fmt.Errorf("line %d: a %s block with no `<!-- recipe: name -->` above it. "+
						"Either give it a name so CI runs it, or fence it as `text` so it is plainly an "+
						"illustration and not a recipe", i+1, f[1])
				}
			}
			continue
		}
		name := m[1]
		if prev, dup := seen[name]; dup {
			return nil, fmt.Errorf("line %d: recipe %q is already defined at line %d", i+1, name, prev)
		}
		seen[name] = i + 1

		j := i + 1
		if j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		f := fence.FindStringSubmatch(strings.TrimSpace(lines[j]))
		if f == nil || !isShell(f[1]) {
			return nil, fmt.Errorf("line %d: recipe %q is not followed by a shell block", i+1, name)
		}
		var script []string
		k := j + 1
		for ; k < len(lines); k++ {
			if strings.TrimSpace(lines[k]) == "```" {
				break
			}
			script = append(script, lines[k])
		}
		if k >= len(lines) {
			return nil, fmt.Errorf("line %d: recipe %q has an unclosed block", i+1, name)
		}
		text := strings.Join(script, "\n") + "\n"
		if !strings.HasPrefix(text, "set -euo pipefail\n") {
			return nil, fmt.Errorf("recipe %q must begin with `set -euo pipefail`: without it a failed "+
				"step is a green recipe, which is worse than no recipe at all", name)
		}
		out = append(out, Recipe{Name: name, Script: "#!/usr/bin/env bash\n" + text, Line: i + 1})
		i = k
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no recipes found")
	}
	return out, nil
}

func isShell(lang string) bool { return lang == "bash" || lang == "sh" }

func markerAbove(lines []string, i int) bool {
	for j := i - 1; j >= 0 && j >= i-2; j-- {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		return marker.MatchString(strings.TrimSpace(lines[j]))
	}
	return false
}

// countWords maps the number a document can spell out to the number it means.
// The cookbook opens by saying how many recipes it has, in words, and that
// sentence is exactly the kind of thing that goes stale the moment somebody
// adds one — it already had, silently, before this check existed (E4-5).
var countWords = map[string]int{
	"One": 1, "Two": 2, "Three": 3, "Four": 4, "Five": 5, "Six": 6,
	"Seven": 7, "Eight": 8, "Nine": 9, "Ten": 10, "Eleven": 11, "Twelve": 12,
	"Thirteen": 13, "Fourteen": 14, "Fifteen": 15, "Sixteen": 16,
}

var countLine = regexp.MustCompile(`(?m)^([A-Z][a-z]+) recipes,`)

func checkCount(doc string, n int) error {
	m := countLine.FindStringSubmatch(doc)
	if m == nil {
		return fmt.Errorf("no line of the form \"<Number> recipes, …\" — the document should say " +
			"how many it has, and this check keeps that true")
	}
	said, ok := countWords[m[1]]
	if !ok {
		return fmt.Errorf("the opening says %q recipes, which is not a number this knows", m[1])
	}
	if said != n {
		return fmt.Errorf("the opening says %s recipes and there are %d", strings.ToLower(m[1]), n)
	}
	return nil
}
