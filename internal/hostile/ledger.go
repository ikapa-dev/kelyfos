// Package hostile is the ledger the hostile corpus reports through (P6-22).
//
// The corpus has to fail before it passes: a fixture added after its fix is one
// nobody has watched fail. But a main branch that stays red until the fix lands
// makes §8 rule 8 stop meaning anything — every session would begin by reading a
// red build and carrying it.
//
// So the failures are written down. testdata/hostile/known-broken.txt says which
// boundary cases are broken and why, and the check is symmetric: a case that
// fails without being listed is a new break, reported on the commit that caused
// it, and a case that holds while still listed is a fix that has to take its own
// line off. The list can only shrink, and it cannot shrink silently.
//
// That is a stronger statement than a red build. Red says something is wrong.
// The ledger says exactly what, since when, and that nothing else has joined it.
//
// It lives in its own package because the corpus spans several — the workspace
// extraction is in internal/sandbox, the file tools are in supervisor, the team
// broker is in internal/team — and a helper copied into each of them is how two
// copies of one rule become two different rules. This project has already found
// that duplication once, in the MCP argument summarisers.
package hostile

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// T is the part of *testing.T this package needs. An interface rather than the
// real type so a package that ships can import this one without importing
// testing — nothing does today, and the constraint is what keeps it that way.
type T interface {
	Helper()
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

var (
	once   sync.Once
	broken map[string]string
	source string
	loadFn = load // swapped in this package's own tests

	// startDir is the working directory when the process began, which for
	// `go test` is the package's own directory.
	//
	// Captured here rather than read when the ledger loads, because a fixture
	// may legitimately chdir before it runs — the file tools take relative
	// paths, and a test that hands `../escape` to one had better not be
	// standing in the repository when it does. A ledger looked up from wherever
	// the test happens to be standing is a ledger a test can move out from
	// under itself.
	startDir = mustWd()
)

// Holds records one boundary case against the ledger.
//
// problem is empty when the case held, and says what went wrong when it did
// not. A listed failure is logged rather than raised: the case is still named
// in the output, so somebody reading a green build can see what is still open.
func Holds(t T, key, problem string) {
	t.Helper()
	once.Do(func() { broken, source = loadFn() })
	why, listed := broken[key]
	switch {
	case problem != "" && !listed:
		t.Errorf("%s does not hold, and is not listed in %s:\n  %s\n"+
			"  A new break is fixed. A finding being recorded gets its line added in the same commit.",
			key, source, problem)
	case problem != "" && listed:
		t.Logf("%s: still broken, as recorded — %s\n  %s", key, why, problem)
	case problem == "" && listed:
		t.Errorf("%s holds now, but is still listed as broken in %s (%s).\n"+
			"  Take its line out, in the commit that fixed it.", key, source, why)
	default:
		t.Logf("%s holds", key)
	}
}

// load finds the ledger by walking up from the working directory.
//
// Walking rather than counting `..` because the corpus lives at several depths —
// internal/sandbox is two levels down, supervisor is one — and a relative path
// that is right for one package is silently wrong for the next. Silently is the
// problem: a ledger that fails to load reads as a ledger with nothing on it,
// which turns every recorded failure into a fresh one and every fixture into
// noise. So a missing ledger is loud.
func load() (map[string]string, string) {
	dir := startDir
	for {
		path := filepath.Join(dir, "testdata", "hostile", "known-broken.txt")
		if _, err := os.Stat(path); err == nil {
			return parse(path), path
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("hostile: testdata/hostile/known-broken.txt is not above " + startDir +
				"; without it every recorded failure would read as a new one")
		}
		dir = parent
	}
}

func mustWd() string {
	wd, err := os.Getwd()
	if err != nil {
		panic("hostile: cannot find the working directory: " + err.Error())
	}
	return wd
}

func parse(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		panic(fmt.Sprintf("hostile: %s exists and will not open: %v", path, err))
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, why, _ := strings.Cut(line, " ")
		out[key] = strings.TrimSpace(why)
	}
	return out
}
