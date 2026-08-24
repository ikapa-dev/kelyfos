package sandbox

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The ledger of boundary cases that do not hold yet (P6-22).
//
// The corpus exists to fail before it passes: a fixture added after its fix is
// one nobody has watched fail. But a repository whose main branch is red until
// the fix lands is a repository where §8 rule 8 stops meaning anything — every
// session would start by reading a red build and carrying it.
//
// So the failures are written down instead. `testdata/hostile/known-broken.txt`
// says which cases are broken and why, CI runs the corpus on every push, and
// the check is symmetric: a case that fails without being listed is a new break
// reported on the commit that caused it, and a case that holds while still
// listed is a fix that has to take its own line off the ledger. The list can
// only shrink, and it cannot shrink silently.
//
// That is the same shape as the generated-reference gate, and it is a stronger
// statement than a red build: red says something is wrong, the ledger says
// exactly what, since when, and that nothing else joined it.

var (
	ledgerOnce sync.Once
	ledger     map[string]string
)

func knownBroken() map[string]string {
	ledgerOnce.Do(func() {
		ledger = map[string]string{}
		f, err := os.Open(filepath.Join("..", "..", "testdata", "hostile", "known-broken.txt"))
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name, why, _ := strings.Cut(line, " ")
			ledger[name] = strings.TrimSpace(why)
		}
	})
	return ledger
}

// holds records one boundary case against the ledger.
//
// problem is empty when the case held and says what went wrong when it did not.
// Nothing here calls t.Errorf for a listed failure: that is the point, and the
// reason a person reading the build output still sees the case named.
func holds(t *testing.T, name, problem string) {
	t.Helper()
	why, listed := knownBroken()[name]
	switch {
	case problem != "" && !listed:
		t.Errorf("%s does not hold, and is not on testdata/hostile/known-broken.txt:\n  %s\n"+
			"  If this is a new break, fix it. If it is a finding being recorded, add the line here in the same commit.",
			name, problem)
	case problem != "" && listed:
		t.Logf("%s: still broken, as recorded — %s\n  %s", name, why, problem)
	case problem == "" && listed:
		t.Errorf("%s holds now, but is still listed as broken (%s).\n"+
			"  Take its line out of testdata/hostile/known-broken.txt in the commit that fixed it.", name, why)
	default:
		t.Logf("%s holds", name)
	}
}
