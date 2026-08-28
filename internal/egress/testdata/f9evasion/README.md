Fixtures for TestF9_ThePeerAuditCatchesEveryEvasionShape.

Each directory holds one construction shape that got past the first version of
the peer audit. They are `.go` files under `testdata`, so the go tool never
builds them and the audit's own repository walk skips them; the fixture test
points at each directory explicitly. Every file must contain exactly one
unarmed construction, so a fixture that stops being caught fails loudly rather
than silently passing.

`testdata/` is invisible to the **go tool**, but not to everything: `gofmt` and
`make docs` both walk it. `tools/gendocs`'s `checkDenialsRaised` parses every
`.go` file under `internal/` recursively, so an unparseable fixture fails
`make docs` with a parse error and no obvious connection to this directory.
Every fixture here must therefore parse and be gofmt-clean — which is awkward
precisely for the next fixture somebody will want, an unparseable file for the
audit's skip-and-log branch. Write that one as `.go.txt` and point the test at
it explicitly.
