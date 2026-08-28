package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadsAPolicy(t *testing.T) {
	cfg, err := Load(write(t, `
# the sandbox this project wants
[sandbox]
image = "dev"
allow = ["github.com", "pypi.org"]
secrets = ["GITHUB_TOKEN@api.github.com"]
workspace = "."
vcpus = 4
mem_mib = 2048
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Image != "dev" || cfg.Vcpus != 4 || cfg.MemMiB != 2048 || cfg.Workspace != "." {
		t.Errorf("scalars wrong: %+v", cfg)
	}
	if len(cfg.Allow) != 2 || cfg.Allow[0] != "github.com" || cfg.Allow[1] != "pypi.org" {
		t.Errorf("allow wrong: %v", cfg.Allow)
	}
	if len(cfg.Secrets) != 1 || cfg.Secrets[0] != "GITHUB_TOKEN@api.github.com" {
		t.Errorf("secrets wrong: %v", cfg.Secrets)
	}
}

// [sessions] retention_days (P7-5, D61): absent means nil Sessions, which
// kelyfos sessions prune reads as "use the built-in default" — the same
// nil-means-absent convention Team already uses, and the same
// zero-means-not-set convention every other numeric field in this package's
// own doc comment states for itself.
func TestSessionsSectionAbsentByDefault(t *testing.T) {
	cfg, err := Load(write(t, `[sandbox]
image = "dev"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sessions != nil {
		t.Errorf("Sessions = %+v, want nil when the file has no [sessions] section", cfg.Sessions)
	}
}

func TestSessionsSectionParsesRetentionDays(t *testing.T) {
	cfg, err := Load(write(t, `[sessions]
retention_days = 365
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sessions == nil || cfg.Sessions.RetentionDays != 365 {
		t.Errorf("Sessions = %+v, want RetentionDays 365", cfg.Sessions)
	}
}

func TestSessionsSectionRefusesUnknownKey(t *testing.T) {
	_, err := Load(write(t, `[sessions]
max_age = 30
`))
	if err == nil {
		t.Fatal("an unknown key in [sessions] was accepted")
	}
	if !strings.Contains(err.Error(), "max_age") || !strings.Contains(err.Error(), "retention_days") {
		t.Errorf("the refusal does not name both the bad key and the real one: %v", err)
	}
}

func TestSessionsSectionRefusesNegativeRetention(t *testing.T) {
	_, err := Load(write(t, `[sessions]
retention_days = -1
`))
	if err == nil {
		t.Fatal("a negative retention_days was accepted")
	}
}

// A policy file is committed to a repository. A secret value in one would be
// committed with it, so this must be refused rather than merely discouraged.
func TestRefusesASecretValue(t *testing.T) {
	_, err := Load(write(t, `
[sandbox]
secrets = ["GITHUB_TOKEN=ghp_realtokenvalue@api.github.com"]
`))
	if err == nil {
		t.Fatal("a secret containing a value must be refused")
	}
	if !strings.Contains(err.Error(), "never a value") {
		t.Errorf("the error should say why: %v", err)
	}
}

func TestRefusesMalformedSecret(t *testing.T) {
	if _, err := Load(write(t, "[sandbox]\nsecrets = [\"GITHUB_TOKEN\"]\n")); err == nil {
		t.Error("a secret without @domain must be refused")
	}
}

// A typo that silently does nothing is worse than one that refuses: the policy
// would look applied and not be.
func TestRefusesUnknownKeysAndSections(t *testing.T) {
	if _, err := Load(write(t, "[sandbox]\nallwo = [\"github.com\"]\n")); err == nil {
		t.Error("an unknown key must be an error, not a silent skip")
	}
	if _, err := Load(write(t, "[sandbxo]\nimage = \"dev\"\n")); err == nil {
		t.Error("an unknown section must be an error")
	}
}

func TestErrorsNameTheLine(t *testing.T) {
	_, err := Load(write(t, "[sandbox]\nimage = \"dev\"\nvcpus = lots\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), ":3") {
		t.Errorf("the error should name the line: %v", err)
	}
}

func TestCommentsAndBlankLines(t *testing.T) {
	cfg, err := Load(write(t, "# leading\n\n[sandbox]\nimage = \"base\" # trailing\n\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Image != "base" {
		t.Errorf("image = %q", cfg.Image)
	}
}

// F7: a comma inside a quoted array element must not split the element in
// two. Before the fix, parseArray split on every comma in the raw bracket
// contents before parseString ever saw an element, so this failed to parse.
func TestArrayCommaInsideQuotes(t *testing.T) {
	out, err := parseArray(`["x", "--y=a,b"]`, "test")
	if err != nil {
		t.Fatalf("parseArray: %v", err)
	}
	if len(out) != 2 || out[0] != "x" || out[1] != "--y=a,b" {
		t.Errorf("got %v, want [x --y=a,b]", out)
	}
}

// Multiple elements can each carry their own internal comma.
func TestArrayMultipleElementsWithInternalCommas(t *testing.T) {
	out, err := parseArray(`["a,b", "c,d,e", "f"]`, "test")
	if err != nil {
		t.Fatalf("parseArray: %v", err)
	}
	want := []string{"a,b", "c,d,e", "f"}
	if len(out) != len(want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("element %d = %q, want %q", i, out[i], want[i])
		}
	}
}

func TestArrayEmpty(t *testing.T) {
	out, err := parseArray(`[]`, "test")
	if err != nil {
		t.Fatalf("parseArray: %v", err)
	}
	if out != nil {
		t.Errorf("got %v, want nil", out)
	}
}

func TestArraySingleElement(t *testing.T) {
	out, err := parseArray(`["solo"]`, "test")
	if err != nil {
		t.Fatalf("parseArray: %v", err)
	}
	if len(out) != 1 || out[0] != "solo" {
		t.Errorf("got %v, want [solo]", out)
	}
}

// A '#' inside a quoted value is part of the value, not a comment.
func TestHashInsideAString(t *testing.T) {
	cfg, err := Load(write(t, "[sandbox]\nworkspace = \"./a#b\"\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Workspace != "./a#b" {
		t.Errorf("workspace = %q", cfg.Workspace)
	}
}

func TestFindWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, FileName), []byte("[sandbox]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	got, ok := Find(deep)
	if !ok {
		t.Fatal("Find should walk up to the project root, as git does")
	}
	if filepath.Dir(got) != root {
		t.Errorf("found %s, want one in %s", got, root)
	}
}

func TestFindReportsAbsence(t *testing.T) {
	if _, ok := Find(t.TempDir()); ok {
		t.Error("Find must report absence rather than inventing a path")
	}
}
