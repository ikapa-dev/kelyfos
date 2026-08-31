package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// What this file checks is the document itself, from outside: it builds the
// tool, builds a Go binary for each architecture the release ships, runs the
// one against the other, and reads what came out. Black box on purpose — the
// defect it covers survived every unit test this package had, because each of
// them was true about a function and none of them was true about the file a
// stranger downloads (D81).
//
// The defect, verified against the published artifacts before it was fixed:
// `sbom-aarch64.cdx.json` and `sbom-x86_64.cdx.json` in v1.1 and in v1.1.1 are
// byte-identical, sha256 fcb447b7… and 022aff89… respectively. -arch was
// validated, printed and discarded; the merge copied Buildroot's metadata
// verbatim, so both documents declared their subject to be "buildroot
// 2025.02.17"; and release.yml's two per-architecture SBOM attestations
// therefore attached one document to both sets of artifacts — the exact claim
// their separation exists to prevent.

// The fixture module. It has no dependencies, so nothing here needs a network
// or a module cache: what is being read out of it is GOOS, GOARCH and the fact
// that debug/buildinfo survives -s -w.
const fixtureMain = `package main

func main() {}
`

const fixtureMod = `module example.com/kelyfosfixture

go 1.27
`

// A Buildroot document in the shape its generator actually emits, cut down to
// the parts this merge has to preserve: a licence, a CPE, a source-tarball
// hash, a patch pedigree, a BR_TYPE property, its own metadata, and — the pair
// that the old name-and-version deduplication collapsed into one — a target
// package and the host build of the same package at the same version.
const buildrootFixture = `{
  "bomFormat": "CycloneDX",
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "bom-ref": "buildroot",
      "name": "buildroot",
      "version": "2025.02.17",
      "type": "firmware"
    },
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "Buildroot generate-cyclonedx",
          "version": "2025.02.17",
          "licenses": [{"license": {"id": "GPL-2.0"}}]
        }
      ]
    }
  },
  "components": [
    {
      "bom-ref": "libzlib",
      "type": "library",
      "name": "libzlib",
      "version": "1.3.2",
      "licenses": [{"license": {"name": "Zlib"}}],
      "cpe": "cpe:2.3:a:zlib:zlib:1.3.2:*:*:*:*:*:*:*",
      "externalReferences": [
        {
          "type": "source-distribution",
          "url": "https://example.invalid/zlib-1.3.2.tar.gz",
          "hashes": [{"alg": "SHA-256", "content": "38ef96b8dfe510d42707d9c781877914792541133e1870841463bfa73f883e32"}]
        }
      ],
      "pedigree": {"patches": [{"type": "unofficial", "diff": {"text": {"content": "--- a\n+++ b\n"}}}]},
      "properties": [{"name": "BR_TYPE", "value": "target"}]
    },
    {
      "bom-ref": "host-libzlib",
      "type": "library",
      "name": "libzlib",
      "version": "1.3.2",
      "licenses": [{"license": {"name": "Zlib"}}],
      "properties": [{"name": "BR_TYPE", "value": "host"}]
    }
  ],
  "dependencies": [
    {"ref": "buildroot", "dependsOn": ["libzlib"]},
    {"ref": "libzlib", "dependsOn": []}
  ],
  "vulnerabilities": []
}
`

var (
	fixtureOnce sync.Once
	fixtureErr  error
	fixtureDir  string
	toolPath    string
	// Reachable only through buildrootFixture(t). It is empty until
	// buildFixtures has run, and an empty -buildroot is not an error to this
	// tool — it means "no Buildroot input", which is a document that quietly
	// omits the half these tests are about. Reading the variable directly is
	// how that happened: Go evaluates a call's arguments before the call, so a
	// helper that passed this to a function which then built the fixtures
	// passed the empty string on the first call of any process.
	buildrootPath string
	// goarch -> the binaries built for it, in the order release-sbom reads them.
	fixtureBins = map[string][]string{}
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureDir != "" {
		os.RemoveAll(fixtureDir)
	}
	os.Exit(code)
}

// theTool builds this package's own program once, and beside it a Go binary for
// every operating system and architecture the release ships a CLI for.
func theTool(t *testing.T) string {
	t.Helper()
	fixtureOnce.Do(buildFixtures)
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return toolPath
}

func buildFixtures() {
	dir, err := os.MkdirTemp("", "sbom-fixture")
	if err != nil {
		fixtureErr = err
		return
	}
	fixtureDir = dir

	toolPath = filepath.Join(dir, "sbom")
	build := exec.Command("go", "build", "-o", toolPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fixtureErr = fmt.Errorf("building tools/sbom: %v\n%s", err, out)
		return
	}

	src := filepath.Join(dir, "fixture")
	if err := os.MkdirAll(src, 0o755); err != nil {
		fixtureErr = err
		return
	}
	for name, body := range map[string]string{"go.mod": fixtureMod, "main.go": fixtureMain} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			fixtureErr = err
			return
		}
	}

	// The same four platforms `make release-cli` stages, built the way it builds
	// them: stripped and trimmed, because the claim that debug/buildinfo
	// survives -s -w is one this file may as well exercise rather than repeat.
	for _, p := range []struct{ goos, goarch string }{
		{"linux", "arm64"}, {"darwin", "arm64"},
		{"linux", "amd64"}, {"darwin", "amd64"},
	} {
		out := filepath.Join(dir, "kelyfosfixture-"+p.goos+"-"+p.goarch)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, ".")
		cmd.Dir = src
		cmd.Env = append(os.Environ(),
			"CGO_ENABLED=0", "GOOS="+p.goos, "GOARCH="+p.goarch,
			"GOFLAGS=", "GOPROXY=off", "GOWORK=off",
		)
		if o, err := cmd.CombinedOutput(); err != nil {
			fixtureErr = fmt.Errorf("cross-building the fixture for %s/%s: %v\n%s", p.goos, p.goarch, err, o)
			return
		}
		fixtureBins[p.goarch] = append(fixtureBins[p.goarch], out)
	}

	buildrootPath = filepath.Join(dir, "sbom-buildroot.json")
	if err := os.WriteFile(buildrootPath, []byte(buildrootFixture), 0o644); err != nil {
		fixtureErr = err
	}
}

// buildrootFixture is the standard Buildroot input, built if it is not there.
func buildrootFixtureAt(t *testing.T) string {
	t.Helper()
	theTool(t)
	return buildrootPath
}

// runTool runs the tool the way `make release-sbom` runs it, for one
// architecture and one Buildroot input, and returns what it wrote to stderr
// beside whether it succeeded.
func runTool(t *testing.T, arch, goarch, version, buildroot, out string) (string, error) {
	t.Helper()
	tool := theTool(t)
	args := []string{"-arch", arch, "-version", version, "-out", out, "-buildroot", buildroot}
	for _, b := range fixtureBins[goarch] {
		args = append(args, "-binary", b)
	}
	cmd := exec.Command(tool, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stderr.String(), err
}

// release is runTool over the standard fixture, for a run that has to succeed.
func release(t *testing.T, arch, goarch, version, out string) []byte {
	t.Helper()
	stderr, err := runTool(t, arch, goarch, version, buildrootFixtureAt(t), out)
	if err != nil {
		t.Fatalf("sbom -arch %s: %v\n%s", arch, err, stderr)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// serialOf reads the serial number back out of a document.
func serialOf(t *testing.T, body []byte) string {
	t.Helper()
	s, _ := parse(t, body)["serialNumber"].(string)
	if s == "" {
		t.Fatal("no serialNumber: actions/attest refuses a document without one (P6-20)")
	}
	return s
}

func parse(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("the document this tool wrote is not JSON: %v", err)
	}
	return d
}

// The defect, stated as a test. Both architectures resolve the same Buildroot
// packages and the same Go modules — that is true and is not the problem. The
// problem is that a document describing one architecture has to say which one,
// and two documents describing different architectures cannot be the same
// bytes under a serial number whose entire job is to tell two BOMs apart.
func TestTheTwoArchitecturesProduceDifferentDocumentsThatEachNameTheirOwn(t *testing.T) {
	dir := t.TempDir()
	arm := release(t, "aarch64", "arm64", "v1.1.2", filepath.Join(dir, "sbom-aarch64.cdx.json"))
	x86 := release(t, "x86_64", "amd64", "v1.1.2", filepath.Join(dir, "sbom-x86_64.cdx.json"))

	if bytes.Equal(arm, x86) {
		t.Error("the aarch64 and x86_64 SBOMs are byte-identical. release.yml attests each of them " +
			"against its own architecture's artifacts precisely so that neither claims to describe the " +
			"other's, and two identical files make both attestations say the same thing.")
	}

	// Both sides have to carry the same Buildroot half, because that is what
	// makes this test about the architecture and nothing else. If one of them
	// lost it, the two documents would differ for a reason this test is not
	// measuring, and every assertion below would pass for the wrong one.
	armDoc, x86Doc := parse(t, arm), parse(t, x86)
	for name, d := range map[string]map[string]any{"aarch64": armDoc, "x86_64": x86Doc} {
		components, _ := d["components"].([]any)
		var buildroot int
		for _, c := range components {
			m, _ := c.(map[string]any)
			if _, fromBuildroot := m["cpe"]; fromBuildroot {
				buildroot++
			}
		}
		if buildroot == 0 || d["dependencies"] == nil {
			t.Fatalf("the %s document carries no Buildroot half, so the two documents differ for a "+
				"reason this test is not about: %d components, %d of them Buildroot's",
				name, len(components), buildroot)
		}
	}
	armSerial, _ := armDoc["serialNumber"].(string)
	x86Serial, _ := x86Doc["serialNumber"].(string)
	if armSerial == "" || x86Serial == "" {
		t.Fatal("no serialNumber: actions/attest refuses a document without one (P6-20)")
	}
	if armSerial == x86Serial {
		t.Errorf("both architectures carry the serial number %s, which is the one field in a CycloneDX "+
			"document that exists to identify this exact BOM", armSerial)
	}

	for _, c := range []struct {
		name, arch string
		doc        map[string]any
	}{{"aarch64", "aarch64", armDoc}, {"x86_64", "x86_64", x86Doc}} {
		t.Run(c.name, func(t *testing.T) {
			for _, field := range []string{"bomFormat", "serialNumber", "specVersion"} {
				if s, _ := c.doc[field].(string); s == "" {
					t.Errorf("no %s: actions/attest tests for exactly these three and refuses the whole "+
						"document with \"Unsupported SBOM format\" if any is missing (P6-20)", field)
				}
			}

			meta, _ := c.doc["metadata"].(map[string]any)
			subject, _ := meta["component"].(map[string]any)
			if subject == nil {
				t.Fatal("the document declares no subject at all")
			}
			if name, _ := subject["name"].(string); name != "kelyfos" {
				t.Errorf("the document says it describes %q. A stranger downloading sbom-%s.cdx.json from a "+
					"KelyfOS release gets a bill of materials whose declared subject is something else.",
					name, c.arch)
			}
			if v, _ := subject["version"].(string); v != "v1.1.2" {
				t.Errorf("the subject's version is %q and this release is v1.1.2", v)
			}
			// The architecture, wherever the subject records it. Asserted over
			// the whole subject rather than one field, so that moving it
			// between purl, a property and the description is a change this
			// test permits and dropping it is not.
			blob, err := json.Marshal(subject)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(blob, []byte(c.arch)) {
				t.Errorf("the subject of sbom-%s.cdx.json does not name its architecture anywhere: %s",
					c.arch, blob)
			}
			other := map[string]string{"aarch64": "x86_64", "x86_64": "aarch64"}[c.arch]
			if bytes.Contains(blob, []byte(other)) {
				t.Errorf("the subject of sbom-%s.cdx.json names %s: %s", c.arch, other, blob)
			}
		})
	}
}

// Determinism, which is the constraint every part of this change had to be
// designed around. Two builds of one commit produce byte-identical artifacts
// (P6-9) and repro-check measures it, so the architecture had to reach the
// document through something derived rather than through a clock or a random
// serial.
func TestTheSameArchitectureTwiceProducesTheSameBytes(t *testing.T) {
	dir := t.TempDir()
	first := release(t, "aarch64", "arm64", "v1.1.2", filepath.Join(dir, "first.json"))
	second := release(t, "aarch64", "arm64", "v1.1.2", filepath.Join(dir, "second.json"))
	if !bytes.Equal(first, second) {
		t.Error("two runs over the same inputs produced different bytes, which breaks the byte-identical " +
			"build P6-9 measured and makes repro-check report a difference that means nothing")
	}
	if bytes.Contains(first, []byte("timestamp")) {
		t.Error("the document carries a timestamp, which is the obvious CycloneDX field to reach for and " +
			"the one that makes every build differ from every other")
	}
}

// Everything Buildroot computed survives the merge.
//
// It did not. `licenses`, `cpe`, `externalReferences` with their source-tarball
// hashes, the patch pedigree and the BR_TYPE property were all dropped, because
// the merge decoded each component into a struct modelling seven fields and
// wrote that struct back out — 333 KB of Buildroot output leaving as 11 KB.
// Deduplication on name and version then collapsed the host build of a package
// into the target one: the published v1.1.1 SBOM lists the *host* OpenSSL, zlib,
// libffi and python3 and not the ones in the image.
func TestBuildrootsComponentsSurviveTheMergeIntact(t *testing.T) {
	dir := t.TempDir()
	doc := parse(t, release(t, "aarch64", "arm64", "v1.1.2", filepath.Join(dir, "sbom.json")))

	byRef := map[string]map[string]any{}
	components, _ := doc["components"].([]any)
	for _, c := range components {
		m, _ := c.(map[string]any)
		ref, _ := m["bom-ref"].(string)
		byRef[ref] = m
	}

	// Two builds of one package at one version are two components.
	for _, ref := range []string{"libzlib", "host-libzlib"} {
		if byRef[ref] == nil {
			t.Errorf("%s is not in the document: a target package and the host build of it are one name "+
				"and one version, and deduplicating on those loses whichever Buildroot emitted second", ref)
		}
	}

	target := byRef["libzlib"]
	if target != nil {
		for _, field := range []string{"licenses", "cpe", "externalReferences", "pedigree", "properties"} {
			if _, ok := target[field]; !ok {
				t.Errorf("libzlib lost its %s. A bill of materials without licences is not one, and a "+
					"component without a CPE is one a scanner cannot match a CVE against.", field)
			}
		}
	}

	// Buildroot was the subject of its own document; it is a component of this
	// one, and the dependency graph is rooted at its bom-ref.
	if byRef["buildroot"] == nil {
		t.Error("the buildroot component is gone, so nothing in the document says which Buildroot built " +
			"the guest userland, and the dependency graph below refers to a component that is not here")
	}
	if _, ok := doc["dependencies"]; !ok {
		t.Error("Buildroot's dependency graph did not survive the merge")
	}

	// The generator and its licence.
	meta, _ := doc["metadata"].(map[string]any)
	tools, err := json.Marshal(meta["tools"])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Buildroot generate-cyclonedx", "GPL-2.0"} {
		if !bytes.Contains(tools, []byte(want)) {
			t.Errorf("metadata.tools no longer names %q: %s", want, tools)
		}
	}

	// The Go halves, and the architecture read out of them rather than claimed.
	blob, err := json.Marshal(components)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"example.com/kelyfosfixture", "goarch", "arm64"} {
		if !bytes.Contains(blob, []byte(want)) {
			t.Errorf("no component names %q, so nothing in the document came from the binaries it read", want)
		}
	}
}

// -arch is an assertion now, not a label. The binaries know what they were
// built for; the flag is a claim, and a document that writes down the claim
// without checking it is how the architecture went missing in the first place.
func TestAnArchitectureTheBinariesDoNotAgreeWithIsRefused(t *testing.T) {
	tool := theTool(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "wrong.json")

	args := []string{"-arch", "x86_64", "-version", "v1.1.2", "-out", out, "-buildroot", buildrootFixtureAt(t)}
	for _, b := range fixtureBins["arm64"] {
		args = append(args, "-binary", b)
	}
	cmd := exec.Command(tool, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("an SBOM for x86_64 was written out of arm64 binaries and nothing objected:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "arm64") {
		t.Errorf("the refusal does not say what the binaries actually are: %s", stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a document was written anyway")
	}
}

// A serial number identifies this exact BOM, so a change anywhere in the BOM
// has to change it — including in the places no identifier names.
//
// This is the defect the adversarial review of D81's first version found, and
// it was introduced by the fix rather than inherited. Hashing five identifying
// fields per component was a content digest for as long as those five fields
// were nearly all a component had; once Buildroot's components pass through
// whole, they are about three per cent of the document. A licence, a CPE and
// the SHA-256 of the tarball a package was built from all sat outside the hash,
// so two materially different documents went out under one serial — the same
// failure the architecture case describes, reached through content.
func TestAChangeBuriedInAComponentChangesTheSerialNumber(t *testing.T) {
	dir := t.TempDir()
	clean := release(t, "aarch64", "arm64", "v1.1.2", filepath.Join(dir, "clean.json"))

	// The licence, the CPE and the source-tarball hash of one component, and
	// nothing else. None of the five fields that identify a component moves.
	tampered := strings.NewReplacer(
		`{"license": {"name": "Zlib"}}`, `{"license": {"name": "MIT"}}`,
		`cpe:2.3:a:zlib:zlib:1.3.2:*:*:*:*:*:*:*`, `cpe:2.3:a:someone:else:1.3.2:*:*:*:*:*:*:*`,
		`38ef96b8dfe510d42707d9c781877914792541133e1870841463bfa73f883e32`,
		`0000000000000000000000000000000000000000000000000000000000000000`,
	).Replace(buildrootFixture)
	if tampered == buildrootFixture {
		t.Fatal("the fixture no longer contains what this test edits")
	}
	other := filepath.Join(dir, "tampered-buildroot.json")
	if err := os.WriteFile(other, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "tampered.json")
	if stderr, err := runTool(t, "aarch64", "arm64", "v1.1.2", other, out); err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	changed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(clean, changed) {
		t.Fatal("the two documents are identical, so this test is not editing what it thinks it is")
	}
	if a, b := serialOf(t, clean), serialOf(t, changed); a == b {
		t.Errorf("a component's licence, its CPE and the hash of the tarball it was built from all "+
			"changed and the serial number did not: %s. The serial covers a summary of the document "+
			"rather than the document, so an attestation over it says nothing about what changed.", a)
	}
}

// Bytes this tool did not write go out under this project's name and a
// signature, so the one property Go's JSON encoder does not check for them is
// checked here. encoding/json escapes what it must inside a json.RawMessage and
// does not validate UTF-8 in it, so a component carrying an invalid sequence
// would produce a published, attested document that no JSON parser can read —
// the shape of P6-20 with a different field.
func TestAComponentThatIsNotValidUTF8IsRefusedRatherThanPublished(t *testing.T) {
	dir := t.TempDir()
	broken := []byte(strings.Replace(buildrootFixture,
		`"name": "libzlib",`, "\"name\": \"libz\xc3(lib\",", 1))
	if bytes.Equal(broken, []byte(buildrootFixture)) {
		t.Fatal("the fixture no longer contains what this test edits")
	}
	in := filepath.Join(dir, "not-utf8.json")
	if err := os.WriteFile(in, broken, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")

	stderr, err := runTool(t, "aarch64", "arm64", "v1.1.2", in, out)
	if err == nil {
		body, readErr := os.ReadFile(out)
		if readErr == nil && !utf8.Valid(body) {
			t.Fatal("a document that is not valid UTF-8 was written and the tool exited 0: " +
				"no JSON reader will accept it, and the release would attest it anyway")
		}
		t.Fatalf("expected a refusal; stderr was %q", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a document was written anyway")
	}
}

// Two components sharing one bom-ref is a document nothing can resolve a
// dependency against, and no JSON schema catches it: the schema does not
// cross-check metadata.component against the components array.
func TestAComponentCollidingWithTheSubjectsBomRefIsRefused(t *testing.T) {
	dir := t.TempDir()
	colliding := strings.Replace(buildrootFixture,
		`"bom-ref": "host-libzlib",`, `"bom-ref": "kelyfos:os",`, 1)
	if colliding == buildrootFixture {
		t.Fatal("the fixture no longer contains what this test edits")
	}
	in := filepath.Join(dir, "colliding.json")
	if err := os.WriteFile(in, []byte(colliding), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")

	if stderr, err := runTool(t, "aarch64", "arm64", "v1.1.2", in, out); err == nil {
		t.Fatalf("a component took the document's own subject bom-ref and nothing objected:\n%s", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a document was written anyway")
	}
}

// dedupe decides what two components are, and nothing else in this package
// tests it directly — the case it is guarding against is unreachable through
// the fixture, which is exactly why it needs a test of its own rather than
// coverage by accident.
//
// A bom-ref identifies a component. A component that has none falls back to its
// name and version, and the two kinds of key are namespaced apart and
// length-prefixed: without that, a component with no bom-ref keyed as
// `name@version` collides with one whose bom-ref is literally that string, and
// `{name: "a", version: "b@c"}` collides with `{name: "a@b", version: "c"}`.
// Each of those drops one of two genuinely different things, which is the
// defect this whole change is about, in miniature.
func TestDedupeKeepsThingsThatOnlyLookAlike(t *testing.T) {
	entryOf := func(ref, name, version string) entry {
		return entry{
			raw: []byte(`{"name":"` + name + `"}`),
			id:  identity{Name: name, Version: version, BOMRef: ref},
		}
	}
	for _, c := range []struct {
		why   string
		in    []entry
		count int
	}{
		{"one bom-ref is one component, however it is spelled elsewhere",
			[]entry{entryOf("go:x", "x", "v1"), entryOf("go:x", "x", "v2")}, 1},
		{"two bom-refs are two components, however alike the rest is",
			[]entry{entryOf("libzlib", "libzlib", "1.3.2"), entryOf("host-libzlib", "libzlib", "1.3.2")}, 2},
		{"a bom-ref that spells out another component's fallback key is still its own component",
			[]entry{entryOf("", "a", "1"), entryOf("a@1", "a", "1")}, 2},
		{"the fallback key cannot be made ambiguous by an @ inside a name or a version",
			[]entry{entryOf("", "a", "b@c"), entryOf("", "a@b", "c")}, 2},
		{"two components with neither a bom-ref nor a difference are one component",
			[]entry{entryOf("", "a", "1"), entryOf("", "a", "1")}, 1},
	} {
		if got := len(dedupe(c.in)); got != c.count {
			t.Errorf("%s: dedupe kept %d of %d, want %d", c.why, got, len(c.in), c.count)
		}
	}
}
