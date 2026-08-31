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
	buildrootAt string
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

	buildrootAt = filepath.Join(dir, "sbom-buildroot.json")
	if err := os.WriteFile(buildrootAt, []byte(buildrootFixture), 0o644); err != nil {
		fixtureErr = err
	}
}

// release runs the tool the way `make release-sbom` runs it, for one
// architecture, and returns the bytes it wrote.
func release(t *testing.T, arch, goarch, version, out string) []byte {
	t.Helper()
	tool := theTool(t)
	args := []string{"-arch", arch, "-version", version, "-out", out, "-buildroot", buildrootAt}
	for _, b := range fixtureBins[goarch] {
		args = append(args, "-binary", b)
	}
	cmd := exec.Command(tool, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sbom %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return body
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

	armDoc, x86Doc := parse(t, arm), parse(t, x86)
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

	args := []string{"-arch", "x86_64", "-version", "v1.1.2", "-out", out, "-buildroot", buildrootAt}
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
