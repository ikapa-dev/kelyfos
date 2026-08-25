package main

import (
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// What this file checks is not this program. It is the agreement between the
// Makefile that produces a release and the workflows that make claims about
// one — an agreement nothing enforced, and which had quietly broken by the time
// anybody read the two files side by side.
//
// The shape of that break is worth naming, because it is the shape this kind of
// break always has: one side grew and the other did not. `make release-cli`
// learned to build a macOS CLI, the release started shipping it, and the two
// statements the release makes about its artifacts — this is what is in them,
// and these bytes rebuild identically — were both still written for the Linux
// pair. Nothing failed. A release simply began asserting something no one had
// checked, and would have gone on doing it.
//
// So the assertions below read both files rather than a list transcribed here.
// A list written here is a list that is right on the day it is written, which
// is the failure being fixed rather than a fix for it.

// makefileRecipe returns the recipe lines of one target, verbatim.
//
// Recipe lines are the tab-indented ones after the target line; a blank line
// inside a recipe is ignored by make and is ignored here too, so a target that
// grows a paragraph break does not silently truncate to nothing.
func makefileRecipe(t *testing.T, target string) string {
	t.Helper()
	body, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(body), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, target+":") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("the Makefile has no %s target; this test describes a build that no longer exists", target)
	}
	var out []string
	for _, l := range lines[start+1:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(l, "\t") {
			break
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		t.Fatalf("%s has an empty recipe", target)
	}
	return strings.Join(out, "\n")
}

var (
	// -o $(CURDIR)/dist/kelyfos-linux-$$uarch, once per operating system.
	stagedBinary = regexp.MustCompile(`-o \$\(CURDIR\)/dist/kelyfos-([a-z0-9]+)-\$\$uarch`)
	// The `amd64:x86_64 arm64:aarch64` pairs the loops iterate over.
	stagedArch = regexp.MustCompile(`\b[a-z0-9]+:([a-z0-9_]+)\b`)
	// -binary $(CURDIR)/dist/kelyfos-linux-$(ARCH), once per operating system.
	sbomBinary = regexp.MustCompile(`-binary \$\(CURDIR\)/dist/kelyfos-([a-z0-9]+)-\$\(ARCH\)`)
	// Any shell glob in a workflow that names these binaries, wherever it
	// points: dist/, /tmp/first/, the second checkout's dist/.
	binaryGlob = regexp.MustCompile(`[\w./$"{}-]*/(kelyfos-[\w*?.-]*)`)
)

// releasedPlatforms is the set of operating systems `make release-cli` stages
// into dist/, and the set of architectures it stages each of them for.
func releasedPlatforms(t *testing.T) (oses, arches []string) {
	t.Helper()
	recipe := makefileRecipe(t, "release-cli")
	for _, m := range stagedBinary.FindAllStringSubmatch(recipe, -1) {
		oses = append(oses, m[1])
	}
	seen := map[string]bool{}
	for _, m := range stagedArch.FindAllStringSubmatch(recipe, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			arches = append(arches, m[1])
		}
	}
	if len(oses) < 2 || len(arches) < 2 {
		t.Fatalf("release-cli no longer parses as a cross-build over OSes and arches: %v / %v", oses, arches)
	}
	return oses, arches
}

// The release attests each architecture's SBOM against a glob — `dist/*aarch64*`
// or `dist/*x86_64*` — which matches every CLI binary staged for that
// architecture, the macOS one as surely as the Linux one. An attestation is a
// signed statement that this document describes those bytes, so every binary
// the glob sweeps up has to be a binary the SBOM actually opened.
//
// It is not enough that the answer comes out the same. The macOS build of
// ./host resolves the same modules the Linux build does, so reading it adds no
// component today — and that is exactly why this went unnoticed. What reading
// it buys is that a dependency arriving on darwin only shows up in the
// document, rather than turning a signed claim false with nobody told.
func TestEverySBOMSubjectIsABinaryTheSBOMRead(t *testing.T) {
	oses, _ := releasedPlatforms(t)

	recipe := makefileRecipe(t, "release-sbom")
	read := map[string]bool{}
	for _, m := range sbomBinary.FindAllStringSubmatch(recipe, -1) {
		read[m[1]] = true
	}

	for _, os := range oses {
		if !read[os] {
			t.Errorf("the release ships dist/kelyfos-%s-$(ARCH) and attests the SBOM against a glob that "+
				"matches it, but release-sbom never passes it to -binary: the attestation would claim an "+
				"SBOM describes a binary it never opened", os)
		}
	}

	// The supervisor is the one component this project actually wrote and the
	// one Buildroot has never heard of, since it arrives through the rootfs
	// overlay rather than as a package. An inventory that lost it would have a
	// hole exactly where a supply-chain question gets asked.
	if !strings.Contains(recipe, "-binary $(GUEST_OVERLAY)/sbin/kelyfos-supervisor") {
		t.Error("release-sbom no longer reads the guest supervisor, which Buildroot cannot report on")
	}
}

// The README publishes a table of what rebuilds byte-identically, sourced from
// the repro-check workflow, and the scope of that measurement is part of its
// result. A check that measured the Linux pair while the release shipped four
// binaries left the two a macOS user downloads outside the only statement this
// project makes about them — under a heading that named the check by its own
// filename.
//
// So every binary the release ships has to be one every glob in that job
// sweeps up. Every glob rather than any: the job copies the first build aside
// and then loops over what it copied, and widening one of those two without the
// other narrows the measurement just as effectively as never widening either.
func TestEveryReleasedCLIBinaryIsMeasuredForReproducibility(t *testing.T) {
	oses, arches := releasedPlatforms(t)

	body, err := os.ReadFile("../../.github/workflows/repro-check.yml")
	if err != nil {
		t.Fatal(err)
	}
	var globs []string
	for _, m := range binaryGlob.FindAllStringSubmatch(string(body), -1) {
		globs = append(globs, m[1])
	}
	if len(globs) == 0 {
		t.Fatal("repro-check no longer refers to the CLI binaries at all")
	}

	for _, goos := range oses {
		for _, arch := range arches {
			name := "kelyfos-" + goos + "-" + arch
			for _, g := range globs {
				ok, err := path.Match(g, name)
				if err != nil {
					t.Fatalf("%q is not a glob: %v", g, err)
				}
				if !ok {
					t.Errorf("the release ships %s, and repro-check's glob %q does not match it: "+
						"that binary is never compared across the two builds", name, g)
				}
			}
		}
	}
}

// The three fields actions/attest tests for, and the property a random one would
// have broken (P6-20).
//
// `actions/attest` decides a document is CycloneDX by checking bomFormat,
// serialNumber and specVersion, and refuses the whole SBOM with "Unsupported
// SBOM format" if any is absent. Buildroot's generator emits no serial number,
// so every SBOM this project produced was rejected at the attestation step —
// and nothing found out until v1.0-rc1, because no release had ever run the
// workflow that attests them.
//
// The second assertion is the one worth keeping: the serial has to be derived
// from the content rather than generated, or two builds of one commit stop
// producing byte-identical artifacts and P6-9's measurement quietly stops
// meaning anything.
func TestTheSerialNumberIsPresentAndDerivedRatherThanRandom(t *testing.T) {
	components := []component{
		{Type: "library", Name: "zlib", Version: "1.3.1"},
		{Type: "library", Name: "busybox", Version: "1.36.1"},
	}

	got := serialFor(components)
	if got == "" {
		t.Fatal("no serial number: actions/attest refuses the document without one")
	}
	if !strings.HasPrefix(got, "urn:uuid:") {
		t.Errorf("serial %q is not a URN UUID, which is the field's grammar", got)
	}
	// Same content, same serial — the whole point.
	if again := serialFor(components); again != got {
		t.Errorf("two calls over the same components gave different serials:\n  %s\n  %s\n"+
			"A serial that changes per run breaks the byte-identical build P6-9 measured.", got, again)
	}
	// Different content, different serial — otherwise it is not identifying anything.
	changed := append([]component{}, components...)
	changed[0].Version = "1.3.2"
	if serialFor(changed) == got {
		t.Error("changing a component's version did not change the serial")
	}
}
