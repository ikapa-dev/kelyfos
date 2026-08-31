// Command sbom merges everything in a KelyfOS release into one CycloneDX
// document (P6-10, D81).
//
// An image is built from three places and only one of them knows it is being
// inventoried:
//
//   - Buildroot's packages — the kernel, musl, busybox, everything in the guest
//     userland. `make show-info | utils/generate-cyclonedx` covers these, and
//     covers them well.
//   - The guest supervisor, which is PID 1. It is cross-compiled by KelyfOS's
//     own toolchain and arrives through the rootfs overlay rather than as a
//     Buildroot package, so **Buildroot has never heard of it** — an SBOM from
//     that source alone would omit the one component this project actually
//     wrote.
//   - The host CLI, which is not in the image at all and is in the release.
//
// An SBOM that is confidently incomplete is the supply-chain form of an audit
// record that is confidently wrong: it invites a reader to conclude something
// from an absence that only means nobody looked. So this merges all three, and
// the count it prints comes from the document it produced rather than from a
// number somebody wrote in a commit message.
//
// The Go halves are read with debug/buildinfo, which survives the -s -w this
// project strips its binaries with: those flags drop symbols and DWARF, not the
// build information. So the dependency list is the linker's own answer rather
// than go.mod's, which is the difference between what was built and what was
// declared.
//
// # Two rules, both learned by reading a published release (D81)
//
// **What this tool did not author, it does not re-encode.** Buildroot's
// components arrive as bytes and leave as the same bytes. Modelling a component
// with a struct and writing that struct back out is how the licence, the CPE,
// the source-tarball hashes and the patch pedigree of all forty-nine Buildroot
// packages were deleted from every SBOM this project ever published — 333 KB of
// input left as 11 KB of output, and nothing said so. The struct below is for
// *reading* identity out of a component in order to sort, deduplicate and hash
// it. It is never the shape anything is written back through.
//
// **The document says what it describes, and the architecture in it is checked
// rather than claimed.** -arch used to be validated non-empty, printed, and
// discarded, so both architectures' documents came out byte-identical and the
// two per-architecture attestations in release.yml each attached the same
// document to both sets of artifacts — the exact claim their separation exists
// to prevent. The architecture now reaches metadata.component, and every binary
// this tool opens has to agree with it: -arch is an assertion checked against
// each binary's own GOARCH, not a label copied into the output.
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// The CycloneDX version this tool writes, and the schema that validates it.
//
// 1.6 because that is what Buildroot's generate-cyclonedx emits, and the largest
// half of this document is its output passed through untouched. It used to say
// 1.5 while carrying 1.6 components, which was a statement about the document
// that nothing checked — so the Buildroot input's own specVersion is now
// compared against this constant and a mismatch stops the build.
const (
	specVersion = "1.6"
	schemaURL   = "http://cyclonedx.org/schema/bom-" + specVersion + ".schema.json"
)

// The Go architectures this release is cut for, under the names it files them
// by — the same `amd64:x86_64 arm64:aarch64` pairs `release-cli` loops over.
var unameArch = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

// doc is the document this tool writes. Components and dependencies are raw
// because they are somebody else's bytes: see the package comment.
type doc struct {
	BOMFormat   string `json:"bomFormat"`
	Schema      string `json:"$schema,omitempty"`
	SpecVersion string `json:"specVersion"`
	// SerialNumber is required, and finding that out cost a release candidate.
	//
	// `actions/attest` decides an SBOM is CycloneDX by testing three fields —
	// bomFormat, serialNumber and specVersion — and refuses the whole document
	// with "Unsupported SBOM format" if any is missing. Buildroot's generator
	// emits no serial number, so every SBOM this project produced was rejected
	// at the attestation step. Nothing caught it before v1.0-rc1 because no
	// release had ever run the workflow: the SBOM was generated, checksummed and
	// published, and only the attestation of it failed (P6-20).
	SerialNumber string            `json:"serialNumber"`
	Version      int               `json:"version"`
	Metadata     *metadata         `json:"metadata,omitempty"`
	Components   []json.RawMessage `json:"components"`
	Dependencies []json.RawMessage `json:"dependencies,omitempty"`
}

// inputDoc is what this tool reads out of a document it did not write. Every
// field it does not name survives anyway, because the parts it copies are
// copied as bytes.
type inputDoc struct {
	SpecVersion  string            `json:"specVersion"`
	Metadata     *inputMetadata    `json:"metadata"`
	Components   []json.RawMessage `json:"components"`
	Dependencies []json.RawMessage `json:"dependencies"`
}

type inputMetadata struct {
	Component json.RawMessage `json:"component"`
	Tools     *tools          `json:"tools"`
}

type metadata struct {
	Component *component `json:"component,omitempty"`
	Tools     *tools     `json:"tools,omitempty"`
}

// tools carries its entries verbatim for the same reason components do:
// Buildroot's generator names its own licence, and this tool models no licence
// field to put it back into.
type tools struct {
	Components []json.RawMessage `json:"components,omitempty"`
}

// component is what this tool authors: the Go halves and the document's own
// subject. Only the fields it sets are named.
type component struct {
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Version     string     `json:"version,omitempty"`
	PURL        string     `json:"purl,omitempty"`
	BOMRef      string     `json:"bom-ref,omitempty"`
	Description string     `json:"description,omitempty"`
	Properties  []property `json:"properties,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// identity is the part of any component — authored here or passed through —
// that this tool has to understand in order to order it, deduplicate it and
// hash it. Reading these five fields out of a component costs nothing that the
// component itself carries, because the component is written from its own bytes
// and not from this.
type identity struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	BOMRef  string `json:"bom-ref"`
}

// entry is one component: the bytes that will be written, beside the identity
// read out of them.
type entry struct {
	raw json.RawMessage
	id  identity
}

// serialFor derives the document's serial number from the document itself.
//
// A CycloneDX serial number is a URN UUID identifying this exact BOM, and the
// obvious implementation is a random one per run. That would be wrong here for a
// reason this project has already measured: two builds of one commit produce
// byte-identical artifacts (P6-9), and a random field would break that quietly —
// the SBOM would differ every time and repro-check would report a difference
// that means nothing. So it is a digest of the content instead: same subject and
// same components, same serial, and a change to any of them changes it.
//
// The subject is hashed first, and that is not decoration. Two documents that
// describe different architectures with the same component list would otherwise
// share a serial number — one identifier naming two different BOMs, which is
// worse than the identical documents it would replace, because a serial number
// is the field whose whole job is to tell them apart.
//
// Formatted as a v4-shaped UUID because the field's grammar demands one, with
// the version and variant nibbles set as the RFC requires. It is not random and
// does not pretend to be — the bytes underneath are SHA-256 of the content.
func serialFor(subject identity, components []identity) string {
	h := sha256.New()
	writeIdentity(h, subject)
	for _, c := range components {
		writeIdentity(h, c)
	}
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeIdentity(h io.Writer, c identity) {
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\n", c.Type, c.Name, c.Version, c.PURL, c.BOMRef)
}

func main() {
	var (
		from    = flag.String("buildroot", "", "CycloneDX JSON from `make show-info | utils/generate-cyclonedx`")
		out     = flag.String("out", "", "where to write the merged document")
		arch    = flag.String("arch", "", "architecture this release is for, checked against every binary read")
		version = flag.String("version", "", "the KelyfOS version being released")
	)
	var bins stringList
	flag.Var(&bins, "binary", "a Go binary to read build information from (repeatable)")
	flag.Parse()

	// -version and at least one -binary are required rather than optional, and
	// that is the point of this program rather than a formality. A document that
	// cannot say which version it describes is the defect being fixed, and an
	// architecture with no binary to check it against is a claim rather than a
	// fact.
	if *out == "" || *arch == "" || *version == "" || len(bins) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sbom -arch <arch> -version <version> -out <file> -binary <path> [-binary <path>]... [-buildroot <cdx.json>]")
		os.Exit(2)
	}

	merged := doc{BOMFormat: "CycloneDX", Schema: schemaURL, SpecVersion: specVersion, Version: 1}

	var (
		entries        []entry
		toolComponents []json.RawMessage
	)

	if *from != "" {
		raw, err := os.ReadFile(*from)
		if err != nil {
			die("read the Buildroot SBOM: %v", err)
		}
		var br inputDoc
		if err := json.Unmarshal(raw, &br); err != nil {
			die("the Buildroot SBOM is not readable: %v", err)
		}
		if br.SpecVersion != specVersion {
			die("the Buildroot SBOM is CycloneDX %s and this document says %s: passing its components through "+
				"would relabel them as a version they were not generated for. Read what changed between the two "+
				"schemas, then move specVersion in tools/sbom.", br.SpecVersion, specVersion)
		}
		for _, c := range br.Components {
			entries = append(entries, passedThrough(c, *from))
		}
		// Buildroot was the subject of its own document and is a component of
		// this one: the guest userland is built from it, and dropping the row
		// would lose which Buildroot built it. Its bom-ref is what the
		// dependency graph below is rooted at, so it has to survive by name.
		if br.Metadata != nil {
			if len(br.Metadata.Component) > 0 {
				entries = append(entries, passedThrough(br.Metadata.Component, *from))
			}
			if br.Metadata.Tools != nil {
				toolComponents = append(toolComponents, br.Metadata.Tools.Components...)
			}
		}
		// Buildroot's own dependency graph, rooted at its own bom-ref. It says
		// how Buildroot's packages relate and claims nothing about this
		// document's subject, which is the only reason it can be copied without
		// being extended: a graph rooted at KelyfOS that named only half the
		// components would be a worse statement than no graph at all.
		merged.Dependencies = br.Dependencies
		fmt.Fprintf(os.Stderr, "buildroot: %d components\n", len(br.Components))
	}

	for _, path := range bins {
		got, goos, goarch, err := fromBinary(path)
		if err != nil {
			die("%s: %v", path, err)
		}
		named, ok := unameArch[goarch]
		if !ok {
			die("%s: is built for GOARCH %q, which this release has no filename for; add it beside the "+
				"Makefile's own amd64:x86_64 arm64:aarch64 pairs", path, goarch)
		}
		if named != *arch {
			die("%s: is built for %s (GOOS=%s GOARCH=%s) and this SBOM says it is for %s. One of the two is "+
				"wrong, and a document that guesses which is the thing this check exists to prevent.",
				path, named, goos, goarch, *arch)
		}
		for _, c := range got {
			entries = append(entries, authored(c))
		}
		fmt.Fprintf(os.Stderr, "%s: %d components (%s/%s)\n", path, len(got), goos, goarch)
	}

	entries = dedupe(entries)
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].id, entries[j].id
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		// bom-ref last, and not for tidiness: `libzlib` and `host-libzlib` are
		// one name at one version, and sort.Slice is not stable. Without a total
		// order here two runs of one commit could order them differently, which
		// is the byte-identical build P6-9 measured, broken by a comparator.
		return a.BOMRef < b.BOMRef
	})

	// The subject. Named, versioned, and tied to one architecture — the three
	// things a reader of sbom-x86_64.cdx.json could not learn from it before,
	// because the merge copied Buildroot's metadata verbatim and the document
	// went out declaring itself to be "buildroot 2025.02.17".
	subject := component{
		Type:        "operating-system",
		Name:        "kelyfos",
		Version:     *version,
		PURL:        "pkg:generic/kelyfos@" + *version + "?arch=" + *arch,
		BOMRef:      "kelyfos",
		Description: "KelyfOS " + *version + " for " + *arch,
		Properties: []property{
			{Name: "kelyfos:architecture", Value: *arch},
		},
	}
	merged.Metadata = &metadata{Component: &subject}

	self, err := json.Marshal(component{
		Type:        "application",
		Name:        "KelyfOS sbom",
		Version:     *version,
		Description: "tools/sbom, which merged this document",
	})
	if err != nil {
		die("%v", err)
	}
	merged.Metadata.Tools = &tools{Components: append(toolComponents, self)}

	ids := make([]identity, len(entries))
	merged.Components = make([]json.RawMessage, len(entries))
	for i, e := range entries {
		ids[i] = e.id
		merged.Components[i] = e.raw
	}
	merged.SerialNumber = serialFor(identityOf(subject), ids)

	body, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(*out, append(body, '\n'), 0o644); err != nil {
		die("%v", err)
	}

	// The count comes from the document, not from a number transcribed into a
	// release note. A total that is written down by hand is a total that is
	// right once.
	fmt.Printf("%s: %d components for kelyfos %s on %s\n", *out, len(merged.Components), *version, *arch)
}

// fromBinary reads a Go binary's own account of what went into it, and of what
// it was built for.
//
// GOOS and GOARCH come from the binary rather than from the -arch flag because
// the binary knows and the flag is a claim. They are also what makes the two
// architectures' documents differ: the same modules resolved for arm64 and for
// amd64 are the same modules, and before these were recorded the whole document
// came out identical for both.
func fromBinary(path string) (components []component, goos, goarch string, err error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, "", "", err
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS":
			goos = s.Value
		case "GOARCH":
			goarch = s.Value
		}
	}
	if goos == "" || goarch == "" {
		return nil, "", "", fmt.Errorf("carries no GOOS/GOARCH in its build information, so nothing here can say what it was built for")
	}
	platform := goos + "/" + goarch

	name := bi.Path
	if name == "" {
		name = path
	}
	out := []component{{
		Type:        "application",
		Name:        name,
		Version:     firstNonEmpty(bi.Main.Version, "(devel)"),
		PURL:        "pkg:golang/" + name + "@" + firstNonEmpty(bi.Main.Version, "devel") + "?goos=" + goos + "&goarch=" + goarch,
		BOMRef:      "go:" + name + "@" + platform,
		Description: "built with " + bi.GoVersion + " for " + platform,
		Properties: []property{
			{Name: "kelyfos:goos", Value: goos},
			{Name: "kelyfos:goarch", Value: goarch},
		},
	}}
	// The toolchain is a component. A guest userland whose compiler is not in
	// the inventory is an inventory with a hole exactly where a supply-chain
	// question would be asked.
	out = append(out, component{
		Type: "application", Name: "go", Version: strings.TrimPrefix(bi.GoVersion, "go"),
		PURL: "pkg:generic/go@" + strings.TrimPrefix(bi.GoVersion, "go"), BOMRef: "toolchain:" + bi.GoVersion,
	})
	for _, d := range bi.Deps {
		if d.Replace != nil {
			d = d.Replace
		}
		out = append(out, component{
			Type: "library", Name: d.Path, Version: d.Version,
			PURL:   "pkg:golang/" + d.Path + "@" + d.Version,
			BOMRef: "go:" + d.Path + "@" + d.Version,
		})
	}
	return out, goos, goarch, nil
}

// passedThrough keeps a component nobody here wrote exactly as it arrived.
func passedThrough(raw json.RawMessage, from string) entry {
	var id identity
	if err := json.Unmarshal(raw, &id); err != nil {
		die("a component in %s is not readable: %v", from, err)
	}
	if id.Name == "" {
		die("a component in %s has no name, so nothing can order or deduplicate it", from)
	}
	return entry{raw: raw, id: id}
}

// authored encodes a component this tool wrote.
func authored(c component) entry {
	raw, err := json.Marshal(c)
	if err != nil {
		die("%v", err)
	}
	return entry{raw: raw, id: identityOf(c)}
}

func identityOf(c component) identity {
	return identity{Type: c.Type, Name: c.Name, Version: c.Version, PURL: c.PURL, BOMRef: c.BOMRef}
}

// dedupe keeps one entry per bom-ref.
//
// The two Go binaries share dependencies, and the same library listed twice is
// not two libraries. It used to key on name and version, which collapsed
// `libzlib` into `host-libzlib`: one name and one version describing two
// different builds of one package, the target's and the build machine's. The
// published v1.1 and v1.1.1 SBOMs list the *host* OpenSSL, zlib, libffi and
// python3 and not the ones in the image, and which of each pair survived was
// decided by the order Buildroot happened to emit them in. A bom-ref is the
// identifier CycloneDX gives a component for exactly this reason, and the
// dependency graph refers to components by it.
func dedupe(in []entry) []entry {
	seen := map[string]bool{}
	var out []entry
	for _, e := range in {
		k := e.id.BOMRef
		if k == "" {
			k = e.id.Name + "@" + e.id.Version
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sbom: "+format+"\n", args...)
	os.Exit(1)
}
