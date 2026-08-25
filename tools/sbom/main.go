// Command sbom merges everything in a KelyfOS release into one CycloneDX
// document (P6-10).
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
package main

import (
	"debug/buildinfo"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// A CycloneDX document, in the shape this tool needs to read one and write one.
// Only the fields that are used are named: a struct that mirrored the whole
// specification would be a second specification to keep correct.
type doc struct {
	BOMFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Version     int             `json:"version"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Components  []component     `json:"components"`
}

type component struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl,omitempty"`
	BOMRef     string `json:"bom-ref,omitempty"`
	Publisher  string `json:"publisher,omitempty"`
	Descriptio string `json:"description,omitempty"`
}

func main() {
	var (
		from    = flag.String("buildroot", "", "CycloneDX JSON from `make show-info | utils/generate-cyclonedx`")
		out     = flag.String("out", "", "where to write the merged document")
		arch    = flag.String("arch", "", "architecture this release is for")
		version = flag.String("version", "", "the KelyfOS version being released")
	)
	var bins stringList
	flag.Var(&bins, "binary", "a Go binary to read build information from (repeatable)")
	flag.Parse()

	if *out == "" || *arch == "" {
		fmt.Fprintln(os.Stderr, "usage: sbom -arch <arch> -out <file> [-buildroot <cdx.json>] [-binary <path>]...")
		os.Exit(2)
	}

	merged := doc{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}

	if *from != "" {
		raw, err := os.ReadFile(*from)
		if err != nil {
			die("read the Buildroot SBOM: %v", err)
		}
		var br doc
		if err := json.Unmarshal(raw, &br); err != nil {
			die("the Buildroot SBOM is not readable: %v", err)
		}
		merged.Components = append(merged.Components, br.Components...)
		merged.Metadata = br.Metadata
		fmt.Fprintf(os.Stderr, "buildroot: %d components\n", len(br.Components))
	}

	for _, path := range bins {
		got, err := fromBinary(path)
		if err != nil {
			die("%s: %v", path, err)
		}
		merged.Components = append(merged.Components, got...)
		fmt.Fprintf(os.Stderr, "%s: %d components\n", path, len(got))
	}

	merged.Components = dedupe(merged.Components)
	sort.Slice(merged.Components, func(i, j int) bool {
		if merged.Components[i].Name != merged.Components[j].Name {
			return merged.Components[i].Name < merged.Components[j].Name
		}
		return merged.Components[i].Version < merged.Components[j].Version
	})

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
	fmt.Printf("%s: %d components for %s", *out, len(merged.Components), *arch)
	if *version != "" {
		fmt.Printf(" (%s)", *version)
	}
	fmt.Println()
}

// fromBinary reads a Go binary's own account of what went into it.
func fromBinary(path string) ([]component, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, err
	}
	name := bi.Path
	if name == "" {
		name = path
	}
	out := []component{{
		Type:       "application",
		Name:       name,
		Version:    firstNonEmpty(bi.Main.Version, "(devel)"),
		PURL:       "pkg:golang/" + name + "@" + firstNonEmpty(bi.Main.Version, "devel"),
		BOMRef:     "go:" + name,
		Descriptio: "built with " + bi.GoVersion,
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
	return out, nil
}

// dedupe keeps one entry per name and version.
//
// The two Go binaries share dependencies, and the same library listed twice is
// not two libraries. Deduplicated on what identifies a component rather than on
// the whole struct, so two entries that describe one thing differently still
// collapse.
func dedupe(in []component) []component {
	seen := map[string]bool{}
	var out []component
	for _, c := range in {
		k := c.Name + "@" + c.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
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
