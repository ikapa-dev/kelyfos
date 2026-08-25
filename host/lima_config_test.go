package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The embedded Lima configuration and the one a developer edits are the same
// file (P6-12).
//
// There are two copies because they serve two people. `dev/lima.yaml` is what
// somebody working in this repository points `limactl` at; `host/lima.yaml` is
// compiled into the binary, because somebody who downloaded a release has no
// source tree to read a template out of.
//
// A second copy of the truth that nothing keeps honest is the defect the
// generated reference exists to prevent, so this is the thing that keeps it
// honest. Not a build step that copies one to the other, because that would
// hide which is the original; a check that fails loudly when they disagree, and
// names the command that fixes it.
func TestTheEmbeddedLimaConfigMatchesTheOneDevelopersEdit(t *testing.T) {
	root := filepath.Join("..")
	embedded, err := os.ReadFile(filepath.Join(root, "host", "lima.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(root, "dev", "lima.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(embedded) != string(source) {
		t.Errorf("host/lima.yaml and dev/lima.yaml have drifted apart.\n"+
			"  dev/lima.yaml is the one to edit; the other is compiled into the binary for\n"+
			"  people who have no source tree. Bring them back together with:\n"+
			"      cp dev/lima.yaml host/lima.yaml\n"+
			"  (%d bytes embedded, %d bytes in dev/)", len(embedded), len(source))
	}
}
