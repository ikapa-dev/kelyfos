package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Routed to this workstream: host/run.go's declined-`--review` path deleted
// both copies of a run's work when the diversion failed.
//
//	where, err := staged.Divert()
//	if err != nil { print it } else { print where }
//	recordReview(...)
//	_ = os.Remove(ws.ImagePath)     // unconditional
//
// with `defer staged.Discard()` already registered. A failed Divert therefore
// removed the workspace image AND, on the way out, the staging tree the
// extraction had just been written into — the only two places the session's
// work existed. It is the same rule the integrity workstream installed in
// syncResumedWorkspace twenty lines away: remove only after a write-back that
// actually happened.

type fakeDiverter struct {
	where     string
	err       error
	discarded bool
}

func (d *fakeDiverter) Divert() (string, error) { return d.where, d.err }
func (d *fakeDiverter) Discard()                { d.discarded = true }

func writeImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ws.ext4")
	if err := os.WriteFile(path, []byte("a workspace image"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAFailedDivertKeepsBothCopiesOfTheWork(t *testing.T) {
	image := writeImage(t)
	d := &fakeDiverter{err: os.ErrPermission}

	var out, errOut strings.Builder
	where, keep := finishDeclinedReview(d, "/work/project", image, &out, &errOut)

	if !keep {
		t.Error("a failed divert did not ask the caller to keep the staging tree; " +
			"the deferred Discard will delete the extraction")
	}
	if _, err := os.Stat(image); err != nil {
		t.Errorf("the workspace image was removed after the divert failed: %v", err)
	}
	if where != "" {
		t.Errorf("a failed divert reported a destination anyway: %q", where)
	}
	// The operator has to be told where the work is, or keeping it is pointless.
	msg := errOut.String()
	if !strings.Contains(msg, image) {
		t.Errorf("the failure does not name the image that was kept:\n%s", msg)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Errorf("the failure does not say what went wrong:\n%s", msg)
	}
	// And nothing was written back over the host directory, which is the whole
	// point of declining.
	if strings.Contains(out.String(), "written back") {
		t.Errorf("a failed divert claimed something was written back:\n%s", out.String())
	}
}

func TestASuccessfulDivertRemovesTheImageAndReportsWhere(t *testing.T) {
	image := writeImage(t)
	d := &fakeDiverter{where: "/work/project.kelyfos-1"}

	var out, errOut strings.Builder
	where, keep := finishDeclinedReview(d, "/work/project", image, &out, &errOut)

	if keep {
		t.Error("a successful divert asked the caller to keep the staging tree")
	}
	if where != d.where {
		t.Errorf("where = %q, want %q", where, d.where)
	}
	if _, err := os.Stat(image); !os.IsNotExist(err) {
		t.Error("the workspace image survived a successful divert; it is now a stale copy")
	}
	if !strings.Contains(out.String(), d.where) || !strings.Contains(out.String(), "/work/project") {
		t.Errorf("the summary does not name both directories:\n%s", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("a successful divert wrote to stderr:\n%s", errOut.String())
	}
}
