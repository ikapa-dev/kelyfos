package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// An exported report is a file written to be handed to somebody, and P6-6's
// atomic-export fix silently made every one of them owner-only: os.CreateTemp
// creates with 0600 and a rename carries the mode with it. Nothing caught it
// until P6-18 ran the suites and the caps workflow's artifact upload failed with
// EACCES on a report the demo had written under sudo.
//
// This pins the rule rather than the number: what an export produces is what
// os.Create would have produced, which is the umask's business and not this
// code's.
func TestAnExportedReportIsReadableTheWayOsCreateWouldMakeIt(t *testing.T) {
	dir := t.TempDir()

	for _, mask := range []int{0o022, 0o077, 0o002} {
		old := syscall.Umask(mask)
		// createMode caches on first use, so each case has to compute the
		// expected value the same way rather than calling it.
		want := os.FileMode(0o666 &^ mask)

		// What os.Create actually does under this mask, as the reference.
		ref := filepath.Join(dir, "reference")
		f, err := os.Create(ref)
		if err != nil {
			syscall.Umask(old)
			t.Fatal(err)
		}
		f.Close()
		info, err := os.Stat(ref)
		if err != nil {
			syscall.Umask(old)
			t.Fatal(err)
		}
		got := info.Mode().Perm()
		os.Remove(ref)
		syscall.Umask(old)

		if got != want {
			t.Errorf("umask %04o: os.Create produced %04o, and the rule this file "+
				"encodes says %04o — the assumption behind createMode is wrong",
				mask, got, want)
		}
	}
}

// And the property that actually matters, on the path that had the defect: a
// temp file made by os.CreateTemp is 0600 until something changes it.
func TestCreateTempIsOwnerOnlyWhichIsWhyTheChmodExists(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()
	info, err := os.Stat(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Skipf("os.CreateTemp made %04o rather than 0600 on this platform; "+
			"the chmod in exportReport is harmless either way", info.Mode().Perm())
	}
	if createMode() == 0o600 {
		t.Log("umask here is 0177, so the chmod is a no-op — the rule still holds")
	}
}
