package sandbox

// HostileImage builds a workspace image of the kind a guest can write, for the
// tests that check what the host does when it reads one.
//
// It lives beside the product rather than in a test file because two packages
// need it — the extraction is here and the CLI's own tests want the same images
// — and because a helper that manufactures the attack is worth reading next to
// the code that has to survive it.
//
// Nothing in the product calls it. It is here, exported, and unused by anything
// that ships: the alternative is a copy in each test package, and two copies of
// an attack drift into two different attacks.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// HostileName is a directory entry a guest writes and a host must refuse.
//
// The placeholder is a name the host filesystem will accept, long enough to
// reserve room for the crafted one that replaces it in the built image. A guest
// crafting a dirent for real has no such constraint — it writes the record
// itself — but a fixture assembled on the host does, and a fixture that grew a
// record would be testing its own arithmetic rather than the host's behaviour.
type HostileName struct {
	// Key names the case for the ledger and for the subtest. It is a slug
	// rather than the name itself because these names contain bytes that are
	// not text — a NUL cannot be written into a ledger file and read back as
	// the same key, and a case whose key silently never matches is a case the
	// ledger cannot see.
	Key         string
	Placeholder string // what mke2fs is asked to create
	Crafted     string // what the image ends up carrying; never longer
	Why         string
}

// EscapingNames are the shapes that reach outside the directory they are
// extracted into, or that name something that is not a name at all.
func EscapingNames() []HostileName {
	return []HostileName{
		{"climbs-out", "AAAAAAAAAA", "../../pwn.", "climbs out of the extraction directory"},
		{"nul-in-name", "BBBBBBBBBBBBBBBB", "..\x00hidden.conf", "a NUL, which ends a name in C and not in Go"},
		{"separator-in-name", "CCCCCCCCCCCC", "sub/nested.x", "a separator inside a single entry"},
		{"names-the-parent", "DDDDDDDDDDDDDDDDDDDD", "..", "the parent directory, named as an entry"},
		{"absolute", "EEEEEEEEEEEEEE", "/etc/kelyfos", "an absolute path as an entry"},
	}
}

// BuildHostileImage writes an ext4 image carrying one crafted directory entry.
//
// The image is built without metadata_csum so the crafted name leaves a *valid*
// filesystem. That models the attacker rather than avoiding a defence: the guest
// owns the block device, so it computes any checksum the format asks for, and a
// host that leaned on ext4's own integrity would be leaning on the guest.
func BuildHostileImage(imagePath string, name HostileName, contents string) error {
	if len(name.Crafted) > len(name.Placeholder) {
		return fmt.Errorf("hostile name %q is longer than its placeholder %q; a longer name would move"+
			" every record after it", name.Crafted, name.Placeholder)
	}
	src, err := os.MkdirTemp("", "kelyfos-hostile-src-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(src)
	if err := os.WriteFile(filepath.Join(src, name.Placeholder), []byte(contents), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(imagePath), 0o700); err != nil {
		return err
	}
	out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F", "-O", "^metadata_csum",
		"-d", src, imagePath, "1024k").CombinedOutput()
	if err != nil {
		return fmt.Errorf("build hostile image: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return patchName(imagePath, name.Placeholder, name.Crafted)
}

// BuildImageWithModes writes an image whose single file carries a mode the guest
// chose. A host that restores guest-chosen modes onto its own filesystem hands
// the guest a say in what the host's files permit.
func BuildImageWithModes(imagePath string, mode os.FileMode) error {
	src, err := os.MkdirTemp("", "kelyfos-hostile-modes-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(src)
	f := filepath.Join(src, "wide-open")
	if err := os.WriteFile(f, []byte("anyone can write this\n"), 0o644); err != nil {
		return err
	}
	// Written and then chmod'd, because WriteFile's mode is masked by umask and
	// the point of the fixture is a mode nobody's umask would allow.
	if err := os.Chmod(f, mode); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(imagePath), 0o700); err != nil {
		return err
	}
	out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", src, imagePath, "1024k").CombinedOutput()
	if err != nil {
		return fmt.Errorf("build modes image: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// patchName overwrites a directory entry's name in place.
//
// The placeholder reserves the room, so the replacement is never longer and the
// entry's record length, the block's free space and every offset after it stay
// exactly as mke2fs left them. A shorter name needs one more byte changed:
// ext4's dirent is inode(4) rec_len(2) name_len(1) file_type(1) name…, so
// name_len sits two bytes before the name and says how much of the reserved room
// is the name. The rest becomes padding, which the format already allows for —
// rec_len is what the reader walks by.
//
// This is how a fixture reaches names a filesystem will not let you create:
// `..` already exists in every directory, and `a/b` and a NUL are not names the
// host kernel would accept at all. The guest does not need this trick — it
// writes the dirent itself — but a fixture built on the host does.
func patchName(imagePath, from, to string) error {
	img, err := os.ReadFile(imagePath)
	if err != nil {
		return err
	}
	i := strings.Index(string(img), from)
	if i < 0 {
		return fmt.Errorf("placeholder %q is not in the image: mke2fs did not lay it out as expected", from)
	}
	if i < 2 {
		return fmt.Errorf("placeholder %q is at offset %d, which is not a directory entry", from, i)
	}
	for j := range from {
		img[i+j] = 0
	}
	copy(img[i:], to)
	img[i-2] = byte(len(to)) // name_len
	return os.WriteFile(imagePath, img, 0o600)
}

// HostileWorkspace wires an image into the type the extraction path takes, so a
// test can drive Stage exactly as a finished sandbox does.
func HostileWorkspace(hostDir, imagePath string) *Workspace {
	fp, _ := Fingerprint(hostDir)
	return &Workspace{HostDir: hostDir, ImagePath: imagePath, fingerprint: fp}
}
