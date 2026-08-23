package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// The plugins device (E4-6, F-D6).
//
// Each declared plugin's directory is packed into a read-only ext4 image,
// attached as a virtio-blk drive and mounted at /plugins. ext4 rather than
// squashfs because both ride virtio-blk equally well and squashfs would mean
// adding CONFIG_SQUASHFS to the P1-2 kernel fragments — a kernel config change
// for marginal gain.
//
// The device is storage; plugins.json is the list. A directory present on the
// device and absent from the manifest is not launched, which is the same
// relationship image.json has to an image directory and exists for the reason
// D21 gives: the host should not assert a fact it has not checked.

// pluginsMinSize is the floor for the image.
//
// Small, unlike the workspace's gigabyte, because nothing in the guest writes
// here: the drive is attached read-only. The doubling below is not headroom for
// growth, it is room for ext4's own metadata, and a floor is what keeps a
// three-file plugin from asking mke2fs for an image too small to format.
const pluginsMinSize = 16 << 20

// PluginSpec is one plugin the host was asked to pack.
type PluginSpec struct {
	Name string
	// Dir is the host directory holding the plugin's files, already resolved
	// against the policy file rather than against a working directory.
	Dir     string
	Command string
	Args    []string
}

// PluginEntry is one line of plugins.json: the host's account of what it packed.
type PluginEntry struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	// SHA256 is a digest of the packed directory's contents — names, modes and
	// bytes — so the supervisor can say what it launched and a reader can tell
	// two builds of the same plugin apart.
	SHA256 string `json:"sha256"`
}

// Plugins is a built plugins image.
type Plugins struct {
	ImagePath string
	Entries   []PluginEntry
	// Device is where the guest will find it, decided by the host when the
	// drives are ordered and passed on the kernel command line. Pinned rather
	// than discovered, for the reason the workspace's is: the supervisor should
	// not have to guess which disk is which.
	Device string
}

// PackPlugins builds the read-only image from the declared plugins.
//
// Everything is staged into a directory first and mke2fs populates the image
// from that in one pass, so no image is ever half-written and nothing has to be
// mounted — the same property that keeps PackWorkspace from needing root.
func PackPlugins(specs []PluginSpec, imagePath string) (*Plugins, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	// The directory has to exist before anything is staged into it or measured
	// against it — on a machine that has never packed one, it does not.
	if err := os.MkdirAll(filepath.Dir(imagePath), 0o700); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(filepath.Dir(imagePath), "plugins-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)

	entries := make([]PluginEntry, 0, len(specs))
	for _, spec := range specs {
		info, err := os.Stat(spec.Dir)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", spec.Name, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("plugin %s: %s is not a directory", spec.Name, spec.Dir)
		}
		packed := filepath.Join(staging, spec.Name)
		if err := copyTree(spec.Dir, packed); err != nil {
			return nil, fmt.Errorf("pack plugin %s: %w", spec.Name, err)
		}
		// Digested after the copy, so the manifest describes what was packed
		// rather than what it was packed from.
		digest, err := digestTree(packed)
		if err != nil {
			return nil, err
		}
		entries = append(entries, PluginEntry{
			Name: spec.Name, Command: spec.Command, Args: spec.Args, SHA256: digest,
		})
	}

	blob, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "plugins.json"), append(blob, '\n'), 0o644); err != nil {
		return nil, err
	}

	used, err := dirSize(staging)
	if err != nil {
		return nil, err
	}
	size := used * 2
	if size < pluginsMinSize {
		size = pluginsMinSize
	}
	if err := checkFreeSpace(filepath.Dir(imagePath), size); err != nil {
		return nil, err
	}
	_ = os.Remove(imagePath)
	out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", staging, imagePath, fmt.Sprintf("%dk", size/1024)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pack plugins: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// The drive is attached read-only, and the file is made read-only too. The
	// first is what the guest is held to; the second is what stops a mistake on
	// this side of the wall from editing a device a machine is running on.
	if err := os.Chmod(imagePath, 0o400); err != nil {
		return nil, err
	}
	return &Plugins{ImagePath: imagePath, Entries: entries}, nil
}

// device is the guest device path, or "" when there are no plugins. A method on
// the pointer so a caller does not have to nil-check before asking.
func (p *Plugins) device() string {
	if p == nil {
		return ""
	}
	return p.Device
}

// Names lists what was packed, in declaration order.
func (p *Plugins) Names() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Entries))
	for _, e := range p.Entries {
		out = append(out, e.Name)
	}
	return out
}

// copyTree copies a directory into dst, following the same rules PackWorkspace
// relies on mke2fs for: regular files and directories, with their modes.
// Symlinks are copied as links; anything else — a socket left by a dev server,
// a device node — is skipped rather than packed, because it cannot mean
// anything inside a fresh machine.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm())
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			return copyFile(path, target)
		default:
			return nil
		}
	})
}

// digestTree hashes a directory by what is in it: every path, its mode, and for
// a regular file its bytes, in sorted order.
//
// Deliberately not Fingerprint, which hashes names, sizes and modification
// times. That is exactly right for noticing that a workspace changed under a
// running sandbox, and exactly wrong for a manifest: the same files packed
// twice would have two different digests, so a reader could not use it to tell
// whether two builds hold the same plugin — which is the only question the
// field is there to answer.
func digestTree(dir string) (string, error) {
	h := sha256.New()
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	for _, path := range paths {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s|%o|%d\n", rel, info.Mode().Perm(), info.Mode()&fs.ModeType)
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(h, "->%s\n", link)
		case info.Mode().IsRegular():
			f, err := os.Open(path)
			if err != nil {
				return "", err
			}
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
