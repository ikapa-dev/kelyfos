package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest is the provenance record written beside every built or fetched
// image (D21). It exists so the host never has to take the caller's word for
// which image is booting: the flight recorder's session.start carries the
// flavor, and an audit record that is confidently wrong is worse than none.
type Manifest struct {
	Schema       int    `json:"schema"`
	Arch         string `json:"arch"`
	Flavor       string `json:"flavor"`
	Kernel       string `json:"kernel"`
	KernelSHA256 string `json:"kernel_sha256"`
	Rootfs       string `json:"rootfs"`
	RootfsSHA256 string `json:"rootfs_sha256"`
	Buildroot    string `json:"buildroot"`
	Linux        string `json:"linux"`
	Built        string `json:"built"`
}

// ReadManifest loads image.json from an image directory.
func ReadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "image.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("image.json in %s is not valid JSON: %w", dir, err)
	}
	return &m, nil
}

// checkManifest verifies that the image on disk is the one the caller asked
// for. A missing manifest is a hard error rather than a silent pass: a silent
// fallback is exactly how the mislabelling bug survived unnoticed.
func checkManifest(dir, arch, flavor string) error {
	m, err := ReadManifest(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no image.json in %s — this image predates the manifest.\n"+
				"    rebuild:  make image ARCH=%s FLAVOR=%s\n"+
				"    or fetch: make fetch-image ARCH=%s", dir, arch, flavor, arch)
		}
		return err
	}
	if m.Arch != arch {
		return fmt.Errorf("image in %s is built for %s, not %s", dir, m.Arch, arch)
	}
	if m.Flavor != flavor {
		return fmt.Errorf("requested --image %s but %s holds the %q image.\n"+
			"    run it:   kelyfos run --image %s\n"+
			"    or build: make image ARCH=%s FLAVOR=%s",
			flavor, dir, m.Flavor, m.Flavor, arch, flavor)
	}
	return nil
}
