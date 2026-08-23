package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PackPlugins runs mke2fs, which is not on every machine these tests run on, so
// the image build is exercised where it can be and the parts that decide what
// goes into the manifest are exercised everywhere.

func TestNoPluginsIsNoDevice(t *testing.T) {
	got, err := PackPlugins(nil, filepath.Join(t.TempDir(), "p.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("a project declaring no plugins got a device: %+v", got)
	}
	// And the nil accessor answers rather than panicking, because every caller
	// asks it before knowing whether there is one.
	if got.device() != "" || got.Names() != nil {
		t.Error("the nil device is not answering as absent")
	}
}

// The digest has to describe the contents. Fingerprint — which the workspace
// uses — mixes in modification times, so the same files packed twice would have
// two different digests and the field could not answer the only question it is
// there for.
func TestTheDigestIsOfTheContentsAndNothingElse(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, dir := range []string{a, b} {
		if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte("console.log(1)\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lib", "x.js"), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Two copies of the same tree, written at different moments.
	da, err := digestTree(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := digestTree(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Errorf("the same contents digested differently:\n  %s\n  %s", da, db)
	}

	// And a changed byte has to change it.
	if err := os.WriteFile(filepath.Join(b, "server.js"), []byte("console.log(2)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := digestTree(b)
	if err != nil {
		t.Fatal(err)
	}
	if changed == da {
		t.Error("an edited file did not change the digest")
	}
}

// The device names the guest sees are decided by drive order, and the plugins
// drive is not always third: it is second when there is no workspace. Getting
// this wrong would mount the root filesystem over /plugins.
func TestDriveDeviceFollowsDriveOrder(t *testing.T) {
	for i, want := range []string{"/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd"} {
		if got := driveDevice(i); got != want {
			t.Errorf("driveDevice(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestThePluginsDriveIsReadOnlyAndPlacedByOrder(t *testing.T) {
	plugins := &Plugins{ImagePath: "/tmp/p.ext4"}
	cfg := firecrackerConfig(Options{Arch: "x86_64", Plugins: plugins}, "k", "r", "u", "id")
	if len(cfg.Drives) != 2 {
		t.Fatalf("got %d drives, want the root and the plugins", len(cfg.Drives))
	}
	if cfg.Drives[1].DriveID != "plugins" || !cfg.Drives[1].IsReadOnly {
		t.Errorf("the plugins drive is %+v, want a read-only one", cfg.Drives[1])
	}
	if plugins.Device != "/dev/vdb" {
		t.Errorf("device = %s; with no workspace the plugins drive is the second one", plugins.Device)
	}
	if !strings.Contains(cfg.BootSource.BootArgs, "kelyfos.plugins=/dev/vdb") {
		t.Errorf("the guest is not told where to find it:\n%s", cfg.BootSource.BootArgs)
	}

	// And with a workspace it is the third, which is the case the constant
	// would have been right about by accident.
	plugins = &Plugins{ImagePath: "/tmp/p.ext4"}
	cfg = firecrackerConfig(Options{Arch: "x86_64", Plugins: plugins,
		Workspace: &Workspace{ImagePath: "/tmp/w.ext4"}}, "k", "r", "u", "id")
	if plugins.Device != "/dev/vdc" {
		t.Errorf("device = %s, want /dev/vdc behind the workspace", plugins.Device)
	}
	if !strings.Contains(cfg.BootSource.BootArgs, "kelyfos.workspace=/dev/vdb") ||
		!strings.Contains(cfg.BootSource.BootArgs, "kelyfos.plugins=/dev/vdc") {
		t.Errorf("the two devices are not both named:\n%s", cfg.BootSource.BootArgs)
	}
}

// A sandbox with no plugins says nothing about them on the command line, rather
// than saying something empty the supervisor would have to interpret.
func TestNoPluginsSaysNothing(t *testing.T) {
	cfg := firecrackerConfig(Options{Arch: "x86_64"}, "k", "r", "u", "id")
	if strings.Contains(cfg.BootSource.BootArgs, "kelyfos.plugins") {
		t.Errorf("a sandbox with no plugins was told about them:\n%s", cfg.BootSource.BootArgs)
	}
}

func TestPackPluginsWritesTheManifest(t *testing.T) {
	if _, err := os.Stat("/sbin/mke2fs"); err != nil {
		if _, err := os.Stat("/usr/sbin/mke2fs"); err != nil {
			t.Skip("mke2fs is not on this machine")
		}
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "server.js"), []byte("console.log(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "plugins.ext4")
	got, err := PackPlugins([]PluginSpec{
		{Name: "browser", Dir: src, Command: "node", Args: []string{"server.js"}},
	}, image)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Name != "browser" {
		t.Fatalf("entries = %+v", got.Entries)
	}
	if got.Entries[0].SHA256 == "" {
		t.Error("the manifest records no digest, so nobody can tell two builds apart")
	}
	info, err := os.Stat(image)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o200 != 0 {
		t.Errorf("the image is writable (%v); a plugin must not be editable from either side", info.Mode())
	}
	blob, _ := json.Marshal(got.Entries)
	if !strings.Contains(string(blob), `"command":"node"`) {
		t.Errorf("the manifest does not say what to launch: %s", blob)
	}
}
