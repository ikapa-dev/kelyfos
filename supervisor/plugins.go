package main

import (
	"encoding/json"
	"os"

	"golang.org/x/sys/unix"
)

// The plugins device, from inside the guest (E4-6).
//
// The host packs each declared plugin into a read-only ext4 image and names the
// device on the kernel command line. This mounts it and reads the manifest; what
// launches the plugins is E4-7's job, and keeping the two apart is deliberate —
// a device that mounts and a manifest that parses are worth proving on their own,
// before anything runs from them.

// PluginEntry mirrors the host's plugins.json. Duplicated rather than shared
// because the guest binary and the host binary are separate programs that meet
// only over a wire format, and internal/sandbox is host-side code the supervisor
// deliberately does not import.
type PluginEntry struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	SHA256  string   `json:"sha256"`
}

// thePlugins is what the manifest said, read once at boot. Package-level for
// the same reason theTeam is: there is exactly one plugins device per machine,
// and the guest is told what is on it rather than allowed to decide.
var thePlugins []PluginEntry

// mountPlugins mounts the plugins disk at /plugins, if the host attached one,
// and returns what the manifest says is on it.
//
// Read-only at the mount as well as at the device, so the guest gets the same
// answer from either direction: a plugin is code the agent may run and must not
// be code the agent can edit (docs/mcp-surface.md §3.1).
func mountPlugins() []PluginEntry {
	dev := kernelParam("kelyfos.plugins")
	if dev == "" {
		return nil
	}
	if err := os.MkdirAll("/plugins", 0o755); err != nil {
		logf("warning: /plugins: %v", err)
		return nil
	}
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
	if err := unix.Mount(dev, "/plugins", "ext4", flags, ""); err != nil {
		logf("warning: could not mount plugins %s on /plugins: %v", dev, err)
		return nil
	}

	blob, err := os.ReadFile("/plugins/plugins.json")
	if err != nil {
		// The device is storage and the manifest is the list. A device with no
		// manifest carries nothing this will launch, and saying so beats
		// scanning the directory and guessing (D21).
		logf("warning: plugins device %s carries no manifest: %v", dev, err)
		return nil
	}
	var entries []PluginEntry
	if err := json.Unmarshal(blob, &entries); err != nil {
		logf("warning: plugins manifest is unreadable: %v", err)
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	logf("plugins mounted read-only from %s on /plugins: %v", dev, names)
	return entries
}
