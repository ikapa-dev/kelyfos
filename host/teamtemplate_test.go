package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// withCache points KelyfOS's root at a temporary directory, so the tests below
// touch a cache of their own rather than the developer's.
func withCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("KELYFOS_CACHE", root)
	return root
}

// writeManifest puts an image.json where templateKey will look for it.
func writeManifest(t *testing.T, arch, kernelSHA, rootfsSHA string) {
	t.Helper()
	dir := sandbox.ImageDir(arch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(sandbox.Manifest{
		Schema: 1, Arch: arch, Flavor: "dev",
		Kernel: "Image", KernelSHA256: kernelSHA,
		Rootfs: "rootfs.ext4", RootfsSHA256: rootfsSHA,
	})
	if err := os.WriteFile(filepath.Join(dir, "image.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

func agent(name string, res config.AgentResources) plannedAgent {
	return plannedAgent{name: name, image: "dev", res: res}
}

// The key covers what is baked into a memory image, and the identity of the
// image itself. Everything in that list must change it; nothing outside it may.
func TestTheTemplateKeyCoversTheImageAndTheMachine(t *testing.T) {
	withCache(t)
	writeManifest(t, "aarch64", "kkk", "rrr")
	base := config.AgentResources{CPUs: 2, MemMiB: 384, ScratchByte: 1 << 20}

	key := func(a plannedAgent) string {
		t.Helper()
		k, err := templateKey(a, "aarch64")
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	same := key(agent("a", base))
	if key(agent("b", base)) != same {
		t.Error("two agents with the same machine got different keys; the name is not baked in")
	}

	// cpu_quota is a host cgroup on the VMM process, not anything inside the
	// machine — it must not split a template.
	q := base
	q.CPUQuota = 150
	if key(agent("a", q)) != same {
		t.Error("cpu_quota changed the key; it is a host-side cgroup, not part of the image")
	}

	// Everything that *is* in the machine must.
	for what, mut := range map[string]func(config.AgentResources) config.AgentResources{
		"cores":   func(r config.AgentResources) config.AgentResources { r.CPUs = 4; return r },
		"memory":  func(r config.AgentResources) config.AgentResources { r.MemMiB = 512; return r },
		"scratch": func(r config.AgentResources) config.AgentResources { r.ScratchByte = 2 << 20; return r },
		"net rate": func(r config.AgentResources) config.AgentResources {
			r.NetMbpsRx = 10
			return r
		},
		"disk rate": func(r config.AgentResources) config.AgentResources {
			r.DiskIOPS = 500
			return r
		},
	} {
		if key(agent("a", mut(base))) == same {
			t.Errorf("changing the %s did not change the template key", what)
		}
	}

	// A spawn budget changes the kernel command line, so it changes the machine.
	sp := agent("a", base)
	sp.spawn = &config.SpawnBudget{Max: 1}
	if key(sp) == same {
		t.Error("a spawn budget did not change the key; it is on the kernel command line")
	}

	// And rebuilding the image must change it, or a stale template could be
	// served for a new rootfs — the invalidation question F-D25 asked.
	writeManifest(t, "aarch64", "kkk", "rrr2")
	if key(agent("a", base)) == same {
		t.Error("a new rootfs digest did not change the key; a stale template could be served")
	}
}

// A directory missing any part of a snapshot is not a template. This is what
// keeps a half-written one from ever being a cache hit.
func TestAnIncompleteTemplateIsNotACacheHit(t *testing.T) {
	withCache(t)
	dir := filepath.Join(templateRoot(), "abc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, present := range [][]string{
		{},
		{"state"},
		{"state", "memory"},
		{"memory", "meta.json"},
	} {
		for _, f := range []string{"state", "memory", "meta.json"} {
			_ = os.Remove(filepath.Join(dir, f))
		}
		for _, f := range present {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, ok := lookupTemplate("abc"); ok {
			t.Errorf("a directory holding only %v was accepted as a template", present)
		}
	}
	for _, f := range []string{"state", "memory", "meta.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := lookupTemplate("abc"); !ok {
		t.Error("a complete template was not a cache hit")
	}
}

// The cache is a promise about disk. It is kept by evicting what was used
// longest ago, which is the only ordering that reflects what teams actually
// boot rather than what was written first.
func TestTheCacheIsBoundedAndEvictsWhatWasUsedLongestAgo(t *testing.T) {
	withCache(t)
	mk := func(name string, size int, age time.Duration) {
		dir := filepath.Join(templateRoot(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"state", "memory", "meta.json"} {
			if err := os.WriteFile(filepath.Join(dir, f), make([]byte, size/3), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(dir, when, when); err != nil {
			t.Fatal(err)
		}
	}
	mk("oldest", 3000, 3*time.Hour)
	mk("middle", 3000, 2*time.Hour)
	mk("newest", 3000, time.Hour)

	// Room for two of the three.
	pruneTemplates(7000)
	if _, ok := lookupTemplate("oldest"); ok {
		t.Error("the least recently used template survived the bound")
	}
	for _, keep := range []string{"middle", "newest"} {
		if _, ok := lookupTemplate(keep); !ok {
			t.Errorf("%s was evicted even though the cache was under its bound", keep)
		}
	}

	// A cache already under its bound is left alone.
	pruneTemplates(1 << 30)
	for _, keep := range []string{"middle", "newest"} {
		if _, ok := lookupTemplate(keep); !ok {
			t.Errorf("%s was evicted from a cache that was already under its bound", keep)
		}
	}
}

// Looking a template up marks it as used, or the eviction order would reflect
// when templates were built rather than when teams last wanted them.
func TestAHitMarksATemplateAsRecentlyUsed(t *testing.T) {
	withCache(t)
	dir := filepath.Join(templateRoot(), "abc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"state", "memory", "meta.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	if _, ok := lookupTemplate("abc"); !ok {
		t.Fatal("a complete template was not a hit")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(info.ModTime()) > time.Minute {
		t.Errorf("a cache hit left the template looking %s old", time.Since(info.ModTime()))
	}
}

// Without a manifest there is no key, and a template that cannot be identified
// must never be served — the caller cold-boots instead.
func TestNoManifestMeansNoKey(t *testing.T) {
	withCache(t)
	if _, err := templateKey(agent("a", config.AgentResources{}), "aarch64"); err == nil {
		t.Error("a key was minted for an image with no manifest")
	} else if !strings.Contains(err.Error(), "image.json") && !os.IsNotExist(err) {
		t.Logf("(refusal was: %v)", err)
	}
}
