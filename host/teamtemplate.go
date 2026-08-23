package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// The fork-template cache (F-D26).
//
// A team boots cold by default, because on the reference environment a cold
// boot is 109–134 ms and writing a template's memory image is 927 ms — so
// forking from a template built on the spot is slower than not forking at all.
// What makes forking worth having is paying that write *once*: after a template
// exists, restoring from it is 57–61 ms per worker there and ~430 ms on the
// nested dev machine, and on both it beats that machine's own cold boot.
//
// So: cold-first, fork-warm. A team-up that finds no template boots everything
// cold and then builds one in the background for next time; a team-up that
// finds one forks its no-egress workers from it.

// templateCacheBytes bounds the cache. Each template is one memory image, so
// the bound is in bytes rather than count: four 512 MiB machines and forty
// 50 MiB ones are very different amounts of disk and the same number of files.
const templateCacheBytes = 2 << 30

func templateRoot() string { return filepath.Join(sandbox.Root(), "templates") }

// templateKey identifies a machine a fork could be made from: everything baked
// into a memory image, and the identity of the image itself.
//
// The image digests are what make a stale template impossible to serve. An
// image rebuild changes the rootfs sha256 in image.json, which changes the key,
// so the old template is simply never looked up again — it ages out of the
// cache rather than being invalidated by something remembering to.
func templateKey(a plannedAgent, arch string) (string, error) {
	man, err := sandbox.ReadManifest(sandbox.ImageDir(arch))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "v1\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%t",
		arch, a.image, man.KernelSHA256, man.RootfsSHA256,
		a.res.CPUs, a.res.MemMiB, a.res.ScratchByte,
		a.res.NetMbpsRx, a.res.NetMbpsTx, a.res.DiskIOPS, a.res.DiskMbps,
		a.spawn != nil)
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// lookupTemplate reports a usable template for this key, and marks it as just
// used so the eviction order reflects what teams actually boot.
//
// "Usable" means complete: a directory holding both halves of a snapshot and
// the metadata a restore reads. A template is renamed into place only once it
// is all three, so a partial one is never a hit.
func lookupTemplate(key string) (string, bool) {
	dir := filepath.Join(templateRoot(), key)
	for _, f := range []string{"state", "memory", "meta.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return "", false
		}
	}
	now := time.Now()
	_ = os.Chtimes(dir, now, now)
	return dir, true
}

// storeTemplate boots one machine of this shape, snapshots it, and puts the
// snapshot in the cache for the next team-up.
//
// Called in the background, after the team it belongs to is already running:
// with cold-first there is no fork demand on a miss, so waiting for one would
// mean the cache never filled. It is cancelled with the team.
func storeTemplate(ctx context.Context, a plannedAgent, sessionID, arch, key string,
	timeout time.Duration) error {

	if _, ok := lookupTemplate(key); ok {
		return nil
	}
	tmpl, snapDir, _, _, err := bootTemplate(ctx, a, sessionID, arch, timeout)
	if err != nil {
		return err
	}
	// The machine has served its purpose the moment its image is on disk.
	go func() { _ = tmpl.Shutdown(10 * time.Second) }()

	if err := ctx.Err(); err != nil {
		_ = os.RemoveAll(snapDir)
		return err
	}
	if err := os.MkdirAll(templateRoot(), 0o700); err != nil {
		_ = os.RemoveAll(snapDir)
		return err
	}
	dest := filepath.Join(templateRoot(), key)
	// Renamed into place rather than written in place: a half-written image
	// must never be a cache hit, and two team-ups racing on the same shape must
	// not serve each other a partial one. A rename within one filesystem is the
	// only step here that is atomic, so it is the step that publishes.
	if err := os.Rename(snapDir, dest); err != nil {
		// Losing the race is the ordinary outcome, not a failure: somebody else
		// published the same shape first and theirs is as good as ours.
		_ = os.RemoveAll(snapDir)
		if _, ok := lookupTemplate(key); ok {
			return nil
		}
		return err
	}
	pruneTemplates(templateCacheBytes)
	return nil
}

// pruneTemplates keeps the cache under its bound, oldest-used first.
//
// The bound is a promise about disk, so it is enforced after a write rather
// than before one: the alternative is refusing to cache a template because it
// might not fit, which trades a bounded overshoot for a cache that never fills.
func pruneTemplates(maxBytes int64) {
	entries, err := os.ReadDir(templateRoot())
	if err != nil {
		return
	}
	type held struct {
		dir  string
		used time.Time
		size int64
	}
	var all []held
	var total int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(templateRoot(), e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := dirBytes(dir)
		total += size
		all = append(all, held{dir, info.ModTime(), size})
	}
	if total <= maxBytes {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used.Before(all[j].used) })
	for _, h := range all {
		if total <= maxBytes {
			return
		}
		if err := os.RemoveAll(h.dir); err != nil {
			continue
		}
		total -= h.size
		// Said out loud. A cache that silently throws work away is a cache that
		// gets blamed for the next slow boot.
		fmt.Fprintf(os.Stderr, "kelyfos: fork template cache is over its %s bound; evicted %s (%s)\n",
			humanBytes(maxBytes), filepath.Base(h.dir), humanBytes(h.size))
	}
}

func dirBytes(dir string) int64 {
	var n int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			n += info.Size()
		}
	}
	return n
}
