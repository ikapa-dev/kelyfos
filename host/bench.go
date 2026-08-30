package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// benchResult is the machine-readable form, so CI can publish a number without
// scraping human output.
type benchResult struct {
	Kind     string  `json:"kind"`
	Arch     string  `json:"arch"`
	Flavor   string  `json:"flavor"`
	Vcpus    int     `json:"vcpus"`
	MemMiB   int     `json:"mem_mib"`
	Runs     int     `json:"runs"`
	MinMS    int64   `json:"min_ms"`
	MedianMS int64   `json:"median_ms"`
	P95MS    int64   `json:"p95_ms"`
	MaxMS    int64   `json:"max_ms"`
	MeanMS   float64 `json:"mean_ms"`
	Samples  []int64 `json:"samples_ms"`
}

// benchCmd measures cold boot-to-ready: a fresh microVM per run, timed on the
// host from launching Firecracker to the first frame arriving on the guest's
// ready channel. Identical to what `kelyfos run` reports, so a local number and
// a CI number mean the same thing (decision D15).
func benchCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos bench", flag.ExitOnError)
	var (
		runs    = fs.Int("runs", 10, "number of cold boots to measure")
		arch    = fs.String("arch", sandbox.HostArch(), "guest architecture (aarch64|x86_64)")
		flavor  = fs.String("image", "base", "image flavor")
		imgDir  = fs.String("image-dir", "", "directory holding the kernel and rootfs")
		vcpus   = fs.Int("vcpus", 2, "virtual CPUs")
		memMiB  = fs.Int("mem", 512, "guest memory, MiB")
		asJSON  = fs.Bool("json", false, "emit the result as JSON")
		restore = fs.String("restore", "", "measure restores from this snapshot instead of cold boots")
		timeout = fs.Duration("ready-timeout", 30*time.Second, "per-boot readiness timeout")
	)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: kelyfos bench [flags]\n\nMeasures cold boot-to-ready over several runs.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *runs < 1 {
		return fmt.Errorf("--runs must be at least 1")
	}

	kind := "cold boot"
	if *restore != "" {
		kind = "restore from " + *restore
	}

	samples := make([]int64, 0, *runs)
	for i := 0; i < *runs; i++ {
		opts := sandbox.Options{
			Arch: *arch, Flavor: *flavor, ImageDir: *imgDir,
			VcpuCount: *vcpus, MemMiB: *memMiB, Quiet: true,
		}
		var ms int64
		var err error
		if *restore != "" {
			ms, err = oneRestore(*restore, opts)
		} else {
			ms, err = oneBoot(opts, *timeout)
		}
		if err != nil {
			return fmt.Errorf("run %d/%d: %w", i+1, *runs, err)
		}
		samples = append(samples, ms)
		if !*asJSON {
			fmt.Fprintf(os.Stderr, "  run %2d/%d: %d ms\n", i+1, *runs, ms)
		}
	}

	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	var sum int64
	for _, v := range sorted {
		sum += v
	}
	res := benchResult{
		Kind: kind,
		Arch: *arch, Flavor: *flavor, Vcpus: *vcpus, MemMiB: *memMiB,
		Runs:    len(sorted),
		MinMS:   sorted[0],
		MaxMS:   sorted[len(sorted)-1],
		MeanMS:  float64(sum) / float64(len(sorted)),
		Samples: samples,
		// Nearest-rank percentiles: with ten samples a p95 is the slowest run,
		// which is the honest reading of ten data points rather than an
		// interpolation that implies more precision than exists.
		MedianMS: sorted[percentileIndex(len(sorted), 50)],
		P95MS:    sorted[percentileIndex(len(sorted), 95)],
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	fmt.Printf("\n%s over %d runs (%s, %s, %d vcpu / %d MiB)\n",
		res.Kind, res.Runs, res.Arch, res.Flavor, res.Vcpus, res.MemMiB)
	fmt.Printf("  min %d ms | median %d ms | p95 %d ms | max %d ms | mean %.1f ms\n",
		res.MinMS, res.MedianMS, res.P95MS, res.MaxMS, res.MeanMS)
	return nil
}

func percentileIndex(n, p int) int {
	i := (p*n + 99) / 100 // ceil(p/100 * n)
	if i < 1 {
		i = 1
	}
	if i > n {
		i = n
	}
	return i - 1
}

func oneBoot(opts sandbox.Options, timeout time.Duration) (int64, error) {
	sb, err := sandbox.New(opts)
	if err != nil {
		return 0, err
	}
	defer sb.Shutdown(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		return 0, err
	}
	if _, err := sb.WaitReady(ctx); err != nil {
		return 0, err
	}
	return sb.State.BootReadyMS, nil
}

// oneRestore measures one restore, from launching Firecracker to the guest
// answering the resync round trip.
func oneRestore(name string, opts sandbox.Options) (int64, error) {
	dir, err := snapshotDir(name)
	if err != nil {
		return 0, err
	}
	sb, elapsed, err := sandbox.Restore(dir, opts)
	if err != nil {
		return 0, err
	}
	defer sb.Shutdown(5 * time.Second)
	return elapsed.Milliseconds(), nil
}
