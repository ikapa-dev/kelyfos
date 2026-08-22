package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

// The mapping from a human rate to Firecracker's two numbers is the whole of
// E1-3's arithmetic, so it is worth pinning exactly rather than approximately.
// The rate Firecracker enforces is size/refill_time; the bucket must also be
// able to hold one whole request, or the limit leaks (see bucket's comment).
func TestBucketMapsRatesToSizeAndRefillTime(t *testing.T) {
	cases := []struct {
		name        string
		limits      IOLimits
		wantNetRx   *TokenBucket
		wantDiskBW  *TokenBucket
		wantDiskOps *TokenBucket
	}{
		{
			name:      "10 Mbps is 1.25 MB/s, and one second of it holds a frame",
			limits:    IOLimits{NetMbpsRx: 10},
			wantNetRx: &TokenBucket{Size: 1_250_000, RefillTimeMS: 1000},
		},
		{
			name:      "1 Mbps: 125 kB still holds the largest frame, so one second stands",
			limits:    IOLimits{NetMbpsRx: 1},
			wantNetRx: &TokenBucket{Size: 125_000, RefillTimeMS: 1000},
		},
		{
			name:       "50 MB/s and 500 iops: a second of each is plenty",
			limits:     IOLimits{DiskMbps: 50, DiskIOPS: 500},
			wantDiskBW: &TokenBucket{Size: 50_000_000, RefillTimeMS: 1000},
			// An operation is one token, so an ops bucket never needs widening.
			wantDiskOps: &TokenBucket{Size: 500, RefillTimeMS: 1000},
		},
		{
			// One second of a 1 MB/s cap is 1 MB, and the guest issues 4 MiB
			// requests: the window widens until the bucket can hold one.
			name:       "1 MB/s widens the window until a 4 MiB request fits",
			limits:     IOLimits{DiskMbps: 1},
			wantDiskBW: &TokenBucket{Size: 5_000_000, RefillTimeMS: 5000},
		},
		{
			name:       "4 MB/s needs two seconds; 5 MB/s does not",
			limits:     IOLimits{DiskMbps: 4},
			wantDiskBW: &TokenBucket{Size: 8_000_000, RefillTimeMS: 2000},
		},
		{
			name:       "5 MB/s holds a 4 MiB request in one second",
			limits:     IOLimits{DiskMbps: 5},
			wantDiskBW: &TokenBucket{Size: 5_000_000, RefillTimeMS: 1000},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rx, _ := tc.limits.NetLimiters()
			var gotRx *TokenBucket
			if rx != nil {
				gotRx = rx.Bandwidth
			}
			eq(t, "net rx", gotRx, tc.wantNetRx)

			var gotBW, gotOps *TokenBucket
			if d := tc.limits.DriveLimiter(); d != nil {
				gotBW, gotOps = d.Bandwidth, d.Ops
			}
			eq(t, "disk bandwidth", gotBW, tc.wantDiskBW)
			eq(t, "disk ops", gotOps, tc.wantDiskOps)
		})
	}
}

func eq(t *testing.T, what string, got, want *TokenBucket) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("%s = %v, want %v", what, got, want)
	case *got != *want:
		t.Errorf("%s = %+v, want %+v", what, *got, *want)
	}
}

// Two invariants hold for every rate the policy file can express, so they are
// checked over a range rather than at the handful of points above: the enforced
// rate is exactly the requested one, and the bucket can hold one whole request.
func TestEveryBucketIsExactAndBigEnough(t *testing.T) {
	for mbps := 1; mbps <= 1000; mbps++ {
		rx, _ := IOLimits{NetMbpsRx: mbps}.NetLimiters()
		check(t, "net", mbps, rx.Bandwidth, int64(mbps)*125_000, maxNetFrame)

		d := IOLimits{DiskMbps: mbps}.DriveLimiter()
		check(t, "disk", mbps, d.Bandwidth, int64(mbps)*1_000_000, maxBlockRequest)
	}
	for iops := 1; iops <= 5000; iops++ {
		d := IOLimits{DiskIOPS: iops}.DriveLimiter()
		check(t, "iops", iops, d.Ops, int64(iops), 1)
	}
}

func check(t *testing.T, what string, n int, b *TokenBucket, wantPerSec, floor int64) {
	t.Helper()
	if got := b.Size * 1000 / b.RefillTimeMS; got != wantPerSec {
		t.Fatalf("%s %d -> size %d / %d ms = %d per second, want %d",
			what, n, b.Size, b.RefillTimeMS, got, wantPerSec)
	}
	if b.Size < floor {
		t.Fatalf("%s %d -> bucket of %d cannot hold one %d-byte request",
			what, n, b.Size, floor)
	}
}

// No limits configured must produce no limiter at all, not an empty one:
// Firecracker treats a zero-sized bucket as "no limiting", but writing one
// would still put a rate_limiter object in the config that nobody asked for.
func TestNoLimitsMeansNoLimiterObject(t *testing.T) {
	var none IOLimits
	if none.Set() {
		t.Error("the zero IOLimits reports itself as set")
	}
	if d := none.DriveLimiter(); d != nil {
		t.Errorf("DriveLimiter() = %+v, want nil", d)
	}
	if rx, tx := none.NetLimiters(); rx != nil || tx != nil {
		t.Errorf("NetLimiters() = %v, %v, want nil, nil", rx, tx)
	}
}

// The limiter has to reach Firecracker under the field names its API uses, and
// only those: the config is a whitelist by construction and a misspelling is
// rejected at boot, which is a bad place to discover it.
func TestConfigCarriesTheLimitersFirecrackerExpects(t *testing.T) {
	opts := Options{
		Arch:      "x86_64",
		VcpuCount: 2,
		MemMiB:    512,
		IO:        IOLimits{NetMbpsRx: 10, NetMbpsTx: 5, DiskIOPS: 500, DiskMbps: 50},
		Net:       &Network{TAP: "kelyfos0", ProxyPort: 1234},
		Workspace: &Workspace{ImagePath: "/tmp/ws.ext4"},
	}
	cfg := firecrackerConfig(opts, "/img/vmlinux", "/img/rootfs.ext4", "/run/v.sock", "abcd1234")

	if len(cfg.Drives) != 2 {
		t.Fatalf("got %d drives, want 2", len(cfg.Drives))
	}
	for _, d := range cfg.Drives {
		if d.RateLimiter == nil {
			t.Errorf("drive %q has no rate limiter", d.DriveID)
			continue
		}
		if d.RateLimiter.Bandwidth == nil || d.RateLimiter.Ops == nil {
			t.Errorf("drive %q limiter is missing a bucket: %+v", d.DriveID, d.RateLimiter)
		}
	}
	if len(cfg.NetworkIfaces) != 1 {
		t.Fatalf("got %d network interfaces, want 1", len(cfg.NetworkIfaces))
	}
	if cfg.NetworkIfaces[0].RxRateLimiter == nil || cfg.NetworkIfaces[0].TxRateLimiter == nil {
		t.Fatal("the NIC is missing a direction's limiter")
	}

	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"rate_limiter"`, `"rx_rate_limiter"`, `"tx_rate_limiter"`,
		`"bandwidth"`, `"ops"`, `"size"`, `"refill_time"`,
	} {
		if !strings.Contains(string(blob), field) {
			t.Errorf("the encoded config has no %s field:\n%s", field, blob)
		}
	}
	// Never emitted: one-time burst credit is deliberately not offered.
	if strings.Contains(string(blob), `"one_time_burst"`) {
		t.Error("the config offers a one-time burst, which KelyfOS never sets")
	}
}

// A sandbox with no limits must encode exactly the config v0.3 encoded, so the
// feature is invisible until it is asked for.
func TestUnlimitedConfigHasNoLimiterFields(t *testing.T) {
	cfg := firecrackerConfig(
		Options{Arch: "x86_64", VcpuCount: 2, MemMiB: 512, Net: &Network{TAP: "kelyfos0"}},
		"/img/vmlinux", "/img/rootfs.ext4", "/run/v.sock", "abcd1234")
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"rate_limiter"`, `"rx_rate_limiter"`, `"tx_rate_limiter"`} {
		if strings.Contains(string(blob), field) {
			t.Errorf("an unlimited sandbox still emits %s:\n%s", field, blob)
		}
	}
}
