package main

import (
	"strings"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// The resources lane is the one part of `kelyfos watch` that does not come from
// the flight recorder, so it is the part worth pinning: what it says, and that
// it always says what a number was measured against.
func TestResourceLaneShowsUsageAgainstItsCaps(t *testing.T) {
	now := time.Now()
	m := &watchModel{session: "abcd1234"}

	// Before any sample: no numbers, and no pretending.
	if got := m.resourceLane(); !strings.Contains(got, "waiting for the first sample") {
		t.Errorf("empty lane = %q", got)
	}

	// One sample is a reading, not a rate: CPU stays blank until there are two.
	first := usageMsg{
		usage: sandbox.Usage{CPUSeconds: 1, RSSKiB: 100 << 10},
		state: sandbox.State{VcpuCount: 2, MemMiB: 512, CPUQuota: 60},
		at:    now,
	}
	m.Update(first)
	if got := m.resourceLane(); !strings.Contains(got, "cpu   —") {
		t.Errorf("a single sample reported a rate: %q", got)
	}

	// Two samples a second apart, half a CPU-second used: 50%.
	m.Update(usageMsg{
		usage: sandbox.Usage{CPUSeconds: 1.5, RSSKiB: 122 << 10, DiskWriteBytes: 40 << 20,
			NetInBytes: 3 << 20, NetOutBytes: 1 << 10},
		state: sandbox.State{VcpuCount: 2, MemMiB: 512, CPUQuota: 60, NetMbpsRx: 10},
		at:    now.Add(time.Second),
	})
	got := m.resourceLane()
	for _, want := range []string{
		"cpu  50.0% of 60% quota", // the rate, and the cap it is measured against
		"mem 122 MiB of 512 MiB",
		"net 3.0 MiB in / 1 KiB out (cap 10/0 Mbps)",
		"disk 40.0 MiB written",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lane %q\n  is missing %q", got, want)
		}
	}
}

// Once the sandbox has stopped there is nothing left to sample, and the lane
// shows the receipt the recorder kept instead.
func TestResourceLaneFallsBackToTheRecordedReceipt(t *testing.T) {
	m := &watchModel{session: "abcd1234"}
	m.absorb(recorder.Event{
		Type: recorder.TypeResourceSummary, CPUSeconds: 1.68, PeakRSSKiB: 122 << 10,
		MemMiB: 512, CPUQuota: 80, DiskWriteBytes: 40 << 20,
	})
	got := m.resourceLane()
	for _, want := range []string{
		"final ·", "1.68 CPU-seconds", "quota 80% of one core",
		"peak RSS 122 MiB of 512 MiB", "disk 40.0 MiB written",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("receipt lane %q\n  is missing %q", got, want)
		}
	}
}
