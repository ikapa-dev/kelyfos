package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Usage is what one sandbox has consumed, read from the host and only from the
// host. Every field comes from a counter the kernel keeps about the Firecracker
// process or the TAP device attached to it; nothing here is asked of the guest,
// which is the same reasoning that puts the caps host-side (F-D2). A guest
// cannot flatter its own receipt.
type Usage struct {
	CPUSeconds     float64
	RSSKiB         int64
	PeakRSSKiB     int64
	NetInBytes     int64 // into the guest
	NetOutBytes    int64 // out of the guest
	DiskReadBytes  int64
	DiskWriteBytes int64
}

// Sample reads the counters for a running sandbox.
//
// CPU and memory come from the VM's cgroup when it has one and from /proc when
// it does not. The cgroup exists only when --cpu-quota was asked for (E1-2), and
// creating one for every sandbox to make this tidier would cost every boot the
// systemd round trip that the quota path pays — three hundred milliseconds on a
// product whose headline number is boot-to-ready. The /proc figures measure the
// same process and are always there.
func (s *State) Sample() (Usage, error) {
	var u Usage
	if s.PID == 0 {
		return u, fmt.Errorf("sandbox %s has no process to sample", s.ID)
	}

	if s.CGroupPath != "" {
		if v, ok := cgroupKeyed(filepath.Join(s.CGroupPath, "cpu.stat"), "usage_usec"); ok {
			u.CPUSeconds = float64(v) / 1e6
		}
		u.RSSKiB = cgroupNumber(filepath.Join(s.CGroupPath, "memory.current")) >> 10
		u.PeakRSSKiB = cgroupNumber(filepath.Join(s.CGroupPath, "memory.peak")) >> 10
	}
	if u.CPUSeconds == 0 {
		u.CPUSeconds = procCPUSeconds(s.PID)
	}
	if u.RSSKiB == 0 || u.PeakRSSKiB == 0 {
		rss, peak := procRSS(s.PID)
		if u.RSSKiB == 0 {
			u.RSSKiB = rss
		}
		if u.PeakRSSKiB == 0 {
			u.PeakRSSKiB = peak
		}
	}

	// The TAP's counters are named from the host's point of view, so they read
	// backwards here: what the host received on the TAP is what the guest sent.
	// Getting this the wrong way round would put a download in the upload
	// column, which is the sort of error a receipt is read too casually to
	// catch.
	if s.TAP != "" {
		base := filepath.Join("/sys/class/net", s.TAP, "statistics")
		u.NetOutBytes = cgroupNumber(filepath.Join(base, "rx_bytes"))
		u.NetInBytes = cgroupNumber(filepath.Join(base, "tx_bytes"))
	}

	// Bytes the VMM actually moved to and from the host's storage, which is what
	// a disk limit is about. The guest's own view would include everything its
	// page cache absorbed.
	if v, ok := cgroupKeyed(fmt.Sprintf("/proc/%d/io", s.PID), "read_bytes"); ok {
		u.DiskReadBytes = v
	}
	if v, ok := cgroupKeyed(fmt.Sprintf("/proc/%d/io", s.PID), "write_bytes"); ok {
		u.DiskWriteBytes = v
	}
	return u, nil
}

// cgroupNumber reads a file holding one number. "max" and anything unreadable
// read as zero: this is a receipt, and a missing counter is better reported as
// nothing than as a guess.
func cgroupNumber(path string) int64 {
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(blob)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// cgroupKeyed reads one "key value" line out of a file of them — the shape both
// cgroup v2 stat files and /proc/<pid>/io use.
func cgroupKeyed(path, key string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			k, v, ok = strings.Cut(sc.Text(), ":")
		}
		if !ok || strings.TrimSuffix(k, ":") != key {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// procCPUSeconds reads utime+stime out of /proc/<pid>/stat.
//
// The comm field is parenthesised and may contain spaces and parentheses, so
// the fields are counted from the last ')' rather than from the start — the
// classic way to misparse this file is to split it on spaces.
func procCPUSeconds(pid int) float64 {
	blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	i := strings.LastIndexByte(string(blob), ')')
	if i < 0 {
		return 0
	}
	// After the comm field, field 3 is state; utime and stime are 14 and 15
	// counting from 1, so 11 and 12 in what remains.
	fields := strings.Fields(string(blob)[i+1:])
	if len(fields) < 13 {
		return 0
	}
	utime, err1 := strconv.ParseInt(fields[11], 10, 64)
	stime, err2 := strconv.ParseInt(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return float64(utime+stime) / clockTicks
}

// clockTicks is USER_HZ, fixed at 100 on every architecture Linux supports for
// the purposes of /proc — the kernel scales the values it reports there.
const clockTicks = 100.0

// procRSS reads the current and high-water resident set from /proc/<pid>/status.
func procRSS(pid int) (rss, peak int64) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			rss = kiBField(line)
		case strings.HasPrefix(line, "VmHWM:"):
			peak = kiBField(line)
		}
	}
	return rss, peak
}

func kiBField(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}
