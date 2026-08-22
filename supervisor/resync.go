package main

import (
	"encoding/base64"
	"errors"
	"os"
	"unsafe"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"golang.org/x/sys/unix"
)

// applyResync repairs the two things a restored guest is wrong about
// (docs/protocol.md §5.4).
//
// A VM resumed from a snapshot believes the wall clock still reads what it did
// when the snapshot was taken, and its random pool holds exactly the state it
// held then. For one restore that is merely stale. For N forks of one snapshot
// it is worse than stale: every fork starts with an identical pool, so every
// fork generates the same "random" bytes — the same session ids, the same
// nonces, the same temporary filenames.
func applyResync(req *proto.ControlRequest) error {
	if req.RealtimeNS <= 0 {
		return errors.New("resync: realtime_ns is required")
	}
	ts := unix.NsecToTimespec(req.RealtimeNS)
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return err
	}

	if req.Entropy == "" {
		return nil
	}
	seed, err := base64.StdEncoding.DecodeString(req.Entropy)
	if err != nil {
		return errors.New("resync: entropy is not valid base64")
	}
	return seedRandom(seed)
}

// seedRandom mixes host-supplied bytes into the guest's pool.
//
// The plain write is what makes the forks diverge and is enough on its own: the
// kernel stirs anything written to /dev/urandom into the pool. RNDADDENTROPY
// additionally tells the kernel to *credit* those bytes, which matters because
// a freshly restored guest can otherwise block in getrandom(2) waiting for an
// entropy estimate to recover — and blocking there is how a "100 ms restore"
// becomes a two-second one. It is attempted second and its failure ignored, so
// the guaranteed part does not depend on the optional part.
func seedRandom(seed []byte) error {
	f, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(seed); err != nil {
		return err
	}

	rnd, err := os.OpenFile("/dev/random", os.O_RDWR, 0)
	if err != nil {
		return nil // the write above already did the load-bearing work
	}
	defer rnd.Close()

	// struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
	buf := make([]byte, 8+len(seed))
	*(*int32)(unsafe.Pointer(&buf[0])) = int32(len(seed) * 8) // bits claimed
	*(*int32)(unsafe.Pointer(&buf[4])) = int32(len(seed))
	copy(buf[8:], seed)
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, rnd.Fd(),
		uintptr(unix.RNDADDENTROPY), uintptr(unsafe.Pointer(&buf[0])))
	return nil
}
