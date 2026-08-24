package sandbox

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// FirecrackerConfig is the machine configuration KelyfOS writes for
// `firecracker --config-file`. Only the fields KelyfOS sets are modelled;
// Firecracker rejects unknown fields, so this is a whitelist by construction.
type FirecrackerConfig struct {
	BootSource    BootSource     `json:"boot-source"`
	Drives        []Drive        `json:"drives"`
	MachineConfig MachineConfig  `json:"machine-config"`
	Vsock         *Vsock         `json:"vsock,omitempty"`
	NetworkIfaces []NetworkIface `json:"network-interfaces,omitempty"`
}

// NetworkIface attaches the host TAP. It is present only when the sandbox was
// started with an allowlist; otherwise the machine has no NIC at all.
type NetworkIface struct {
	IfaceID       string       `json:"iface_id"`
	HostDevName   string       `json:"host_dev_name"`
	GuestMAC      string       `json:"guest_mac,omitempty"`
	RxRateLimiter *RateLimiter `json:"rx_rate_limiter,omitempty"`
	TxRateLimiter *RateLimiter `json:"tx_rate_limiter,omitempty"`
}

// RateLimiter is Firecracker's own I/O throttle: two independent token buckets,
// one counting bytes and one counting operations. KelyfOS configures it rather
// than building anything (E1-3) — the limiting happens in the VMM's I/O thread,
// at the barrier where guest traffic is copied to the host device, which is
// exactly where a limit on untrusted code belongs (F-D2).
type RateLimiter struct {
	Bandwidth *TokenBucket `json:"bandwidth,omitempty"`
	Ops       *TokenBucket `json:"ops,omitempty"`
}

// TokenBucket holds Size tokens and takes RefillTimeMS milliseconds to refill
// from empty, so the rate it enforces is Size/RefillTimeMS. The bucket starts
// full, which makes RefillTimeMS also the length of the burst a limit allows
// before it begins to bite.
type TokenBucket struct {
	Size int64 `json:"size"`
	// OneTimeBurst is extra, non-replenishing credit. KelyfOS never sets it: a
	// limit that can be exceeded once by an arbitrary amount is not a limit
	// anybody asked this project for.
	OneTimeBurst int64 `json:"one_time_burst,omitempty"`
	RefillTimeMS int64 `json:"refill_time"`
}

// IOLimits are the per-second I/O rates a sandbox may not exceed, in the units
// kelyfos.toml uses. Zero means that limit is off.
type IOLimits struct {
	NetMbpsRx int // megabits per second
	NetMbpsTx int // megabits per second
	DiskIOPS  int // operations per second
	DiskMbps  int // megabytes per second
}

// Set reports whether any limit at all is configured.
func (l IOLimits) Set() bool {
	return l.NetMbpsRx > 0 || l.NetMbpsTx > 0 || l.DiskIOPS > 0 || l.DiskMbps > 0
}

// Rates are decimal — a megabit is a million bits and a megabyte a million
// bytes — because that is how a rate is quoted everywhere else. Sizes stay
// powers of two, because that is what a size means. docs/resources.md states
// the split so nobody has to infer it from a constant.
const (
	bitsPerMegabit   = 1_000_000
	bytesPerMegabyte = 1_000_000
)

// The largest single request each device puts through the limiter, and
// therefore the smallest bucket that can hold one whole request.
//
// The block figure is measured rather than assumed: the guest reports
// /sys/block/vdb/queue/max_sectors_kb = 4096, so Linux hands virtio-blk single
// 4 MiB requests. The network figure is the largest frame virtio-net reads at
// once.
const (
	maxBlockRequest = 4 << 20
	maxNetFrame     = 64 << 10
)

// bucket turns a per-second rate into a token bucket sized so the limit
// actually holds.
//
// Firecracker enforces size/refill_time, so any pair in that ratio states the
// same rate — but only on paper. A request larger than the whole bucket cannot
// be paid for, and Firecracker deals with it by emptying the bucket and waiting
// out only the deficit; the tokens that would have overflowed the bucket during
// that wait are dropped, and the guest has them for free. Measured on this
// project's own dev machine: a 10 MB/s cap with a 1 MB bucket passed 200 MiB in
// 17.0 s — 12.3 MB/s, 23% over — while the same cap with a 10 MB bucket passed
// it in 19.8 s, or 10.1 MB/s. Same ratio, different truth.
//
// So the bucket is a whole number of seconds' worth of tokens: one second, and
// more only when one second's worth would be smaller than a single request.
// Whole seconds keep every size an exact multiple of the rate, so nothing is
// rounded and the rate enforced is the rate the file asked for.
//
// A tenth-second window was tried and rejected, and the reason is the other
// half of the same mechanism. When the bucket empties, Firecracker waits a
// fixed 100 ms before retrying — so if a single request is a large fraction of
// the bucket, most of each window's tokens are never spent. Measured: a 10 Mbps
// cap with a 125 kB bucket, against 64 kB frames, delivered 6.8 Mbps — 32%
// *under* what was asked for. The same cap with a one-second bucket delivered
// it exactly. A small bucket is not a tighter limit, it is a wrong one.
//
// What a one-second bucket costs, stated because it is real: the bucket starts
// full, and the opening burst is up to *twice* the bucket rather than once.
// Firecracker only advances a bucket's last_update when it has to replenish, so
// a device idle for a refill period before its first traffic drains a full
// bucket and is then immediately handed another. Measured at 10, 40 and
// 100 Mbps against the same 50 MB download, the excess over the configured rate
// was a constant 0.8 s of traffic at each — two buckets, near enough exactly.
//
// One residual: a guest that deliberately raises its own max_sectors_kb past
// the bucket size can still provoke the over-consumption path. That is bounded
// at twice the configured rate and needs deliberate action inside the guest.
func bucket(perSecond, largestRequest int64) *TokenBucket {
	if perSecond <= 0 {
		return nil
	}
	seconds := int64(1)
	if largestRequest > perSecond {
		seconds = (largestRequest + perSecond - 1) / perSecond
	}
	return &TokenBucket{Size: perSecond * seconds, RefillTimeMS: seconds * 1000}
}

// NetLimiters builds the receive and transmit limiters for the guest's NIC.
// Firecracker names them from the guest's point of view: rx is traffic into the
// guest, tx is traffic out of it.
func (l IOLimits) NetLimiters() (rx, tx *RateLimiter) {
	if b := bucket(int64(l.NetMbpsRx)*bitsPerMegabit/8, maxNetFrame); b != nil {
		rx = &RateLimiter{Bandwidth: b}
	}
	if b := bucket(int64(l.NetMbpsTx)*bitsPerMegabit/8, maxNetFrame); b != nil {
		tx = &RateLimiter{Bandwidth: b}
	}
	return rx, tx
}

// DriveLimiter builds the limiter attached to each block device. Note "each":
// Firecracker's limiter is per device, so a sandbox with a workspace has two of
// them and the disk limits are a per-device budget, not a shared one.
func (l IOLimits) DriveLimiter() *RateLimiter {
	bw := bucket(int64(l.DiskMbps)*bytesPerMegabyte, maxBlockRequest)
	ops := bucket(int64(l.DiskIOPS), 1)
	if bw == nil && ops == nil {
		return nil
	}
	return &RateLimiter{Bandwidth: bw, Ops: ops}
}

// firecrackerConfig assembles the machine description Firecracker boots from.
//
// Pulled out of New so it is a pure function of the options: what ends up in
// config.json is the part of a sandbox most worth testing and the part hardest
// to reach once a VM has to exist first.
func firecrackerConfig(opts Options, kernel, rootfs, udsPath, id string) FirecrackerConfig {
	driveLimit := opts.IO.DriveLimiter()
	cfg := FirecrackerConfig{
		BootSource: BootSource{KernelImagePath: kernel},
		Drives: []Drive{{
			DriveID:      "rootfs",
			PathOnHost:   rootfs,
			IsRootDevice: true,
			IsReadOnly:   true,
			RateLimiter:  driveLimit,
		}},
		MachineConfig: MachineConfig{VcpuCount: opts.VcpuCount, MemSizeMib: opts.MemMiB},
		Vsock:         &Vsock{GuestCID: proto.CIDGuest, UDSPath: udsPath},
	}
	if opts.Workspace != nil {
		// The workspace is the second virtio-blk drive, so it is always
		// /dev/vdb in the guest — pinned rather than discovered, because the
		// supervisor should not have to guess which disk is which.
		//
		// It gets its own limiter rather than sharing the root device's: a
		// Firecracker limiter belongs to one device, so disk_iops and
		// disk_mbps are a per-device budget. Said out loud in
		// docs/resources.md, because the alternative reading — one budget
		// split across the disks — is the one people assume.
		cfg.Drives = append(cfg.Drives, Drive{
			DriveID:      "workspace",
			PathOnHost:   opts.Workspace.ImagePath,
			IsRootDevice: false,
			IsReadOnly:   false,
			RateLimiter:  driveLimit,
		})
	}
	if opts.Plugins != nil {
		// Read-only at the device, not merely by convention: a plugin is code
		// the agent may run and must not be code the agent can edit
		// (docs/mcp-surface.md §3.1).
		cfg.Drives = append(cfg.Drives, Drive{
			DriveID:      "plugins",
			PathOnHost:   opts.Plugins.ImagePath,
			IsRootDevice: false,
			IsReadOnly:   true,
			RateLimiter:  driveLimit,
		})
		// Which /dev/vd? is computed from where the drive actually landed
		// rather than assumed to be the third, because it is the second when
		// there is no workspace. The workspace's own device is pinned at
		// /dev/vdb for the same reason it always is: it is always second when
		// it exists at all.
		opts.Plugins.Device = driveDevice(len(cfg.Drives) - 1)
	}
	cfg.BootSource.BootArgs = bootArgs(opts, opts.Plugins.device())
	if opts.Net != nil {
		rx, tx := opts.IO.NetLimiters()
		cfg.NetworkIfaces = []NetworkIface{{
			IfaceID:       "eth0",
			HostDevName:   opts.Net.TAP,
			GuestMAC:      guestMAC(id),
			RxRateLimiter: rx,
			TxRateLimiter: tx,
		}}
	}
	return cfg
}

// jailPaths rewrites every path in a machine's configuration to where the file
// appears inside the jail (P5-1).
//
// The run directory is the chroot root, so every device is at the top level. It
// is done here, after the configuration is otherwise complete, rather than
// threaded through every branch above: one place to read, and a device added
// later cannot forget to be rewritten because it is rewritten by its position
// rather than by its name.
func jailPaths(cfg FirecrackerConfig, names jailNames) FirecrackerConfig {
	cfg.BootSource.KernelImagePath = inJail(names.Kernel)
	for i := range cfg.Drives {
		switch cfg.Drives[i].DriveID {
		case "rootfs":
			cfg.Drives[i].PathOnHost = inJail(names.Rootfs)
		case "workspace":
			cfg.Drives[i].PathOnHost = inJail(names.Workspace)
		case "plugins":
			cfg.Drives[i].PathOnHost = inJail(names.Plugins)
		}
	}
	if cfg.Vsock != nil {
		cfg.Vsock.UDSPath = inJail(names.Vsock)
	}
	return cfg
}

// jailNames are the file names inside a jail. Fixed rather than derived from
// the host paths, because the host names differ per run and the guest's view
// should not.
type jailNames struct {
	Kernel, Rootfs, Workspace, Plugins, Vsock string
}

func defaultJailNames() jailNames {
	return jailNames{
		Kernel:    "kernel",
		Rootfs:    "rootfs.ext4",
		Workspace: "workspace.ext4",
		Plugins:   "plugins.ext4",
		Vsock:     "v.sock",
	}
}

type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type Drive struct {
	DriveID      string       `json:"drive_id"`
	PathOnHost   string       `json:"path_on_host"`
	IsRootDevice bool         `json:"is_root_device"`
	IsReadOnly   bool         `json:"is_read_only"`
	RateLimiter  *RateLimiter `json:"rate_limiter,omitempty"`
}

type MachineConfig struct {
	VcpuCount  int `json:"vcpu_count"`
	MemSizeMib int `json:"mem_size_mib"`
}

// Vsock is the hybrid vsock device. UDSPath is a host Unix socket that
// Firecracker creates and owns; it is not the Firecracker API socket, and no
// host vsock kernel module is involved (docs/protocol.md §1).
type Vsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// bootArgs builds the guest kernel command line.
//
// Deliberately absent: root= and ro. Firecracker inserts both itself from the
// drive's is_root_device and is_read_only flags (src/vmm/src/builder.rs), and
// repeating them here would put the same option on the command line twice.
//
// Also absent: 8250.nr_uarts=0, which is in Firecracker's own default cmdline.
// It disables the serial port, and KelyfOS wants a console — it is the only way
// to see why a guest failed before the supervisor is up.
// driveDevice names the guest block device a drive at index i becomes. Firecracker
// attaches virtio-blk devices in configuration order, so the root device is
// /dev/vda, the next is /dev/vdb, and so on.
func driveDevice(i int) string { return "/dev/vd" + string(rune('a'+i)) }

func bootArgs(opts Options, pluginsDev string) string {
	arch, quiet, net := opts.Arch, opts.Quiet, opts.Net
	scratchBytes, agent, maySpawn := opts.ScratchBytes, opts.Agent, opts.MaySpawn
	workspace := opts.Workspace != nil
	args := []string{
		"reboot=k",                      // no BIOS to reboot through; ask KVM to reset
		"panic=1",                       // a panicked sandbox should die, not sit there
		"nomodule",                      // belt to the kernel config's braces: no modules exist
		"swiotlb=noforce",               // no bounce buffers; there is no real DMA here
		"console=ttyS0",                 // ns16550a on both arches — see docs/protocol.md
		"pci=off",                       // Firecracker exposes virtio over MMIO, not PCI
		"init=/sbin/kelyfos-supervisor", // PID 1 is the supervisor itself (P2-1)
	}
	if arch == "x86_64" {
		// Stop the kernel probing a PS/2 controller Firecracker does not
		// emulate. Pure boot-time saving, and meaningless on aarch64 where the
		// i8042 does not exist.
		args = append(args, "i8042.noaux", "i8042.nomux", "i8042.dumbkbd")
	}
	if net != nil {
		// CONFIG_IP_PNP configures eth0 before userspace starts, so nothing in
		// the guest has to be trusted to bring the network up correctly, and
		// the supervisor learns where the proxy is from the same place
		// (docs/networking.md §5).
		args = append(args,
			fmt.Sprintf("ip=%s::%s:%s::eth0:off", net.GuestIP, net.HostIP, net.Netmask),
			fmt.Sprintf("kelyfos.proxy=%s:%d", net.HostIP, net.ProxyPort),
		)
	}
	if workspace {
		args = append(args, "kelyfos.workspace=/dev/vdb")
	}
	if pluginsDev != "" {
		// Same channel as the workspace device and the proxy address, for the
		// same reason: the kernel command line is the one thing inside the
		// guest that the guest did not write (E4-6).
		args = append(args, "kelyfos.plugins="+pluginsDev)
	}
	if agent != "" {
		// The guest is told which agent it is, rather than asked. Same channel
		// as the proxy address and the scratch cap, and for the same reason:
		// the kernel command line is the one thing inside the guest that the
		// guest did not write (E2-2).
		args = append(args, "kelyfos.agent="+agent)
	}
	if maySpawn {
		// Whether this agent may ask for workers is the host's answer, so the
		// guest is told it rather than left to try and be refused. A tool that
		// is always advertised and always fails teaches a model to ignore
		// failures (docs/teams.md §3.6).
		args = append(args, "kelyfos.spawn=1")
	}
	if scratchBytes > 0 {
		// The cap travels on the kernel command line rather than over a vsock
		// RPC because the overlay is mounted before any channel exists, and
		// because the command line is the one thing in the guest the guest did
		// not write (E1-5, and docs/networking.md §5 for the same reasoning
		// applied to the proxy address).
		args = append(args, fmt.Sprintf("kelyfos.scratch=%d", scratchBytes))
	}
	if quiet {
		args = append(args, "quiet")
	}
	return strings.Join(args, " ")
}

// HostArch reports the build host's architecture using the project's spelling
// (aarch64 / x86_64) rather than Go's (arm64 / amd64).
func HostArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	default:
		return runtime.GOARCH
	}
}

// KernelArtifact is the file Firecracker boots for an architecture. Both are
// uncompressed: Firecracker boots the raw Image on aarch64 and the ELF vmlinux
// on x86_64, never Image.gz and never bzImage.
func KernelArtifact(arch string) (string, error) {
	switch arch {
	case "aarch64":
		return "Image", nil
	case "x86_64":
		return "vmlinux", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", arch)
	}
}
