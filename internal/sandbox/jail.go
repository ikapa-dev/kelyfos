package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/denial"
)

// Running Firecracker under its own jailer (P5-1, docs/hardening.md §2).
//
// The VMM is the process that would matter if the hardware boundary ever
// failed, and until now it ran as the invoking user, in that user's mount
// namespace, able to address their home directory and every session record in
// it. The jailer takes that away: a chroot containing only what this machine
// needs, its own PID namespace, /dev/kvm and nothing else of the host's
// devices, and a uid that is not root.
//
// Two facts shape everything here, both established by running it rather than
// by reading about it:
//
//   - **The jailer requires root.** As an unprivileged user it fails at the
//     chown of its own copied binary. So KelyfOS invokes it through `sudo -n`,
//     exactly as it already invokes `ip` and `nft` for egress, and `doctor`
//     checks for it. Without it a run refuses and says what to add to sudoers.
//   - **The jailer accepts a chroot directory that already exists and has
//     files in it.** That is what makes this design possible at all: the host
//     binds its own listening sockets and writes the machine's configuration
//     before the VMM starts, and those have to be inside the jail for the VMM
//     to reach them. A jail built after the fact could not contain them.
//
// So the sandbox's run directory *is* the jail root. Every path the host uses
// is unchanged in kind — it is still an absolute host path to a real file — and
// inside the chroot the same files are at the top level.

// jailerUID is who the VMM ends up as: the invoking user. Under sudo the
// process would otherwise be root, so this is the drop that keeps the jail from
// being a regression. A dedicated system account would be a stronger drop and
// is deliberately not required — it would put "create a user" in the quickstart
// to protect against a case the chroot already narrows sharply.
func jailerUID() (uid, gid int) { return os.Getuid(), os.Getgid() }

// JailBase is where jails live: one directory per sandbox, under the run root.
func JailBase() string { return RunRoot() }

// jailRunDir is the chroot the jailer builds for an id, and therefore the run
// directory. The shape is the jailer's, not ours: <base>/<exec>/<id>/root.
func jailRunDir(id string) string {
	return filepath.Join(JailBase(), "firecracker", id, "root")
}

// jailDir is the directory to remove when the sandbox is gone — the level
// above the chroot, so nothing of the jail is left behind.
func jailDir(id string) string { return filepath.Join(JailBase(), "firecracker", id) }

// ErrNoJailer is returned when this machine cannot run the jailer. The caller
// turns it into the refusal a person reads, with the sudoers line in it.
var ErrNoJailer = errors.New("the jailer needs passwordless sudo")

// JailAvailable reports whether `sudo -n jailer` can run here.
//
// Checked by running it rather than by looking for the binary: a jailer on PATH
// that sudo will not run without a password is a jailer this machine does not
// have, and finding that out at boot time is finding it out too late.
func JailAvailable() error {
	if _, err := exec.LookPath("jailer"); err != nil {
		return fmt.Errorf("%w: jailer is not on PATH", ErrNoJailer)
	}
	cmd := exec.Command("sudo", "-n", "jailer", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNoJailer, strings.TrimSpace(firstLineOf(string(out))))
	}
	return nil
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// SudoersLine is the line a person adds to make the jailer usable. Exported so
// `kelyfos doctor` prints the same text the refusal does — one string, so the
// fix somebody is given cannot depend on which of the two told them.
func SudoersLine() string { return sudoersLine() }

// sudoersLine is the line a person adds to make the jailer usable.
//
// Built from this machine rather than printed as a template: the user name and
// the jailer's actual path are the two things somebody would otherwise have to
// work out, and a fix line that has to be adapted before it can be pasted is a
// fix line that gets pasted wrong.
func sudoersLine() string {
	who := os.Getenv("USER")
	if who == "" {
		if u, err := user.Current(); err == nil {
			who = u.Username
		}
	}
	return fmt.Sprintf("%s ALL=(root) NOPASSWD: %s", who, jailerPath())
}

func jailerPath() string {
	if p, err := exec.LookPath("jailer"); err == nil {
		return p
	}
	return "/usr/local/bin/jailer"
}

// requireJail is the check every entry point gets, because it is made here
// rather than at each of them.
//
// `run`, `team up`, `fork`, `snapshot restore`, `serve-mcp` and `shim` all
// build a sandbox through this package, so putting the refusal in the one place
// they share is what makes "every entry point goes through the jailer, or none
// does" structural instead of a rule six call sites have to remember.
func requireJail(opts Options) error {
	if opts.NoJail {
		return nil
	}
	if err := JailAvailable(); err != nil {
		return denial.JailNoSudo.Err(denial.V{
			"reason":  strings.TrimPrefix(err.Error(), ErrNoJailer.Error()+": "),
			"sudoers": sudoersLine(),
		})
	}
	return nil
}

// The names a snapshot's two files take inside a jail. Fixed, because the VMM
// writes them and the host moves them out immediately afterwards; nothing else
// ever sees these names.
const (
	jailSnapState = "snapshot.state"
	jailSnapMem   = "snapshot.mem"
)

// inJail is where a file in the run directory appears from inside the chroot.
// The run directory is the chroot root, so it is the bare name.
func inJail(name string) string { return "/" + name }

// jailArgv wraps a Firecracker command line in the jailer.
//
// The arguments after `--` are Firecracker's own and are given chroot-relative
// paths, because that is the filesystem the VMM will see.
func jailArgv(id string, slice *Slice, fcArgs []string) []string {
	uid, gid := jailerUID()
	argv := []string{"sudo", "-n", "jailer",
		"--id", id,
		"--exec-file", firecrackerPath(),
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),
		"--chroot-base-dir", JailBase(),
	}
	// --new-pid-ns is deliberately not passed. It makes the jailer fork into a
	// new PID namespace and the parent return, so the process KelyfOS waits on
	// exits the moment the machine starts and every run reports "firecracker
	// exited before the guest was ready". Supervising the VMM matters more than
	// hiding the host's process list from a VMM that is already chrooted and
	// unprivileged; found by trying it.
	// Placed inside the cgroup KelyfOS already made rather than beside it, so
	// the caps from E1 keep applying to the jailed process (E1-2). The
	// clone-time placement a direct run uses is not available here — the
	// jailer forks — so the parent cgroup is named instead.
	if slice.Direct() && slice.Path != "" {
		if rel := cgroupRelative(slice.Path); rel != "" {
			argv = append(argv, "--cgroup-version", "2", "--parent-cgroup", rel)
		}
	}
	argv = append(argv, "--")
	return append(argv, fcArgs...)
}

// firecrackerPath resolves the VMM binary, because the jailer wants a path and
// not a name to look up.
func firecrackerPath() string {
	if p, err := exec.LookPath("firecracker"); err == nil {
		return p
	}
	return "/usr/local/bin/firecracker"
}

// cgroupRelative turns an absolute cgroup path into the form the jailer wants:
// relative to the cgroup mount point.
func cgroupRelative(path string) string {
	const mount = "/sys/fs/cgroup/"
	if strings.HasPrefix(path, mount) {
		return strings.TrimPrefix(path, mount)
	}
	return ""
}

// jailedPID reads the PID the jailer recorded for the VMM.
//
// Needed because our own child is `sudo`, whose child is the jailer, which
// execs into Firecracker. Every host-side thing that wants the VMM — reading
// its cgroup, checking its seccomp mode, signalling it — wants this one.
func jailedPID(runDir string) (int, error) {
	deadline := time.Now().Add(5 * time.Second)
	path := filepath.Join(runDir, "firecracker.pid")
	for {
		blob, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(blob)))
			if err == nil && pid > 0 {
				return pid, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("the jailer wrote no pid file at %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// removeJail deletes a jail directory.
//
// Through sudo, because the jailer leaves root-owned files in it: the pid file,
// and a copy of the host's CPU topology under sys/. A plain RemoveAll fails
// half way and leaves the rest, which over a few hundred runs is a disk full of
// abandoned chroots.
func removeJail(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	out, err := exec.Command("sudo", "-n", "rm", "-rf", dir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove jail %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// linkInto puts a file the VMM needs inside the jail.
//
// A hard link when the source is on the same filesystem, which it is for
// everything KelyfOS builds — images and jails both live under the cache root —
// and a copy otherwise. The distinction matters for the rootfs: copying a
// 128 MiB image per sandbox would make `fork -n 4` cost half a gigabyte of disk
// for four machines that share one read-only file.
func linkInto(src, dest string) error {
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Link(src, dest); err == nil {
		return nil
	} else if !isCrossDevice(err) {
		return fmt.Errorf("link %s into the jail: %w", src, err)
	}
	return copyOnto(src, dest)
}

// copyOnto is the cross-device half both link-or-copy paths here share, with
// the source's permissions, because the destination is being created.
func copyOnto(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	return out.Close()
}

// writeBackImage puts src at dest the other way round from linkInto: the
// destination is never removed, it is replaced.
//
// linkInto is right for staging into a jail nobody has looked in yet — the
// destination is a name this package made moments ago, and losing it costs
// nothing. It is wrong for the direction this function serves, where the
// destination is the person's own workspace image. Remove-then-copy means that
// between the remove and the last byte there is no image at all, and after an
// interruption in the middle of it there is a partial one under the name they
// trust: a write-back that can destroy what it is rescuing. Measured, the
// failure did not even need an interruption — a copy that could not be finished
// left an empty file where the image had been.
//
// So the new content is built beside the destination and renamed onto it, which
// is atomic within a filesystem and is the shape every other write-back here
// uses (stageFile, and the tree swap in workspace.go). Beside it rather than in
// a temporary directory for that reason: rename is atomic only within one
// filesystem, and the case this exists for is the one where the two ends are on
// different ones.
func writeBackImage(src, dest string) error {
	tmp := dest + ".kelyfos-writeback"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Removed on every path that does not reach the rename, so a write-back
	// that fails leaves the destination alone *and* leaves nothing beside it.
	// Once the rename has taken the name away this finds nothing, which is the
	// same no-op stageFile's deferred remove makes.
	defer os.Remove(tmp)
	if err := os.Link(src, tmp); err != nil {
		if !isCrossDevice(err) {
			return fmt.Errorf("link %s out of the jail: %w", src, err)
		}
		if err := copyOnto(src, tmp); err != nil {
			return err
		}
	}
	return os.Rename(tmp, dest)
}

func isCrossDevice(err error) bool {
	var le *os.LinkError
	if errors.As(err, &le) {
		return errors.Is(le.Err, syscall.EXDEV) || errors.Is(le.Err, syscall.EPERM)
	}
	return false
}

// stageJail puts every file the VMM needs inside the chroot and returns the
// configuration rewritten to the paths it will see there.
//
// The vsock socket is not staged: the host binds it inside the run directory
// already, which is the chroot root, so it is in the jail by construction. That
// is the whole reason the run directory and the jail root are the same place.
func stageJail(runDir string, opts Options, kernel, rootfs string, cfg FirecrackerConfig) (FirecrackerConfig, error) {
	names := defaultJailNames()
	staged := []struct{ src, name string }{
		{kernel, names.Kernel},
		{rootfs, names.Rootfs},
	}
	if opts.Workspace != nil {
		staged = append(staged, struct{ src, name string }{opts.Workspace.ImagePath, names.Workspace})
	}
	if opts.Plugins != nil {
		staged = append(staged, struct{ src, name string }{opts.Plugins.ImagePath, names.Plugins})
	}
	for _, f := range staged {
		if err := linkInto(f.src, filepath.Join(runDir, f.name)); err != nil {
			return cfg, err
		}
	}
	return jailPaths(cfg, names), nil
}

// syncJailedWorkspace copies a jailed workspace image back out to where the
// host expects it.
//
// A hard link would make this unnecessary — the two names would be one file —
// and that is what happens on the same filesystem, which is every ordinary
// installation. The copy path exists for the case where it is not, and doing
// nothing there would silently lose an agent's work at teardown, which is the
// one failure this product must not have.
//
// Through writeBackImage rather than linkInto: the destination here is the
// host's image, not a name inside a jail, and it is only ever replaced whole.
func syncJailedWorkspace(runDir, hostImage string) error {
	inside := filepath.Join(runDir, defaultJailNames().Workspace)
	si, err := os.Stat(inside)
	if err != nil {
		return nil // never staged; nothing to bring back
	}
	hi, err := os.Stat(hostImage)
	if err == nil && os.SameFile(si, hi) {
		return nil // the same file by two names: the link did its job
	}
	return writeBackImage(inside, hostImage)
}
