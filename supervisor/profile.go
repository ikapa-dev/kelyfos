package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Guest confinement: what the supervisor grants what it spawns (P5-3,
// docs/hardening.md §4).
//
// An agent is root inside its own guest and stays root — §6 of that document
// says so and this does not change it. What changes is that being root stops
// being the same thing as being unlimited. Two mechanisms, declared per flavor,
// applied to every process the supervisor starts and to nothing else:
//
//	Landlock  the filesystem. Read and execute the whole image, write only
//	          where writing is the point. An agent can no longer edit the
//	          toolbox it was handed — /bin, /usr, /etc and /lib are writable
//	          through the tmpfs overlay today, and after this they are not.
//	seccomp   the syscall surface. A refusal list rather than an allowlist,
//	          because an allowlist for python3 is a research project and the
//	          crash it eventually produces would look like a security feature
//	          (the same argument P5-2 made against writing one for the VMM).
//
// Both are inherited across fork and exec and both restrict the *calling*
// thread, which is why they are applied by a small re-exec of this same binary
// rather than here: see confine.go.

// Profile is what one flavor grants.
type Profile struct {
	// Name is the flavor this profile belongs to.
	Name string
	// Write lists the directory trees a spawned process may write, create and
	// delete in. Everything else on the filesystem is readable and executable
	// and nothing else is writable.
	Write []string
	// DenySyscalls names the syscalls refused with EPERM, by number for this
	// architecture.
	DenySyscalls []syscallRef
	// AllowPtrace keeps ptrace out of the refusal list. A debugger is the
	// difference between a toolbox and a box, so `dev` keeps it and `base`,
	// which ships no debugger, does not.
	AllowPtrace bool
}

type syscallRef struct {
	name string
	nr   int
}

// writableEverywhere is the set of trees any flavor may write. It is the same
// list for both flavors on purpose: /work is the durable one, and the other
// three are tmpfs that dies with the machine. What differs between flavors is
// the syscall half, not this.
//
//	/work  the workspace, when one is attached — the whole point of a workspace
//	/tmp   where every build system puts its scratch
//	/run   pid files and sockets
//	/root  $HOME, because pip, npm and git all keep caches there and a profile
//	       that breaks them has hardened nothing
var writableEverywhere = []string{"/work", "/tmp", "/run", "/root"}

// writableDevices are the device nodes an ordinary program writes, named one by
// one instead of granting /dev.
//
// This was not a guess: git opens /dev/null read-write before it does anything
// else, and the first profile that granted only the four trees above broke it
// with "could not open '/dev/null' for reading and writing". Granting /dev
// would have fixed that and also handed an agent /dev/vda and /dev/vdb — the
// raw block devices behind the read-only root and the workspace — so the list
// is explicit and the disks are not on it.
//
// A path that does not exist on this machine is skipped rather than refused:
// which nodes devtmpfs presents depends on the flavor, and a profile that
// refuses to load because a machine has no /dev/tty has hardened nothing.
var writableDevices = []string{
	"/dev/null", "/dev/zero", "/dev/full",
	"/dev/random", "/dev/urandom",
	"/dev/tty", "/dev/ptmx",
}

// writableTrees are directories under /dev that a program may write within.
// /dev/pts is where a pty's slave side appears, and a shell writes to it.
var writableDeviceTrees = []string{"/dev/pts", "/dev/shm"}

// Profiles returns the profile for a flavor. An unknown flavor gets the
// strictest one rather than none: a machine whose flavor the host did not name
// is not a machine to relax for.
func profileFor(flavor string) Profile {
	p := Profile{
		Name:         flavor,
		Write:        writableEverywhere,
		DenySyscalls: deniedSyscalls(),
	}
	if flavor == "dev" {
		// The dev flavor ships gdb-adjacent tooling and the whole point of it
		// is to be worked in. Refusing ptrace there would refuse strace, gdb
		// and every language's own debugger, and buy very little: a process
		// may only ptrace another process it could already signal, and inside
		// this guest that is every process, all of them the agent's own.
		p.AllowPtrace = true
	}
	return p
}

// --- Landlock --------------------------------------------------------------

// The rights a writable tree gets. REFER is in here deliberately: without it
// Landlock denies every rename or link that changes a file's parent directory,
// so `mv /tmp/x /work/x` would stop working — the exact shape of breakage §4.2
// warns about.
const writeRights = unix.LANDLOCK_ACCESS_FS_EXECUTE |
	unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
	unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
	unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_MAKE_REG |
	unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
	unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
	unix.LANDLOCK_ACCESS_FS_REFER |
	unix.LANDLOCK_ACCESS_FS_TRUNCATE

// The rights a named device node gets: exactly what a program does to
// /dev/null. No MAKE_* — nothing creates device nodes here — and no REFER,
// because renaming /dev/null somewhere else is not a thing to permit.
const deviceRights = unix.LANDLOCK_ACCESS_FS_READ_FILE |
	unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_TRUNCATE

// The rights everything else gets: look and run, do not touch.
const readRights = unix.LANDLOCK_ACCESS_FS_EXECUTE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_DIR

// handledRights is what the ruleset governs. Anything not named here is left
// alone by Landlock entirely.
//
// LANDLOCK_ACCESS_FS_IOCTL_DEV is deliberately absent. Handling it without
// granting it on /dev would refuse the terminal ioctls every interactive
// program makes — TCGETS on a pty is how a shell decides it is a shell — and
// granting it on /dev would make handling it a no-op. It restricts ioctls on
// device nodes, which is not the surface this profile is about.
const handledRights = writeRights

// minLandlockABI is the oldest Landlock this refuses to run without. The guest
// kernel is built at 6.12 and reports 6; the floor is 2 because REFER, which
// the write set depends on, arrived there.
const minLandlockABI = 2

// landlockABI asks the kernel which Landlock it has. A kernel with none returns
// ENOSYS or EOPNOTSUPP, which is a fact about the machine and not an error to
// paper over.
func landlockABI() (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// applyLandlock builds this profile's ruleset and restricts the calling thread
// to it. Every path in Write must exist; one that does not is a profile that
// does not describe this machine, and is refused rather than skipped.
func applyLandlock(p Profile) error {
	abi, err := landlockABI()
	if err != nil {
		return fmt.Errorf("landlock is not available in this kernel: %w", err)
	}
	if abi < minLandlockABI {
		return fmt.Errorf("landlock ABI %d is older than the %d this profile needs", abi, minLandlockABI)
	}

	attr := unix.LandlockRulesetAttr{Access_fs: handledRights}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create the landlock ruleset: %w", errno)
	}
	rules := int(fd)
	defer unix.Close(rules)

	// The whole image, readable and runnable. Added first so a writable tree
	// underneath it widens rather than narrows: Landlock takes the union of
	// the rules that cover a path.
	if err := allowBeneath(rules, "/", readRights); err != nil {
		return err
	}
	for _, dir := range p.Write {
		if _, err := os.Stat(dir); err != nil {
			// /work only exists when a workspace was attached, which is the one
			// legitimate absence among the trees a flavor names.
			if os.IsNotExist(err) && dir == "/work" {
				continue
			}
			return fmt.Errorf("profile %q names %s, which this machine does not have: %w", p.Name, dir, err)
		}
		if err := allowBeneath(rules, dir, writeRights); err != nil {
			return err
		}
	}
	for _, dir := range writableDeviceTrees {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := allowBeneath(rules, dir, writeRights); err != nil {
			return err
		}
	}
	for _, dev := range writableDevices {
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		// A path_beneath rule on a file covers that file and nothing else, so
		// this is the whole of what is granted: read it, write it, truncate it.
		if err := allowBeneath(rules, dev, deviceRights); err != nil {
			return err
		}
	}

	// Landlock refuses to restrict a thread that could still gain privileges.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("apply the landlock ruleset: %w", errno)
	}
	return nil
}

func allowBeneath(rules int, dir string, rights uint64) error {
	// O_PATH: the ruleset needs a reference to the directory, not the ability
	// to read it here.
	dfd, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s for the ruleset: %w", dir, err)
	}
	defer unix.Close(dfd)

	// This struct is __attribute__((packed)) in the kernel's uapi header, so
	// the twelve bytes the kernel copies are allowed_access followed by
	// parent_fd — which is exactly the prefix of the Go struct. The four bytes
	// of Go padding after it are never read.
	pb := unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(dfd)}
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rules), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pb)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("add %s to the ruleset: %w", dir, errno)
	}
	return nil
}

// --- seccomp ---------------------------------------------------------------

// applySeccomp installs this profile's refusal list on the calling thread.
//
// The action is EPERM rather than a kill. A killed process tells its author
// nothing; a refused syscall produces the error the libc call is documented to
// return, which a program can report and a person can read in the transcript.
func applySeccomp(p Profile) error {
	prog := seccompProgram(p)
	if len(prog) == 0 {
		return nil
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	// No TSYNC: this thread is about to become the whole process through
	// execve, and asking to synchronise a filter across the Go runtime's other
	// threads is asking for a failure that depends on the scheduler.
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("install the seccomp filter: %w", errno)
	}
	return nil
}

// The classic-BPF opcodes this assembler needs. seccomp programs are cBPF, the
// same instruction set P5-2's probe reads back out of the kernel.
const (
	bpfLDW  = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJEQK = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRETK = 0x06 // BPF_RET | BPF_K

	retAllow = 0x7fff0000 // SECCOMP_RET_ALLOW
	retErrno = 0x00050000 // SECCOMP_RET_ERRNO
)

// seccompProgram assembles the refusal list.
//
//	load  arch                       ; a filter that does not pin the
//	jne   this arch -> refuse        ; architecture can be walked past on a
//	load  nr                         ; machine that runs two ABIs
//	jeq   denied[0] -> refuse
//	...
//	ret   ALLOW
//	refuse: ret ERRNO(EPERM)
func seccompProgram(p Profile) []unix.SockFilter {
	var denied []int
	for _, s := range p.DenySyscalls {
		if s.name == "ptrace" && p.AllowPtrace {
			continue
		}
		if s.nr >= 0 {
			denied = append(denied, s.nr)
		}
	}
	if len(denied) == 0 {
		return nil
	}

	// Two instructions after the comparison chain: the allow and the refusal.
	// Every jump is forward and every offset fits in the byte the instruction
	// has for it, which is what bounds the list at 253 entries.
	prog := make([]unix.SockFilter, 0, len(denied)+5)
	prog = append(prog,
		unix.SockFilter{Code: bpfLDW, K: 4},                        // seccomp_data.arch
		unix.SockFilter{Code: bpfJEQK, Jt: 0, Jf: 0, K: auditArch}, // patched below
		unix.SockFilter{Code: bpfLDW, K: 0},                        // seccomp_data.nr
	)
	// The arch mismatch jumps to the refusal, which is the last instruction.
	// Its distance is known only once the chain is built, so it is filled in
	// after: len(denied) comparisons + the allow, counted from the instruction
	// after the jump.
	prog[1].Jf = uint8(len(denied) + 2)

	for i, nr := range denied {
		// Distance from the instruction after this one to the refusal.
		prog = append(prog, unix.SockFilter{
			Code: bpfJEQK,
			Jt:   uint8(len(denied) - i), // to the refusal
			Jf:   0,                      // to the next comparison
			K:    uint32(nr),
		})
	}
	prog = append(prog,
		unix.SockFilter{Code: bpfRETK, K: retAllow},
		unix.SockFilter{Code: bpfRETK, K: retErrno | uint32(unix.EPERM)},
	)
	return prog
}

// Refused is the syscalls this profile actually refuses, in the order the
// filter compares them.
func (p Profile) Refused() []syscallRef {
	out := make([]syscallRef, 0, len(p.DenySyscalls))
	for _, s := range p.DenySyscalls {
		if s.name == "ptrace" && p.AllowPtrace {
			continue
		}
		if s.nr >= 0 {
			out = append(out, s)
		}
	}
	return out
}

// Describe is the one-line form: what a person sees on the terminal and what
// the ready frame carries. The full list is docs/reference/profiles.md, which
// is generated from this same code by `make docs`.
func (p Profile) Describe() string {
	name := p.Name
	if name == "" {
		name = "unnamed"
	}
	note := ""
	if p.AllowPtrace {
		note = ", ptrace permitted"
	}
	return fmt.Sprintf("%s · write %s · %d syscalls refused%s",
		name, strings.Join(p.Write, " "), len(p.Refused()), note)
}

// DumpProfile writes the full profile for a flavor, which is what `make docs`
// turns into the reference page. Generated rather than transcribed, so the
// documented list is the enforced list (F-D4).
func DumpProfile(w io.Writer, flavors []string) error {
	for _, f := range flavors {
		p := profileFor(f)
		if _, err := fmt.Fprintf(w, "flavor %s\n", f); err != nil {
			return err
		}
		fmt.Fprintf(w, "  arch %s\n", runtime.GOARCH)
		fmt.Fprintf(w, "  landlock-abi-min %d\n", minLandlockABI)
		for _, d := range p.Write {
			fmt.Fprintf(w, "  write %s\n", d)
		}
		// Every entry the policy names, including any this architecture does
		// not have — printed as "-" rather than omitted, so the difference
		// between "not refused" and "not a syscall here" is visible.
		for _, sc := range p.DenySyscalls {
			if sc.name == "ptrace" && p.AllowPtrace {
				continue
			}
			nr := "-"
			if sc.nr >= 0 {
				nr = fmt.Sprint(sc.nr)
			}
			fmt.Fprintf(w, "  refuse %s %s\n", sc.name, nr)
		}
	}
	return nil
}
