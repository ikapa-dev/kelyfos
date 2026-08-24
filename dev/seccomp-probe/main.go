//go:build linux

// Command seccomp-probe reads the syscall filter that is actually installed on
// a running process and says what it permits.
//
//	sudo dev/seccomp-probe -pid <vmm pid>
//
// This exists because "Firecracker ships a seccomp filter and we do not turn it
// off" is a claim about somebody else's binary, and P5-2 asks for the filter to
// be established rather than assumed. The program installed in the kernel is
// the only thing that settles it, so that is what this reads: it attaches with
// ptrace, pulls the classic-BPF program back out with PTRACE_SECCOMP_GET_FILTER,
// fingerprints it, and then interprets it to work out which syscall numbers can
// reach an ALLOW.
//
// It is a development tool and is not shipped in the CLI. Dumping another
// process's filter needs CAP_SYS_ADMIN, and a diagnostic that wants root has no
// business in the surface a person runs every day; `dev/accept-seccomp.sh` is
// the only caller.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// PTRACE_SECCOMP_GET_FILTER is not in the syscall package. Its value is stable
// uapi (include/uapi/linux/ptrace.h, since Linux 4.4) and it needs
// CONFIG_CHECKPOINT_RESTORE in the running kernel.
const ptraceSeccompGetFilter = 0x420c

// __WALL, so Wait4 will report a stop from a thread that is not our own child
// in the "cloned with a non-SIGCHLD exit signal" sense — which every thread of
// another process is.
const waitAll = 0x40000000

// sockFilter is struct sock_filter: one classic-BPF instruction, eight bytes.
type sockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// The audit arch constants a seccomp filter compares against, from
// include/uapi/linux/audit.h.
const (
	auditArchAARCH64 = 0xc00000b7
	auditArchX86_64  = 0xc000003e
)

func main() {
	pid := flag.Int("pid", 0, "process to read the filter of")
	format := flag.String("format", "text", "text (with the thread list), record (what dev/expect holds), or json")
	maxSyscall := flag.Int("max", 1024, "highest syscall number to classify")
	flag.Parse()

	if *pid <= 0 {
		fmt.Fprintln(os.Stderr, "seccomp-probe: -pid is required")
		os.Exit(2)
	}
	report, err := probe(*pid, *maxSyscall)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seccomp-probe: %v\n", err)
		os.Exit(1)
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp-probe: %v\n", err)
			os.Exit(1)
		}
	case "record":
		fmt.Print(report.Text(false))
	case "text":
		fmt.Print(report.Text(true))
	default:
		fmt.Fprintf(os.Stderr, "seccomp-probe: unknown format %q\n", *format)
		os.Exit(2)
	}
}

// Report is the whole answer for one process.
type Report struct {
	Schema    int      `json:"schema"`
	Arch      string   `json:"arch"`
	AuditArch string   `json:"audit_arch"`
	PID       int      `json:"pid"`
	Exe       string   `json:"exe"`
	Threads   []Thread `json:"threads"`
	// Categories is Threads collapsed to one entry per distinct filter, which
	// is the shape worth recording: two vcpu threads running byte-identical
	// programs are one fact, not two.
	Categories []Category `json:"categories"`
}

// Thread is what /proc says about one task, before any interpretation.
type Thread struct {
	TID      int    `json:"tid"`
	Comm     string `json:"comm"`
	Category string `json:"category"`
	Mode     int    `json:"seccomp_mode"`
	Filters  int    `json:"seccomp_filters"`
	SHA256   string `json:"program_sha256"`
	Insns    int    `json:"program_instructions"`
}

// Category is one distinct filter and what it permits.
type Category struct {
	Name        string        `json:"name"`
	Threads     []string      `json:"threads"`
	SHA256      string        `json:"program_sha256"`
	Insns       int           `json:"program_instructions"`
	Mismatch    string        `json:"mismatch_action"`
	ArchFail    string        `json:"foreign_arch_action"`
	Allowed     []string      `json:"allowed"`
	Conditional []Conditional `json:"conditional"`
	Complete    bool          `json:"analysis_complete"`
}

// Conditional is a syscall the filter permits only for some arguments. It is
// reported separately rather than folded into the allow list, because "allowed"
// and "allowed if the first argument is one of three values" are different
// promises and a record that flattens them is overstating one of them.
type Conditional struct {
	Syscall string   `json:"syscall"`
	Number  uint32   `json:"number"`
	Actions []string `json:"other_actions"`
}

func probe(pid, maxSyscall int) (*Report, error) {
	arch, auditArch, err := hostArch()
	if err != nil {
		return nil, err
	}
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

	tids, err := threadsOf(pid)
	if err != nil {
		return nil, err
	}
	names, err := loadSyscallNames()
	if err != nil {
		return nil, err
	}

	rep := &Report{
		Schema:    1,
		Arch:      arch,
		AuditArch: fmt.Sprintf("0x%08x", auditArch),
		PID:       pid,
		Exe:       exe,
	}
	// byFingerprint collapses identical programs; byOrder keeps the order they
	// were first seen so the report is stable across runs.
	byFingerprint := map[string]*Category{}
	var order []string

	for _, tid := range tids {
		comm, mode, filters, err := threadStatus(tid)
		if err != nil {
			return nil, err
		}
		t := Thread{TID: tid, Comm: comm, Category: categoryOf(comm), Mode: mode, Filters: filters}

		if mode != 2 || filters == 0 {
			// Nothing to dump, and the absence is itself the finding.
			rep.Threads = append(rep.Threads, t)
			continue
		}
		if filters > 1 {
			// Several filters compose by running all of them and taking the
			// most severe result. Firecracker installs one. Rather than
			// implement a composition rule nothing here exercises, say so.
			return nil, fmt.Errorf("thread %d has %d stacked filters; this tool "+
				"reads one per thread and will not guess how several compose", tid, filters)
		}
		prog, err := dumpFilter(tid, 0)
		if err != nil {
			return nil, fmt.Errorf("thread %d: %w", tid, err)
		}
		sum := programSHA256(prog)
		t.SHA256 = sum
		t.Insns = len(prog)
		rep.Threads = append(rep.Threads, t)

		if _, seen := byFingerprint[sum]; !seen {
			cat := classify(prog, auditArch, maxSyscall, names)
			cat.Name = t.Category
			cat.SHA256 = sum
			cat.Insns = len(prog)
			byFingerprint[sum] = cat
			order = append(order, sum)
		}
		c := byFingerprint[sum]
		c.Threads = append(c.Threads, comm)
	}
	for _, sum := range order {
		rep.Categories = append(rep.Categories, *byFingerprint[sum])
	}
	return rep, nil
}

// classify walks the program once per syscall number and sorts the results into
// three buckets: permitted outright, permitted for some arguments, and refused.
func classify(prog []sockFilter, auditArch uint32, maxSyscall int, names map[uint32]string) *Category {
	cat := &Category{Complete: true}

	for nr := 0; nr <= maxSyscall; nr++ {
		actions, ok := reachableActions(prog, uint32(nr), auditArch)
		if !ok {
			cat.Complete = false
			continue
		}
		var allow, other []uint32
		for a := range actions {
			if isAllow(a) {
				allow = append(allow, a)
			} else {
				other = append(other, a)
			}
		}
		if len(allow) == 0 {
			continue
		}
		name := syscallName(names, uint32(nr))
		if len(other) == 0 {
			cat.Allowed = append(cat.Allowed, name)
			continue
		}
		sort.Slice(other, func(i, j int) bool { return other[i] < other[j] })
		labels := make([]string, 0, len(other))
		for _, a := range other {
			labels = append(labels, actionName(a))
		}
		cat.Conditional = append(cat.Conditional, Conditional{
			Syscall: name, Number: uint32(nr), Actions: labels,
		})
	}
	sort.Strings(cat.Allowed)
	sort.Slice(cat.Conditional, func(i, j int) bool {
		return cat.Conditional[i].Syscall < cat.Conditional[j].Syscall
	})

	// What a syscall that is in no list gets. 0xfffe is chosen because no
	// architecture Linux supports assigns it, so the walk lands on whatever the
	// program does with an unrecognised number.
	cat.Mismatch = summarize(prog, auditArch, 0xfffe)
	// And what happens to a syscall issued under a different architecture,
	// which is the check every seccompiler-built filter opens with.
	cat.ArchFail = summarize(prog, 0, 0)
	return cat
}

func summarize(prog []sockFilter, auditArch, nr uint32) string {
	actions, ok := reachableActions(prog, nr, auditArch)
	if !ok {
		return "UNRESOLVED"
	}
	labels := make([]string, 0, len(actions))
	for a := range actions {
		labels = append(labels, actionName(a))
	}
	sort.Strings(labels)
	return strings.Join(labels, "|")
}

// --- ptrace ---------------------------------------------------------------

// dumpFilter pulls one installed filter program out of a thread.
//
// The thread has to be in ptrace-stop for the request to be answered, so it is
// attached (which stops it), read, and detached. The VMM is stopped for the
// microseconds this takes; the alternative is not reading the filter at all.
func dumpFilter(tid, index int) ([]sockFilter, error) {
	// Every ptrace request for a tracee must come from the thread that
	// attached to it, so this goroutine is nailed to one.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if _, err := ptrace(syscall.PTRACE_ATTACH, tid, 0, 0); err != nil {
		return nil, fmt.Errorf("attach: %w (CAP_SYS_ADMIN is needed; run under sudo)", err)
	}
	defer ptrace(syscall.PTRACE_DETACH, tid, 0, 0)

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(tid, &ws, waitAll, nil); err != nil {
		return nil, fmt.Errorf("wait for the ptrace-stop: %w", err)
	}
	if !ws.Stopped() {
		return nil, errors.New("the thread did not stop, so its filter cannot be read")
	}

	n, err := ptrace(ptraceSeccompGetFilter, tid, uintptr(index), 0)
	if err != nil {
		return nil, fmt.Errorf("filter %d: %w (needs CONFIG_CHECKPOINT_RESTORE)", index, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("filter %d is empty", index)
	}
	prog := make([]sockFilter, int(n))
	if _, err := ptrace(ptraceSeccompGetFilter, tid, uintptr(index),
		uintptr(unsafe.Pointer(&prog[0]))); err != nil {
		return nil, fmt.Errorf("read filter %d: %w", index, err)
	}
	return prog, nil
}

func ptrace(req, pid int, addr, data uintptr) (uintptr, error) {
	r, _, errno := syscall.Syscall6(syscall.SYS_PTRACE,
		uintptr(req), uintptr(pid), addr, data, 0, 0)
	if errno != 0 {
		return r, errno
	}
	return r, nil
}

func programSHA256(prog []sockFilter) string {
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&prog[0])), len(prog)*8)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// --- /proc ----------------------------------------------------------------

func threadsOf(pid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, fmt.Errorf("read the thread list of pid %d: %w", pid, err)
	}
	var tids []int
	for _, e := range entries {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			tids = append(tids, n)
		}
	}
	sort.Ints(tids)
	if len(tids) == 0 {
		return nil, fmt.Errorf("pid %d has no threads", pid)
	}
	return tids, nil
}

func threadStatus(tid int) (comm string, mode, filters int, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	// Seccomp_filters has been in /proc/<pid>/status since Linux 5.9. A kernel
	// without it reports zero, and the mode alone still settles whether a
	// filter is on.
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Seccomp:"):
			mode = intField(line)
		case strings.HasPrefix(line, "Seccomp_filters:"):
			filters = intField(line)
		}
	}
	if mode == 2 && filters == 0 {
		// The mode says a filter is installed, so treat the count as one rather
		// than as "nothing to read" on a kernel too old to report it.
		filters = 1
	}
	return comm, mode, filters, sc.Err()
}

func intField(line string) int {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fields[1])
	return n
}

// categoryOf names the thread the way Firecracker's own filter file does. The
// comm values are the VMM's: the main thread keeps the process name, the API
// thread is fc_api, and each vcpu is "fc_vcpu N".
func categoryOf(comm string) string {
	switch {
	case comm == "fc_api":
		return "api"
	case strings.HasPrefix(comm, "fc_vcpu"):
		return "vcpu"
	default:
		return "vmm"
	}
}

// --- syscall names --------------------------------------------------------

var defineLine = regexp.MustCompile(`^#define\s+(__NR\w*)\s+(\w+)\s*$`)

// loadSyscallNames gets the number-to-name table from the machine's own kernel
// headers rather than from a table committed here, which would be a second
// thing to keep true.
//
// It asks the C preprocessor rather than reading the header as text, because
// asm-generic/unistd.h defines both ABIs' spellings and picks between them with
// `#if __BITS_PER_LONG == 64`. Read as text, both branches are visible at once
// and syscall 79 is as much `fstatat64` as it is `newfstatat` — which is how
// the first version of this recorded two syscalls under their 32-bit names on a
// 64-bit machine. Re-implementing the preprocessor to fix that would be
// choosing to own a second copy of somebody else's conditional; running it
// costs one process.
//
// Two passes over what comes back, because the table does not give every number
// directly: `#define __NR3264_fstat 80` and then `#define __NR_fstat
// __NR3264_fstat`.
func loadSyscallNames() (map[uint32]string, error) {
	var lastErr error
	for _, cc := range []string{"cc", "gcc", "clang"} {
		cmd := exec.Command(cc, "-E", "-dM", "-x", "c", "-")
		cmd.Stdin = strings.NewReader("#include <asm/unistd.h>\n")
		out, err := cmd.Output()
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", cc, err)
			continue
		}
		names := parseSyscallNames(string(out))
		if len(names) == 0 {
			lastErr = fmt.Errorf("%s defined no __NR_ macros", cc)
			continue
		}
		return names, nil
	}
	// Falling back to reading the header as text would produce a record that
	// disagrees with the one this machine's compiler would produce, and a
	// record that depends on which tools were installed is worse than no
	// record.
	return nil, fmt.Errorf("no C preprocessor to resolve syscall names (%v); "+
		"install build-essential", lastErr)
}

func parseSyscallNames(header string) map[uint32]string {
	// symbol -> literal number, for every __NR* define that gives one.
	values := map[string]uint32{}
	// symbol -> symbol, for the ones that forward to another define.
	aliases := map[string]string{}

	for _, line := range strings.Split(header, "\n") {
		m := defineLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		if n, err := strconv.ParseUint(m[2], 10, 32); err == nil {
			values[m[1]] = uint32(n)
			continue
		}
		aliases[m[1]] = m[2]
	}

	names := map[uint32]string{}
	claim := func(sym string, n uint32) {
		name, ok := strings.CutPrefix(sym, "__NR_")
		if !ok {
			return
		}
		// First definition wins, so a later alias cannot rename a syscall the
		// header already named outright.
		if _, taken := names[n]; !taken {
			names[n] = name
		}
	}
	// Sorted, so that a number a header names twice always resolves to the same
	// one of the two. A record whose contents depend on map iteration order is
	// a record that fails its own diff every other run.
	for _, sym := range sortedKeys(values) {
		claim(sym, values[sym])
	}
	for _, sym := range sortedKeys(aliases) {
		if n, ok := values[aliases[sym]]; ok {
			claim(sym, n)
		}
	}
	return names
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func syscallName(names map[uint32]string, nr uint32) string {
	if n, ok := names[nr]; ok {
		return n
	}
	return fmt.Sprintf("syscall_%d", nr)
}

func hostArch() (string, uint32, error) {
	switch runtime.GOARCH {
	case "arm64":
		return "aarch64", auditArchAARCH64, nil
	case "amd64":
		return "x86_64", auditArchX86_64, nil
	}
	return "", 0, fmt.Errorf("no audit arch known for GOARCH %q", runtime.GOARCH)
}

// --- rendering ------------------------------------------------------------

// Text is the recorded form: stable field order, one syscall per line, so a
// diff against the committed expectation names exactly what moved.
//
// withThreads is off for the committed record and on for a person reading the
// output. The thread list names each vcpu by index, so a machine with four
// vcpus writes a different list than one with two — a true fact about that run
// and a useless one to diff a filter against.
func (r *Report) Text(withThreads bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "arch %s\n", r.Arch)
	fmt.Fprintf(&b, "audit_arch %s\n", r.AuditArch)
	fmt.Fprintf(&b, "exe %s\n", filepath.Base(r.Exe))
	if withThreads {
		for _, t := range r.Threads {
			fmt.Fprintf(&b, "thread %-12s category=%-4s seccomp=%d filters=%d\n",
				t.Comm, t.Category, t.Mode, t.Filters)
		}
	}
	for _, c := range r.Categories {
		fmt.Fprintf(&b, "\nfilter %s\n", c.Name)
		fmt.Fprintf(&b, "  instructions %d\n", c.Insns)
		fmt.Fprintf(&b, "  sha256 %s\n", c.SHA256)
		fmt.Fprintf(&b, "  unlisted-syscall %s\n", c.Mismatch)
		fmt.Fprintf(&b, "  foreign-arch %s\n", c.ArchFail)
		fmt.Fprintf(&b, "  complete %t\n", c.Complete)
		fmt.Fprintf(&b, "  allowed %d\n", len(c.Allowed))
		for _, s := range c.Allowed {
			fmt.Fprintf(&b, "    %s\n", s)
		}
		fmt.Fprintf(&b, "  conditional %d\n", len(c.Conditional))
		for _, c := range c.Conditional {
			fmt.Fprintf(&b, "    %s otherwise=%s\n", c.Syscall, strings.Join(c.Actions, ","))
		}
	}
	return b.String()
}
