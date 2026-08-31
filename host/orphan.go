package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// The orphan scan (ST-0.2, the doctor half of IA-M1): a `run`/`restore`
// process that died without its teardown leaves the machine it booted —
// Firecracker under its jailer, its TAP, its nftables table, its jail
// directory — running and unreachable forever, because the vsock control
// channel died with the process and nothing reaps what it did not create.
// `kelyfos doctor` is where a reconciliation sweep belongs: it is already the
// command that looks at the machine rather than at a session.
//
// The rule this file will not break is §8 trap 1 of the security testing plan,
// and it is worth writing out because the obvious implementation is the wrong
// one: on a machine where several worktrees run sandboxes at once, "a
// firecracker with a dead parent" is not proof of anything. The proof this
// scan accepts is layered, and every layer is checkable:
//
//   - A VMM is **KelyfOS's** when its jail chroot resolves under a KelyfOS
//     run root (`<cache>/run/firecracker/<id>/root`, read from /proc/<pid>/root)
//     or its own argv names a socket under one — the paths only this product
//     creates. A bare `firecracker` somebody is running by hand matches
//     neither and is never listed, let alone signalled.
//   - A KelyfOS VMM is **orphaned** when no live `kelyfos` process sits
//     anywhere in its ancestor chain. A peer worktree's boot in progress has
//     one — that is the point of walking the chain instead of reading one
//     ppid — and a `kill -9`ed run leaves its VMM reparented to init (or
//     under a zombie, which counts as dead: a zombie supervises nothing).
//   - A TAP `kelyfos<id>` or a table `kelyfos_<id>` is **leftover** when no
//     live VMM carries that id and no live `kelyfos` process's run
//     directory names it — the second condition keeps a machine that is
//     mid-boot (TAP up, VMM a few milliseconds away) from being reported by
//     a doctor that ran inside the window.
//
// `--reap-orphaned` turns the report into action, and it is opt-in for the
// same reason doctor itself is read-only by default: stopping a VMM and
// deleting its network plumbing is a judgement somebody should ask for. What
// it reaps is exactly what the scan proved; what it cannot prove it leaves
// and says so.

// orphan is one piece of residue the scan attributed to this product and to
// no live process. PID is 0 for network residue with no surviving VMM; Cache
// is the run root the evidence pointed at, so the reaper can reach a jail
// directory under a peer worktree's cache without guessing.
type orphan struct {
	Kind  string // "vmm", "tap", "table"
	ID    string
	PID   int
	Cache string
	// StartMS pins the process this finding was made about: the reaper
	// re-checks it before signalling, because a pid that exited and was
	// recycled between scan and reap belongs to somebody else now (review,
	// finding 6).
	StartMS int64
	Detail  string // evidence: what was read, from where, and how old it is
}

const (
	orphanKindVMM   = "vmm"
	orphanKindTAP   = "tap"
	orphanKindTable = "table"
)

// procInfo is the slice of /proc/<pid> the scan needs. It is a struct rather
// than a tangle of os.ReadFile calls so the decision logic below can be tested
// against a synthetic process table instead of a real one.
type procInfo struct {
	PID     int
	PPID    int
	Comm    string
	State   byte // /proc/<pid>/stat field 3: R,S,D,Z,… — Z is a zombie
	StartMS int64
	Cmdline string
}

// jailRootRe matches the chroot the jailer builds for a VMM:
// <cache>/run/firecracker/<id>/root. The id is hex because newID mints hex;
// the length floor keeps a directory called `run` from matching by accident.
var jailRootRe = regexp.MustCompile(`^(.+)/run/firecracker/([0-9a-f]{8,})/root$`)

// vmmSocketRe matches a socket path under a run directory — the unjailed
// VMM's --api-sock, which sandbox.go puts under the run dir this product
// made. Anchored to the token it is matched against.
var vmmSocketRe = regexp.MustCompile(`^(.+)/run/firecracker/([0-9a-f]{8,})/`)

// jailerSudoRe matches the `sudo -n jailer --id <id> … --chroot-base-dir <run
// root>` wrapper that stays alive for exactly as long as the jailed VMM it
// started. It has to be the identity anchor, and the reason is worth writing
// down: the jailer execs into Firecracker, whose argv is then chroot-relative
// (`/firecracker --api-sock /fc.sock`) and whose /proc/<pid>/root readlink
// resolves to `/` from outside the jail — neither carries the id or the cache
// any more. The wrapper's argv is the only place both survive.
var jailerSudoRe = regexp.MustCompile(`jailer .*--id ([0-9a-f]{8,}) .*--chroot-base-dir (\S+)`)

// jailerWrap is one identified jailer wrapper: the sandbox id and the run root
// its VMM was jailed under. Cache is the run root's parent — the KELYFOS_CACHE
// the jail directory belongs to.
type jailerWrap struct {
	id    string
	cache string
	pid   int
}

// jailerWrapFrom extracts the identity a jailer wrapper carries, when this
// process is one. The cache is the run root the jailer was handed minus the
// /run the run root adds.
func jailerWrapFrom(p procInfo) (jailerWrap, bool) {
	if p.Comm != "sudo" {
		return jailerWrap{}, false
	}
	m := jailerSudoRe.FindStringSubmatch(p.Cmdline)
	if m == nil {
		return jailerWrap{}, false
	}
	return jailerWrap{id: m[1], cache: strings.TrimSuffix(m[2], "/run"), pid: p.PID}, true
}

// vmmIdentity extracts what proves a process is KelyfOS's: the sandbox id and
// the cache root it came from. wrap is the parent jailer wrapper when the
// process has one. ok=false means this process is somebody else's firecracker,
// and the scan's whole contract is to leave those alone.
func vmmIdentity(p procInfo, rootLink string, wrap *jailerWrap) (id, cache string, ok bool) {
	if p.Comm == "firecracker" || p.Comm == "jailer" {
		if wrap != nil {
			return wrap.id, wrap.cache, true
		}
		if m := jailRootRe.FindStringSubmatch(rootLink); m != nil {
			return m[2], m[1], true
		}
		// Token by token: on the whole argv a greedy capture would swallow
		// the flags before the path.
		for _, tok := range strings.Fields(p.Cmdline) {
			if m := vmmSocketRe.FindStringSubmatch(tok); m != nil {
				return m[2], m[1], true
			}
		}
	}
	return "", "", false
}

// orphanedVMM decides the second layer: no live kelyfos anywhere up the
// ancestor chain. A zombie in the chain does not claim the child — a zombie
// supervises nothing — so the walk continues through it. Depth is bounded
// because a cycle or a pathological tree must not hang doctor.
func orphanedVMM(p procInfo, procs map[int]procInfo) bool {
	pid := p.PPID
	for depth := 0; pid > 1 && depth < 16; depth++ {
		parent, ok := procs[pid]
		if !ok {
			return true // the chain names a process that is already gone
		}
		if parent.Comm == "kelyfos" && parent.State != 'Z' {
			return false
		}
		pid = parent.PPID
	}
	return true
}

// claimedByLiveKelyfos reports whether id appears in the run directory of any
// live kelyfos process's own cache — the mid-boot guard for network residue
// whose VMM has not started yet. Environ is readable only for this user's own
// processes, which is exactly the set whose claims we can check.
func claimedByLiveKelyfos(id string, procs map[int]procInfo, self int, envOf func(int) ([]byte, error)) bool {
	for pid, p := range procs {
		if pid == self || p.Comm != "kelyfos" || p.State == 'Z' {
			continue
		}
		blob, err := envOf(pid)
		if err != nil {
			continue
		}
		for _, kv := range strings.Split(string(blob), "\x00") {
			if cache, found := strings.CutPrefix(kv, "KELYFOS_CACHE="); found {
				if _, err := os.Stat(filepath.Join(cache, "run", "firecracker", id)); err == nil {
					return true
				}
			}
		}
	}
	return false
}

// Indirections over the live machine, swapped out in tests. Everything they
// wrap is a read: the scan never mutates the machine.
var (
	readProcs  = readProcsFromProc
	readRoot   = func(pid int) (string, error) { return os.Readlink(fmt.Sprintf("/proc/%d/root", pid)) }
	readEnv    = func(pid int) ([]byte, error) { return os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)) }
	listTAPs   = listTAPsFromIP
	listTables = listTablesFromNFT
)

func readProcsFromProc() (map[int]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	btime := bootTimeMS()
	procs := make(map[int]procInfo, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := readProc(pid, btime)
		if err != nil {
			continue // a process that exited between readdir and read is normal
		}
		procs[pid] = p
	}
	return procs, nil
}

func readProc(pid int, btimeMS int64) (procInfo, error) {
	blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procInfo{}, err
	}
	// comm is in parentheses and may contain spaces and digits; everything
	// after the closing one is fixed-position, so split there rather than on
	// spaces and index from the front.
	s := string(blob)
	close := strings.LastIndexByte(s, ')')
	if close < 0 {
		return procInfo{}, fmt.Errorf("no comm terminator in stat for %d", pid)
	}
	rest := strings.Fields(s[close+2:])
	if len(rest) < 20 {
		return procInfo{}, fmt.Errorf("short stat for %d", pid)
	}
	ppid, _ := strconv.Atoi(rest[1])
	startTicks, _ := strconv.ParseUint(rest[19], 10, 64)
	p := procInfo{
		PID:     pid,
		PPID:    ppid,
		Comm:    s[strings.IndexByte(s, '(')+1 : close],
		State:   rest[0][0],
		StartMS: btimeMS + int64(startTicks)*1000/clkTCK,
	}
	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		p.Cmdline = strings.ReplaceAll(string(cmdline), "\x00", " ")
	}
	return p, nil
}

func bootTimeMS() int64 {
	blob, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(blob), "\n") {
		if v, found := strings.CutPrefix(line, "btime "); found {
			if s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return s * 1000
			}
		}
	}
	return 0
}

// clkTCK is the USER_HZ the kernel exports /proc through: /proc/stat's btime
// is seconds, the stat fields are in USER_HZ ticks, and Linux fixes USER_HZ
// at 100 for every architecture and every config — it is the userspace
// contract, not the kernel's internal HZ. Read once per scan would be
// ceremony around a constant the kernel does not let move.
const clkTCK = 100

func scanOrphans(self int) ([]orphan, error) {
	procs, err := readProcs()
	if err != nil {
		return nil, err
	}

	// The jailer wrappers first (see jailerSudoRe for why they are the
	// identity anchor): pid → the sandbox id and cache their VMM answers to.
	wraps := map[int]jailerWrap{}
	for pid, p := range procs {
		if pid == self {
			continue
		}
		if w, ok := jailerWrapFrom(p); ok {
			wraps[pid] = w
		}
	}

	// Live claims first: a VMM id that any live VMM already carries, or that
	// any live kelyfos process is in the middle of booting, is not residue.
	liveVMM := map[string]bool{}
	orphans := []orphan{}
	for pid, p := range procs {
		if pid == self {
			continue
		}
		var wrap *jailerWrap
		if w, ok := wraps[p.PPID]; ok {
			wrap = &w
		}
		root, _ := readRoot(pid)
		id, cache, ours := vmmIdentity(p, root, wrap)
		if !ours {
			continue
		}
		if orphanedVMM(p, procs) {
			orphans = append(orphans, orphan{
				Kind: orphanKindVMM, ID: id, PID: pid, Cache: cache, StartMS: p.StartMS,
				Detail: fmt.Sprintf("pid %d %s, parent chain reaches no live kelyfos, up %.0f s: %.160s",
					pid, p.Comm, time.Since(time.UnixMilli(p.StartMS)).Seconds(), p.Cmdline),
			})
		}
		// Claimed either way: an orphaned VMM is still a running machine, and
		// its TAP and table belong to it — they go when it does, below.
		liveVMM[id] = true
	}

	claim := func(id string) bool {
		return liveVMM[id] || claimedByLiveKelyfos(id, procs, self, readEnv)
	}

	for _, tap := range listTAPs() {
		id, ok := strings.CutPrefix(tap, "kelyfos")
		if !ok || len(id) < 8 {
			continue // an interface we did not name is not ours to judge
		}
		if claim(id) {
			continue
		}
		orphans = append(orphans, orphan{
			Kind: orphanKindTAP, ID: id,
			Detail: fmt.Sprintf("TAP %s names sandbox %s and no live machine claims it", tap, id),
		})
	}
	for _, tbl := range listTables() {
		id, ok := strings.CutPrefix(tbl, "kelyfos_")
		if !ok || len(id) < 8 {
			continue // IA-I4's residue and every table like it: named, judged, left
		}
		if claim(id) {
			continue
		}
		orphans = append(orphans, orphan{
			Kind: orphanKindTable, ID: id,
			Detail: fmt.Sprintf("table inet %s names sandbox %s and no live machine claims it", tbl, id),
		})
	}

	sort.Slice(orphans, func(i, j int) bool {
		if orphans[i].Kind != orphans[j].Kind {
			return orphans[i].Kind < orphans[j].Kind
		}
		return orphans[i].ID < orphans[j].ID
	})
	return orphans, nil
}

func listTAPsFromIP() []string {
	out, err := exec.Command("ip", "-j", "-o", "link", "show").Output()
	if err != nil {
		return nil
	}
	var links []struct {
		IFName string `json:"ifname"`
	}
	if json.Unmarshal(out, &links) != nil {
		return nil
	}
	names := make([]string, 0, len(links))
	for _, l := range links {
		names = append(names, l.IFName)
	}
	return names
}

func listTablesFromNFT() []string {
	out, err := exec.Command("sudo", "-n", "nft", "-j", "list", "tables").Output()
	if err != nil {
		return nil
	}
	// nft wraps every listing in a top-level nftables array — the same shape
	// network.go's counter reader decodes — with a metainfo object first.
	var doc struct {
		Nftables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Nftables))
	for _, item := range doc.Nftables {
		if item.Table != nil && item.Table.Family == "inet" {
			names = append(names, item.Table.Name)
		}
	}
	return names
}

// reapOrphans acts on exactly what scanOrphans proved, and reports every
// action it took — a reaper that stayed quiet would be indistinguishable from
// one that did nothing, which is the failure mode D83's review found in the
// teardown that inspired this scan's scoping rules.
func reapOrphans(orphans []orphan) []string {
	var actions []string
	byID := groupOrphans(orphans)
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		group := byID[id]
		for _, o := range group {
			if o.Kind != orphanKindVMM || o.PID <= 0 {
				continue
			}
			// Identity corroboration before any destructive step: the scan's
			// evidence (comm, argv, chroot path) is text a local process can
			// forge, and the reaper acts with root. The one piece of evidence
			// the guest cannot forge is the sandbox state file the HOST wrote
			// beside the image — it names the pid the host itself recorded.
			// A finding whose pid the state file does not corroborate stays
			// report-only: listed, never signalled, never deleted (second
			// review, finding 2).
			if !stateFileCorroborates(o) {
				actions = append(actions, fmt.Sprintf(
					"sandbox %s: pid %d is listed but UNCORROBORATED by the state file — report only, nothing signalled or deleted", id, o.PID))
				continue
			}
			// Re-validate the pid against the start time the scan recorded:
			// a scan is a snapshot, and a pid that exited and was recycled in
			// the seconds since belongs to a process this reaper has no
			// evidence about — and no right to signal (review, finding 6).
			if o.StartMS > 0 {
				now, err := procStartMS(o.PID)
				if err != nil || now != o.StartMS {
					actions = append(actions, fmt.Sprintf("sandbox %s: pid %d is no longer the process the scan saw — skipping", id, o.PID))
					continue
				}
			}
			if stopProcess(o.PID) {
				actions = append(actions, fmt.Sprintf("stopped orphaned VMM pid %d (sandbox %s)", o.PID, id))
			} else {
				actions = append(actions, fmt.Sprintf("VMM pid %d (sandbox %s) was already gone", o.PID, id))
			}
		}
		if msg := sandbox.RemoveNetworkResidue(id); msg != "" {
			actions = append(actions, fmt.Sprintf("sandbox %s: %s", id, msg))
		}
		// One jail directory per cache the evidence named — usually one, but
		// the same id in two worktrees is exactly the collision the id exists
		// to prevent, so every named location is cleaned, not the first.
		seen := map[string]bool{}
		for _, o := range group {
			if o.Cache == "" || seen[o.Cache] {
				continue
			}
			seen[o.Cache] = true
			actions = append(actions, removeJailDir(id, o.Cache)...)
		}
	}
	return actions
}

// groupOrphans buckets findings by sandbox id for the reaper, deduplicating on
// a finding's own identity (kind, id, pid) as it goes: a scan that somehow saw
// the same VMM twice must not stop it twice and report both — a reaper's
// report is evidence, and evidence says each thing once.
func groupOrphans(orphans []orphan) map[string][]orphan {
	byID := map[string][]orphan{}
	seen := map[string]bool{}
	for _, o := range orphans {
		key := fmt.Sprintf("%s/%s/%d", o.Kind, o.ID, o.PID)
		if seen[key] {
			continue
		}
		seen[key] = true
		byID[o.ID] = append(byID[o.ID], o)
	}
	return byID
}

// procStartMS re-reads a process's start time for reap-time revalidation.
func procStartMS(pid int) (int64, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	rest := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+2:])
	if len(rest) < 20 {
		return 0, fmt.Errorf("short stat for %d", pid)
	}
	ticks, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return 0, err
	}
	return bootTimeMS() + int64(ticks)*1000/clkTCK, nil
}

// stateFileCorroborates checks the host-written sandbox state file against
// the finding: the state file's own "pid" must name the process the scan
// saw. Read from both shapes scope.sh knows — beside the jail directory and
// inside its root — because the jail layout is the jailer's, not ours.
func stateFileCorroborates(o orphan) bool {
	if o.Cache == "" {
		return false
	}
	for _, candidate := range []string{
		filepath.Join(o.Cache, "run", "firecracker", o.ID, "sandbox.json"),
		filepath.Join(o.Cache, "run", "firecracker", o.ID, "root", "sandbox.json"),
	} {
		blob, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		for _, kv := range strings.Split(string(blob), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(kv), "\"pid\":"); ok {
				pid := strings.Trim(strings.TrimSpace(v), `", `)
				if pid != "" && pid != "0" && pid == strconv.Itoa(o.PID) {
					return true
				}
			}
		}
	}
	return false
}

// stopProcess TERM, wait, then KILL — the same escalation teardown itself
// uses. The booleans are evidence, not decoration.
func stopProcess(pid int) bool {
	if !processAlive(pid) {
		return false
	}
	_ = exec.Command("kill", "-TERM", strconv.Itoa(pid)).Run()
	for i := 0; i < 30; i++ {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = exec.Command("kill", "-KILL", strconv.Itoa(pid)).Run()
	for i := 0; i < 20; i++ {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !processAlive(pid)
}

func processAlive(pid int) bool {
	blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(blob)
	return !strings.HasPrefix(s[strings.LastIndexByte(s, ')')+2:], "Z")
}

// removeJailDir deletes one sandbox's jail directory under one known cache.
// The jailer leaves root-owned files in it, so the plain removal falls back to
// sudo exactly as removeJail in internal/sandbox does; the comment there says
// why ("a plain RemoveAll fails half way and leaves the rest, which over a few
// hundred runs is a disk full of abandoned chroots").
func removeJailDir(id, cache string) []string {
	dir := filepath.Join(cache, "run", "firecracker", id)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	if err := os.RemoveAll(dir); err == nil {
		return []string{fmt.Sprintf("removed jail dir %s", dir)}
	}
	if err := exec.Command("sudo", "-n", "rm", "-rf", dir).Run(); err == nil {
		return []string{fmt.Sprintf("removed jail dir %s (via sudo: the jailer leaves root-owned files)", dir)}
	}
	return []string{fmt.Sprintf("could not remove jail dir %s — remove it by hand", dir)}
}
