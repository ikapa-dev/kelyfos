# The MCP surface

**Status:** normative for `v0.7`. Written at E4-0 before any of it exists; E4-1
through E4-8 implement it. Where this document and the code disagree during the
epic, the code is wrong.

KelyfOS already speaks MCP in one place: `kelyfos mcp` bridges a client's
standard streams to one guest's supervisor, and the agent inside gets six tools
plus the team tools. That is the *inside* of a sandbox.

This document is about the two directions around it.

**Outward.** `kelyfos serve-mcp` makes the whole of KelyfOS a tool for any MCP
client. One line of configuration and a client's agent gains
`sandbox_run`, `sandbox_exec`, snapshots and team control — so the risky command
it was about to run on the developer's machine runs inside a microVM instead.

**Inward.** `[[plugin]]` entries in `kelyfos.toml` declare extra MCP servers the
agent gets *inside* the guest — a browser-control server, a database client,
whatever the job needs — namespaced, policy-bound, and audited per call.

The two are not layers of each other. Outward, KelyfOS is the server. Inward, it
is the client. What they share is the wall: neither direction may widen policy,
and both write the same flight recorder.

---

## 1. The invariant

> **`serve-mcp` can never widen the policy it was given. The project's
> `kelyfos.toml` is the ceiling, and no tool exists to change it.**

Read that with its condition, because the condition is load-bearing: a server
that was never given a policy has no ceiling to enforce. Naming the file with
`--policy` is what makes the invariant absolute, and §2.3 says why a client
cannot be trusted to supply the working directory that would find it. Every
statement of the invariant in this document means *the policy this server is
holding* — which the `initialize` instructions name, so an agent can see it too.

This is F-D5, and everything in section 2 is arranged around it. It has three
consequences worth stating separately, because each rules out a design somebody
would otherwise reach for.

**There is no `set_policy`, no `allow_domain`, no `raise_limit`.** Not refused
at runtime — *absent*. A tool that exists and always fails teaches a model to
ignore failures (F-D18); a tool that does not exist teaches it nothing, which is
correct, because policy is not a thing an agent negotiates. Policy changes are
human, they happen in a file that lives in a repository, and they show up in a
diff.

**A tool argument may ask for less, never more.** `sandbox_run` accepts `cpus`
and `mem` for the same reason `kelyfos run` accepts `--cpus` and `--mem`: an
agent that needs a smaller machine should be able to ask for one. The
relationship to `[resources]` is identical to a flag's — a request above the
ceiling is refused at the call, naming the ceiling and the file and line it came
from, in the E1-1 style (`docs/resources.md`).

**The client is not trusted to say who it is.** `serve-mcp` reads the policy
from the filesystem, once, at startup. Nothing in a tool call selects a
different policy file, and no argument names one. A client that could point the
server at another `kelyfos.toml` would have found the `set_policy` tool by
another route.

---

## 2. Outward: `kelyfos serve-mcp`

```sh
kelyfos serve-mcp
```

Speaks MCP over stdio on its own standard streams. It is a long-lived process
that owns sandboxes: they are created by tool calls, live across calls, and are
destroyed by a tool call or by the server exiting.

### 2.1 How it differs from `kelyfos mcp`

They are easy to confuse and are opposites.

| | `kelyfos mcp` | `kelyfos serve-mcp` |
| --- | --- | --- |
| Fronts | one guest's supervisor | the whole host CLI |
| Tools the client sees | what the *guest* offers: `exec`, `read_file`, … | what the *host* offers: `sandbox_run`, `sandbox_exec`, … |
| Sandboxes | attaches to one that already exists | creates and destroys them |
| Role | a byte pass-through | a real MCP server |

An agent typically wants `serve-mcp`: it can boot a sandbox, work in it, and
stop it, all from inside its own session. `kelyfos mcp` is for the case where
something else already owns the sandbox's lifetime.

### 2.2 The tools

Every name is lowercase ASCII with underscores and stays well inside 64
characters, for the reason in §3.2.

#### Lifecycle

**`sandbox_run`** — boot a sandbox under the project's policy.

| Parameter | Type | Required | Meaning |
| --- | --- | --- | --- |
| `image` | string | no | Image flavor. Defaults to the policy's, and must be one the policy permits. |
| `cpus` | integer | no | Cores. A request above `[resources] cpus` is refused. |
| `mem` | string | no | Guest RAM, e.g. `"512M"`. A request above `[resources] mem` is refused. |
| `allow` | string array | no | Egress allowlist. **Must be a subset of the policy's.** An entry the policy does not contain is refused. |

Returns the new sandbox's id, and `structuredContent` carrying
`{sandbox, image, arch, boot_ms, allow}`. The key is `sandbox`, not `id`, and it
is what every other tool takes as its `sandbox` argument.

There is no `workspace` parameter, and **a sandbox created here does not get the
project's `[sandbox] workspace` device**. `/work` inside it is an ordinary
directory in the guest's own overlay, which vanishes with the machine. That is a
deliberate absence: one server may hold several sandboxes, and several
write-backs into one host directory is the most destructive thing this product
could do quietly.

**It is said rather than done in silence.** A project that declares a
`workspace` gets a line on stderr at startup explaining that this server does
not attach it and what to use instead, and the `initialize` instructions tell
the *agent* the same thing — because the agent is the one that would otherwise
write into `/work` expecting the file to reach the host. Use
`sandbox_write_file` and `sandbox_read_file` to move files, or
`kelyfos run --workspace` for a single machine that syncs back.

`allow` is the one parameter where "ask for less" needs saying out loud: the
policy's allowlist is the set of domains this project may reach, and a call may
narrow it for one sandbox. It may never add to it. A call naming a domain the
policy does not list is refused and audited, and the refusal names the domain.

**`sandbox_stop`** — stop one sandbox and clean up.
`{sandbox: string}` → confirmation. Stopping a sandbox this server did not
create is an error: `serve-mcp` owns what it made and does not adopt a machine
somebody's `kelyfos run` is using.

**`sandbox_list`** — the sandboxes this server created.
No parameters → `structuredContent: {sandboxes: [{sandbox, image, allow, created}], max}`.

#### Work

**`sandbox_exec`** — run a command inside one.

| Parameter | Type | Required | Meaning |
| --- | --- | --- | --- |
| `sandbox` | string | **yes** | Which one. |
| `command` | string | no | Shell command line, run through `/bin/sh -c`. |
| `argv` | string array | no | Argument vector, executed with no shell. |
| `cwd` | string | no | Working directory in the guest. |
| `stdin` | string | no | Text on the command's standard input. |
| `timeout_ms` | integer | no | Kill it after this long. |

One of `command` or `argv` is required. The result mirrors the guest's own
`exec` tool exactly — text output, then `[exit status N]`, `isError` when the
status is non-zero, and `structuredContent: {exit_code, stdout, stderr, signal}`
— because an agent that has used one should not have to learn the other.

**`sandbox_read_file`** — `{sandbox, path}` → the contents.
`structuredContent: {path, bytes, content, encoding}`.
**`sandbox_write_file`** — `{sandbox, path, content}` → bytes written.
`structuredContent: {path, bytes, sha256}`.

**The payload is in `structuredContent`, not only in the text block.** A client
is entitled to prefer one or the other, and a tool whose whole result lived in
the text returns *nothing* to a client that reads only the structured form —
which is how `sandbox_read_file` was found to be unusable from a real signed-in
client at the E4 exit, after passing every test and every recipe. The rule now
holds for every tool here and is checked by a test and by the acceptance run:
whatever a caller asked for must be reachable from `structuredContent` alone.

`encoding` is `utf-8` or `base64`. A file that is not valid UTF-8 comes back
base64 rather than being put in a JSON string, where Go replaces every invalid
sequence with U+FFFD and the caller receives a quietly corrupted file; the text
block then says what happened instead of carrying the damaged copy. `download`
is still the tool built for binary.

Both are the supervisor's own RPCs with a sandbox id in front, and that is
meant literally: the host opens the guest's own MCP channel and calls the tool,
rather than reimplementing it and growing a second idea of what the limit is.
The 8 MiB per-call cap the guest tools have therefore applies here too, for the
same reason and in the same words — and the frame limit on the channel is set
from it, so the cap is what refuses a large file rather than the transport
(§4). Measured end to end at 512 KiB, 2 MiB, 4 MiB and 8 MiB; 9 MiB is refused
by the guest, naming the limit in bytes.

A write is recorded in the sandbox's flight recorder by path, size and digest,
with `via: serve-mcp` — never by content. A read is not recorded, for the same
reason a read is not recorded anywhere else: the record is of what changed.

#### State

**`sandbox_snapshot`** — `{sandbox, name}` → freeze it. The sandbox keeps
running. `structuredContent: {name, sandbox, took_ms, state_bytes, memory_bytes}`.
**`sandbox_restore`** — `{name, allow?}` → bring one back as a new sandbox.
`structuredContent: {sandbox, snapshot, image, restore_ms, allow}`.
**`sandbox_fork`** — `{name, count}` → N independent copies of one snapshot.
`structuredContent: {sandboxes, snapshot, wall_ms, failed}`, where `sandboxes` is
a list of ids — not the objects `sandbox_list` returns under the same key.

**Every one of these counts against `max_sandboxes`**, because every one of them
makes a machine. A fork asking for more room than is left is refused before any
of it starts, naming what is running and what was asked for: finding out at fork
three of five is finding out too late.

`sandbox_fork` inherits P3-2's rule unchanged: a snapshot taken from a networked
sandbox cannot be forked, because the guest's address lives inside the memory
image every fork shares. The refusal says so rather than producing N machines
that each believe they are the same host.

Four more refusals belong to this door rather than to the machinery under it,
because they are all consequences of the caller being a model on the far side of
the wall rather than a person at a shell:

- **A snapshot name is checked, not trusted.** A name becomes a directory, so it
  is letters, digits, dot, dash and underscore, at most 64 of them, not starting
  with a dot. `../evil` is refused for the slash it contains.
- **A restored machine is held to the policy's ceiling.** Firecracker takes vcpu
  and memory from the state file, so a restore cannot shrink a machine to fit:
  the only honest answers are to allow it or refuse it. Snapshots record what
  they hold; one taken by an older `kelyfos` does not, and where a ceiling is set
  that unknown is refused rather than waved through.
- **A restore may narrow an allowlist and never widen one**, against two
  ceilings: the project's policy, and the snapshot's own list. A snapshot taken
  under some other policy does not carry its permission with it.
- **A networked snapshot cannot be restored while its original is running.** The
  guest's address and proxy port are inside the memory image (D22), so exactly
  one machine can hold them; the refusal names the sandbox that has it.

Restoring is what makes the rest of it worth having: measured on the development
machine, a restore is **~150 ms** against **~800 ms** for a cold boot, and two
forks of one snapshot come up in **~230 ms** of wall clock between them. Those
are nested-virtualisation figures and informational only — the bars that bind
are measured on the bare-KVM reference (D15).

#### Teams

**`team_up`** — raise the team the project's `kelyfos.toml` declares.
No parameters: the topology is the file's, not the caller's. There is no
argument that adds an agent or an edge, for the reason in §1.
**`team_ps`** — the roster, as structured data. This is deliberately the
machine-readable form `kelyfos team ps` does not have, and it is where an
orchestrator gets the mapping it needs:
`{team, session, owner, started_at, edges, budget, agents: [{agent, sandbox, via,
alive, sampled, cpu_seconds, cpu_quota_percent, vcpus, rss_kib, mem_mib,
disk_write_bytes, allow, reaches}]}`.
`alive` is whether the machine is still there, and `sampled` is whether its usage
could be read at all — a genuinely idle agent and one whose sample failed are two
different facts and would otherwise both be zeroes.
**`team_down`** — retire it.

An external agent can raise and retire a whole declared team and cannot change
its shape. That is the same bargain the guest's `team_spawn` makes: capacity is
grantable, topology is not. `team_up` and `team_down` take **no parameters at
all**, and that is the feature rather than an omission.

Three consequences worth saying out loud:

- **One team at a time**, because a machine runs one: the state file that says
  what is up has one name in it. A second `team_up` is refused, naming the team
  already running.
- **A team belongs to whoever raised it.** `team.json` records which door it came
  through. A team raised here is retired here; `kelyfos team down` in a shell
  refuses to signal the server, because that process is also holding every
  sandbox it created and stopping it would take all of that down too. The
  refusal says so and names the alternative. The reverse holds as well: this
  server will not retire a team somebody else's `kelyfos team up` is holding.
- **The sandbox tools do not reach into a team.** An id from `team_ps` handed to
  `sandbox_exec` is refused, and the refusal says which agent of which team it
  is rather than insisting the machine does not exist. What runs inside a team is
  the team's own business, bounded by the same file — raising it is the
  capability on offer here.

`team_down` reports what teardown did rather than asserting it: each agent's
workspace write-back names the directory it landed in.

Measured on the development machine: a five-agent team raised through `team_up`
in **~1.3 s**, four of the five forked from a cached template, and retired in
**~280 ms** with the master's workspace written back. Nested-virtualisation
figures, informational only (D15).

### 2.3 Sessions, concurrency and `max_sandboxes`

```toml
[mcp]
max_sandboxes = 4
```

**Which policy file is a decision, not a default.** The server searches upward
from its working directory for `kelyfos.toml`, which is right on a command line
and a trap under a client: the working directory belongs to the client, and one
launched from outside the project finds no policy and runs with no ceiling at
all. `--policy <path>` names the file, and a `--policy` that does not exist is
an error rather than a quiet fall back to the search. The `initialize`
instructions name the policy in force, or say plainly that none was found —
because the banner naming it goes to stderr, and clients bury stderr.


`max_sandboxes` bounds how many sandboxes one `serve-mcp` process may have
running at once. The default is **4**, and it is small on purpose: each one is a
real microVM with real RAM, four of them at the default 512 MiB is 2 GiB, and an
agent that wants a fleet should be made to say so in a file a human reads. A
`sandbox_run` that would exceed it is refused and audited, naming the limit.

The limit is on machines, not on calls. MCP assumes a client may have several
requests in flight — JSON-RPC requires only that their ids differ — and nothing
in the specification orders them. `serve-mcp` therefore has to be safe under
concurrent `tools/call`, and every tool takes the sandbox it acts on as an
explicit argument rather than relying on a "current" one. There is no implicit
session state between calls, which is what makes concurrency safe rather than
merely permitted.

When the server exits, every sandbox it created is stopped. A client that
disconnects without calling `sandbox_stop` does not leave microVMs behind.

### 2.4 Errors

The distinction the MCP specification draws is the one to follow, and it is not
a matter of taste — it decides whether a model can recover.

**A tool that ran and failed** returns a normal result with `isError` set: a
command that exited non-zero, a file that does not exist, a policy refusal. The
model sees it and adapts.

**A request that could not be attempted** is a JSON-RPC error: an unknown tool,
a malformed call, a missing required argument.

A policy refusal is deliberately the first kind. "You asked for four cores and
this project allows two" is something an agent can act on by asking for two.

### 2.5 The audit lane

Every client tool call is a flight-recorder event, `mcp.host.*`. The outer
agent's use of the sandbox is itself recorded, beside — not merged into — the
record of what happened inside the guest. There are two chains and no export
that holds both; §4.1 has the reasoning and the cross-link between them.

This is the point of the outward direction rather than a feature of it. Without
it, "an agent did some work in a sandbox" would be recorded and "an agent
decided to create a sandbox with these limits" would not, and the second is the
part a reader most wants when something has gone wrong.

Two event types carry it, and they mirror `command.start` / `command.exit`
because they are the same shape of fact:

| Event | What it says |
| --- | --- |
| `mcp.host.call` | a client asked for a tool: which one, with what arguments, and the sandbox it names if it names one |
| `mcp.host.result` | what came back: `ok` or `error`, how long it took, and the refusal in the case of an error |

`docs/reference/events.md` carries their fields, generated from the same table
the code uses.

**They live in the server's own session**, not in each sandbox's. The calls that
matter most belong to no sandbox at the moment they are made: the one that
chose a machine's limits, before the machine exists, and every call that was
refused, which never gets one. `serve-mcp` prints its session id to stderr at
startup, and each sandbox's `session.start` carries it **in its `reason`
field** — `created through serve-mcp session 9504d5a2` — as does a team raised
here. Since clients bury stderr, the reliable route from the other end is
`kelyfos log --list`, which marks a server's session `serve-mcp, N sandbox(es)`
the way it marks a team's.

`kelyfos log --session <server-id> --export` renders that session with **one
lane per sandbox**, exactly as a team's transcript renders one lane per agent —
the same machinery, because it is the same question: which machine did this
belong to. A call naming no sandbox spans every lane. A refused call is drawn
like a refused message, because it is the same thing: the wall saying no, where
a reader can see it.

**The record never holds content.** A call's arguments are summarised into one
line, keys sorted, with anything carrying content — `content`, `stdin` —
replaced by its size:

```
client call    sandbox_write_file content=<19 bytes> path=/work/brief.txt sandbox=85e04ad9
client result  sandbox_run refused: cpus 64 exceeds the ceiling cpus = 2 set at kelyfos.toml:5 (0 ms)
```

That is the rule `file.write` already follows. The summariser walks whatever it is
given rather than knowing the tools, so an argument added later shows up in the
log without anyone remembering to add it, and one carrying content is withheld
even on a tool that does not exist yet.

The rest of the rule is the one every other event follows: the host writes them,
the client does not, and a refused call is recorded exactly like a permitted
one — a ceiling nobody can see being enforced is a ceiling nobody can audit.

---

## 3. Inward: plugins

```toml
[[plugin]]
name    = "browser"
path    = "./plugins/browser"
command = "node"
args    = ["server.js"]
```

Each entry is an MCP server that runs **inside the guest**, launched by the
supervisor, speaking MCP stdio to it. Its tools are aggregated into the agent's
session alongside the built-in ones.

**Where it runs, and how `command` is resolved.** The plugin's working
directory is `/plugins/<name>`, and that directory is read-only: the device is
mounted `ro`, so a plugin cannot write beside its own files. It may write
anywhere the sandbox can — `/tmp` and the rest of the overlay, bounded by
`[resources] scratch`.

`command` is resolved the way a shell resolves one. A bare name — `python3`,
`node` — is looked up on `PATH`; a name containing a slash — `./server`,
`bin/serve` — is resolved against the plugin's own directory. Both examples in
this document are the first kind. `args` are passed through untouched.

It gets **exactly the environment every other command in the sandbox gets** —
the same `PATH`, and the same egress proxy variables when the sandbox has
egress. Not a second environment, and not the supervisor's own: one environment,
decided in one place.

The handshake happens **before the sandbox reports ready**, and the tool list is
read once there rather than on every call. That costs something and the cost is
the plugin's: on the development machine a sandbox with no plugins is ready in
about **800 ms**, and one with the Python demo plugin in about **1.4 s** —
almost all of it a CPython interpreter starting. A compiled plugin costs far
less. Doing it in the background would be cheaper and wrong: *ready* means the
machine is usable, and a machine whose `tools/list` is still filling in is one
an agent cannot tell apart from a machine that never had those tools. (Nested
virtualisation figures, informational only — D15.)

### 3.1 Why this is safe

A plugin has exactly the powers of a malicious agent, and the sandbox already
assumes the agent is malicious (F-D5). It runs inside the same microVM, under
the same read-only root, behind the same absent network. There is nothing a
plugin can reach that agent-written code could not have reached anyway.

Two things follow, and both are enforced rather than assumed:

**A plugin gets no egress of its own.** The per-agent allowlist is the single
network policy surface. There is no `[[plugin]] allow`, and asking for one is
asking for a second door in a wall whose whole value is having one.

That is not the same as "a plugin cannot reach the network". In a project whose
policy grants egress, a plugin inherits the proxy variables like everything else
in the sandbox and can reach exactly the allowlist — no more, and through the
same audited proxy. [`networking.md`](networking.md) describes what that means
in practice: the four proxy variables, `NO_PROXY`, and the trust anchor. Where
the sandbox has no egress, a plugin has none either, and a connection attempt
fails the way it would for any other process in there.

**A plugin cannot grant itself anything.** It is launched by the supervisor with
the environment the supervisor decides, from files on a read-only device.

### 3.2 Namespacing: `<plugin>_<tool>`, and why not a dot

A plugin's tools are advertised to the agent as `<plugin>_<tool>` —
`browser_navigate`, `browser_screenshot`.

**E4-0's own text says `<plugin>.<tool>`, and F-D5 wrote it that way. The dot is
not taken.** The reason is verified rather than aesthetic, and it is worth
recording because a dot is the obvious choice and is *legal*:

- The MCP specification explicitly permits a dot. Its tool-name guidance (added
  in revision 2025-11-25) says names SHOULD use ASCII letters, digits,
  underscore, hyphen **and dot**, and its own example of a good name is
  `admin.tools.list`. Both official SDKs accept dots and only warn.
- Downstream of MCP, dots are rejected. The Anthropic Messages API constrains a
  tool name to `^[a-zA-Z0-9_-]{1,64}$`, which excludes the dot outright. Claude
  Code — the first client this project cares about — rewrites every character
  outside `A-Za-z0-9_-` to an underscore before the name reaches a model.
- That rewriting is worse than a rejection, because it is silent and it
  **collides**: `a.b` and `a_b` become the same name. A dotted scheme is
  therefore not merely mangled, it can be ambiguous after mangling.

So the separator is `_`, which is what every KelyfOS tool already uses, and the
collision the separator itself could cause is closed by constraining the name
rather than hoping:

> A plugin's `name` matches `^[a-z][a-z0-9-]*$` — lowercase, starting with a
> letter, no underscore, no dot, and **at most 24 characters**. `<plugin>_<tool>`
> is then unambiguous, because the plugin half cannot contain the separator.

The 24 is not arbitrary: the *whole* of `<plugin>_<tool>` must fit in **64
characters**, the strictest downstream limit, and a prefix that used most of it
would make perfectly reasonable tool names unadvertisable.

**The tool half is checked too**, against `^[a-zA-Z0-9_-]{1,64}$` — the
Messages API's own constraint, applied to the finished name. A plugin's tool
whose namespaced name would not survive it is dropped at boot with a line on the
console saying so, rather than advertised and rejected later by somebody else's
API. Uppercase is allowed there and not in the plugin name, because the plugin
name has one more job to do: being unambiguous as a prefix.

A `[[plugin]]` whose name is already taken by another is refused when the file
is read, naming both lines. And a plugin *tool* whose namespaced name collides
with a built-in — a plugin called `read` exporting `file` — is dropped at boot
with a line saying why, because two entries with one name in `tools/list` is
worse than one missing tool: dispatch reaches the built-in and the plugin's is
unreachable. The team tools count as built-ins even in a sandbox that is not in
a team, so the same plugin does not work in one sandbox and come up short in
another.

**The prefix is the declared name, never the plugin's own.** A plugin announces
a `serverInfo.name` at initialize, and that name is not used for anything — the
in-repo demo plugin announces `not-the-name-that-counts` precisely so a test can
see that it is ignored. The
MCP specification says as much — a server's self-reported name is not guaranteed
unique and should not be relied on for disambiguation — and KelyfOS would refuse
it anyway, for the reason it refuses every other guest-asserted identity: the
host decides what a thing is called, and the thing being named does not get a
vote (F-D24).

### 3.3 The plugins drive

The host packs each declared plugin's `path` directory into a **read-only ext4
image**, attached as the next virtio-blk device and mounted at `/plugins`
(F-D6). The image is built by the same host-side `mkfs.ext4`-and-populate the
workspace uses; sizing follows P3-10's doubling with a much smaller floor,
because nothing in the guest writes here and a gigabyte of headroom on a device
nobody can write to would be a gigabyte of nothing.

`path` is resolved against the policy file, not against a working directory —
the same rule `workspace` follows, and it matters more here, because a client
launches `serve-mcp` from a directory nobody chose.

**Which device it is, is decided rather than assumed.** It is `/dev/vdc` behind
a workspace and `/dev/vdb` without one, so the host computes it from where the
drive actually landed and puts it on the kernel command line as
`kelyfos.plugins=`. That is the same channel the workspace device and the proxy
address travel on, for the same reason: the kernel command line is the one thing
inside the guest that the guest did not write.

**Read-only three times over**, because each layer answers a different question:
the drive is attached `is_read_only`, so Firecracker refuses a write; the mount
adds `ro,nosuid,nodev`, so the guest kernel refuses one too; and the image file
is `0400` on the host, so a mistake on this side of the wall cannot edit a
device a machine is running on. A `touch /plugins/anything` in the guest gets
`Read-only file system`.

**A snapshot carries the device.** Firecracker will not load a snapshot until
every block device's backing file is at the path recorded in it, so the plugins
image travels with the snapshot and is staged back if it is missing. Unlike the
workspace there is no per-fork copy: the device is read-only, so every fork of
one snapshot reads the same file and none of them can change it.

```
/plugins/
  plugins.json          the manifest, written by the host
  browser/              this plugin's files, as packed
  db/
```

ext4 rather than squashfs because both ride virtio-blk equally well and squashfs
would mean adding `CONFIG_SQUASHFS` to the P1-2 kernel fragments — a kernel
config change for marginal gain (F-D6).

**`plugins.json` is the host's account of what it packed**, and the supervisor
reads it rather than scanning the directory:

| Field | Meaning |
| --- | --- |
| `name` | The declared name, and the tool prefix. |
| `command`, `args` | What to launch, relative to that plugin's directory. |
| `sha256` | Digest of the packed directory: every path, its mode, and the bytes of every file. Deliberately not the workspace's fingerprint, which mixes in modification times — the same plugin packed twice would then have two digests, and telling two builds apart is the only question this field is here to answer. |

A plugin present on the device and absent from the manifest is not launched. The
manifest is the list; the device is storage. That is the same relationship
`image.json` has to an image directory, and it exists for the same reason D21
gives: the host should not assert a fact it has not checked.

A flavor may also ship a server built into the image. Both routes launch
identically — the manifest is what differs, and a built-in server appears in it
the same way.

### 3.4 What it costs, and what it is allowed

Every number here exists in the product and none of it was written down until
the E4 exit exam asked for it.

| | |
| --- | --- |
| Time to answer `initialize` | **20 s**, and it is paid before the sandbox reports ready |
| Time to answer one tool call | **120 s**, after which the caller gets an error naming the plugin |
| One message, either direction | **16 MiB**, the MCP channel's frame limit (`docs/protocol.md` §3) |
| A tool result's size | whatever the plugin returns, inside that frame — the guest tools' 8 MiB per-call cap is theirs, not yours |
| The plugins device | sized from the directory it packs, so a plugin's size is bounded by disk rather than by policy |

**Where a plugin's output goes.** Its standard error is the console, prefixed
with the plugin's name — `kelyfos run --console` is how you read it, and it is
where a traceback lands. Its standard input and output are the protocol and must
carry nothing else: a `print()` to stdout is a malformed frame.

**When it will not start at all** — a `command` that does not resolve, a file
that is not executable, a handshake that never answers — the failure is a
`plugin.crash` event whose reason begins `did not start:`, and a console line
saying the same. The sandbox boots anyway, without that plugin's tools. One
broken plugin does not cost the agent the other three.

### 3.5 When a plugin breaks

A plugin is a child process and processes die.

**Its tools fail; the sandbox does not.** A crashed plugin's tools return
`isError` results explaining that the plugin is gone. `exec` still works, the
other plugins still work, and the supervisor — which is PID 1 — is untouched.

**The crash is an event.** `plugin.crash` names the plugin and what it exited
with. A plugin that dies silently and takes its tools with it would otherwise
look identical to a plugin that never had those tools.

**Per-call audit events carry the plugin name**, so a transcript says which
plugin was asked for which tool, rather than only that a tool was called.
`plugin.call` records the plugin, the tool without its prefix, the outcome and
how long it took; `plugin.crash` records the plugin and what it exited with.

It records the arguments too, in the same redacted shape the outward
`mcp.host.call` uses: every key, with anything carrying content — `content`,
`stdin`, `data` — replaced by its size. The summariser walks whatever it is
given rather than knowing the tools, so an argument a plugin adds later appears
without anyone remembering, and one carrying content is withheld even on a tool
nobody here has seen. Both are
reported by the supervisor and written by the host, exactly as `resource.oom`
is and for the same reason: a guest that could write its own audit trail could
forge it.

**A crashed plugin's tools stay in the list.** Removing them would leave an
agent that had already read the list calling something that no longer exists and
being told "unknown tool" — which is what a typo looks like, not what a crash
looks like. They fail instead, naming the plugin, what it exited with, and the
fact that nothing else in the sandbox is affected.

---

## 4. Framing and protocol revision

**The framing is settled and is not reopened here.** MCP over stdio is
newline-delimited JSON-RPC — one message per line, no embedded newlines, and
explicitly not LSP `Content-Length` framing. This was verified against the
official specification across every revision through 2025-11-25 during the build
plan's review rounds, and `docs/protocol.md` §6 carries it.

**Frames are bounded at 16 MiB on this channel**, rather than at the 1 MiB the
rest of the protocol uses. Nothing here is chunked — a `read_file` result is a
whole file on one line — and the per-call limit on a file is 8 MiB, so a 1 MiB
frame would refuse messages the tools above it promise to carry. Sixteen leaves
room for JSON escaping around eight and still bounds the buffer. Every reader
*and writer* on both sides of the channel takes the number from one constant
(`proto.MaxMCPLine`), because a writer that will send more than the reader
opposite it accepts is a connection that dies mid-answer — which is what a
caller sees as an unexplained EOF. `docs/protocol.md` §3 carries it.

**`serve-mcp` implements revision 2025-11-25**, the same revision the guest's
server advertises, so the product speaks one revision in both directions.

A newer revision exists — **2026-07-28** — and it is a redesign rather than an
increment: the `initialize` handshake is replaced by `server/discover`, sessions
are removed in favour of an explicitly stateless model, `serverInfo` moves into
`_meta`, and results carry a `resultType`. Adopting it would mean changing the
guest's server, the host's bridge, this new server and the cookbook's recipes
together, and it would drop clients that have not moved. That is its own piece
of work with its own evidence, and E4 is not it. What E4 owes is that nothing
here makes the move harder: the tool surface, the namespacing and the policy
ceiling are revision-independent, and only the handshake would change.

---

## 4.1 Both directions at once

The two doors are independent and can run at the same time on the same machine.
Recipe 11 of the [cookbook](cookbook.md) does exactly that, and it is what E4-8
proves: an outside client drives `serve-mcp` to make a sandbox, write a file and
run a command in it, while an agent attached to that same sandbox through
`kelyfos mcp` calls a plugin running beside it inside the guest.

**Two records, and each one holds what its party did.**

The machine's own chain says what was done *to the machine*: the file write and
the command, marked `via: serve-mcp`, and every plugin call the inner agent
made. That is both directions of action in one transcript, verifiable as one
chain.

The server's chain says what the client *asked for*: every tool call with its
arguments, its duration and its outcome — including the request for 64 cores
that was refused, which never reached a machine and therefore appears in no
machine's record. F-D43 has the reasoning; the short form is that each chain
records what that party did, and a refused call did nothing to any machine.

The two are cross-linked rather than merged: the sandbox's `session.start` names
the server session it was created through, and the server prints that id when it
starts.

---

## 5. Conformance

| Requirement | Task |
| --- | --- |
| This spec | E4-0 |
| `serve-mcp` core: `sandbox_run`, `sandbox_exec`, `sandbox_stop`, `sandbox_list`, `max_sandboxes`, ceilings refused | E4-1 |
| `sandbox_read_file`, `sandbox_write_file`, `sandbox_snapshot`, `sandbox_fork`, `sandbox_restore` | E4-2 |
| `team_up`, `team_ps`, `team_down` | E4-3 |
| `mcp.host.*` audit lane, rendered by `log --export` | E4-4 |
| Client recipes in the cookbook, CI-executed; generated reference picks up the new surface | E4-5 |
| The plugins drive and its manifest | E4-6 |
| Supervisor plugin runtime, `<plugin>_<tool>`, `plugin.crash` | E4-7 |
| Both directions proved at once, with a demo plugin in-repo | E4-8 |
