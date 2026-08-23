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

> **`serve-mcp` can never widen policy. The project's `kelyfos.toml` is the
> ceiling, and no tool exists to change it.**

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
`{id, image, arch, boot_ms}`.

`allow` is the one parameter where "ask for less" needs saying out loud: the
policy's allowlist is the set of domains this project may reach, and a call may
narrow it for one sandbox. It may never add to it. A call naming a domain the
policy does not list is refused and audited, and the refusal names the domain.

**`sandbox_stop`** — stop one sandbox and clean up.
`{sandbox: string}` → confirmation. Stopping a sandbox this server did not
create is an error: `serve-mcp` owns what it made and does not adopt a machine
somebody's `kelyfos run` is using.

**`sandbox_list`** — the sandboxes this server created.
No parameters → `structuredContent: {sandboxes: [{id, image, allow, created}]}`.

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
**`sandbox_write_file`** — `{sandbox, path, content}` → bytes written.

Both are the supervisor's own RPCs with a sandbox id in front. The 8 MiB
per-call cap the guest tools have applies here too, for the same reason.

#### State

**`sandbox_snapshot`** — `{sandbox, name}` → freeze it. The sandbox keeps
running.
**`sandbox_restore`** — `{name, allow?}` → bring one back as a new sandbox.
**`sandbox_fork`** — `{name, count}` → N independent copies of one snapshot.

`sandbox_fork` inherits P3-2's rule unchanged: a snapshot taken from a networked
sandbox cannot be forked, because the guest's address lives inside the memory
image every fork shares. The refusal says so rather than producing N machines
that each believe they are the same host.

#### Teams

**`team_up`** — raise the team the project's `kelyfos.toml` declares.
No parameters: the topology is the file's, not the caller's. There is no
argument that adds an agent or an edge, for the reason in §1.
**`team_ps`** — the roster, as structured data. This is deliberately the
machine-readable form `kelyfos team ps` does not have.
**`team_down`** — retire it.

An external agent can raise and retire a whole declared team and cannot change
its shape. That is the same bargain the guest's `team_spawn` makes: capacity is
grantable, topology is not.

### 2.3 Sessions, concurrency and `max_sandboxes`

```toml
[mcp]
max_sandboxes = 4
```

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
agent's use of the sandbox is itself in the transcript, alongside what happened
inside the guest, and `kelyfos log --export` renders the client's lane beside
the guest's.

This is the point of the outward direction rather than a feature of it. Without
it, "an agent did some work in a sandbox" would be recorded and "an agent
decided to create a sandbox with these limits" would not, and the second is the
part a reader most wants when something has gone wrong.

The event types are named in `docs/events.md` when E4-4 adds them. The rule they
follow is the one every other event follows: the host writes them, the client
does not, and a refused call is recorded exactly like a permitted one.

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

### 3.1 Why this is safe

A plugin has exactly the powers of a malicious agent, and the sandbox already
assumes the agent is malicious (F-D5). It runs inside the same microVM, under
the same read-only root, behind the same absent network. There is nothing a
plugin can reach that agent-written code could not have reached anyway.

Two things follow, and both are enforced rather than assumed:

**A plugin gets no egress of its own.** The per-agent allowlist is the single
network policy surface. There is no `[[plugin]] allow`, and asking for one is
asking for a second door in a wall whose whole value is having one.

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

> A plugin's `name` matches `^[a-z][a-z0-9-]*$` — lowercase, no underscore, no
> dot. `<plugin>_<tool>` is then unambiguous, because the plugin half cannot
> contain the separator.

The full name must also fit in **64 characters**, the strictest downstream
limit, and a plugin whose tool would exceed it is refused at boot rather than
advertised and rejected later by somebody else's API.

**The prefix is the declared name, never the plugin's own.** A plugin announces
a `serverInfo.name` at initialize, and that name is not used for anything. The
MCP specification says as much — a server's self-reported name is not guaranteed
unique and should not be relied on for disambiguation — and KelyfOS would refuse
it anyway, for the reason it refuses every other guest-asserted identity: the
host decides what a thing is called, and the thing being named does not get a
vote (F-D24).

### 3.3 The plugins drive

The host packs each declared plugin's `path` directory into a **read-only ext4
image**, attached as the next virtio-blk device and mounted at `/plugins`
(F-D6). Sizing follows P3-10's rule and the image is built by the same
host-side `mkfs.ext4`-and-populate the workspace uses.

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
| `sha256` | Digest of the packed directory. |

A plugin present on the device and absent from the manifest is not launched. The
manifest is the list; the device is storage. That is the same relationship
`image.json` has to an image directory, and it exists for the same reason D21
gives: the host should not assert a fact it has not checked.

A flavor may also ship a server built into the image. Both routes launch
identically — the manifest is what differs, and a built-in server appears in it
the same way.

### 3.4 When a plugin breaks

A plugin is a child process and processes die.

**Its tools fail; the sandbox does not.** A crashed plugin's tools return
`isError` results explaining that the plugin is gone. `exec` still works, the
other plugins still work, and the supervisor — which is PID 1 — is untouched.

**The crash is an event.** `plugin.crash` names the plugin and what it exited
with. A plugin that dies silently and takes its tools with it would otherwise
look identical to a plugin that never had those tools.

**Per-call audit events carry the plugin name**, so a transcript says which
plugin was asked to do what, not merely that a tool was called.

---

## 4. Framing and protocol revision

**The framing is settled and is not reopened here.** MCP over stdio is
newline-delimited JSON-RPC — one message per line, no embedded newlines, and
explicitly not LSP `Content-Length` framing. This was verified against the
official specification across every revision through 2025-11-25 during the build
plan's review rounds, and `docs/protocol.md` §6 carries it.

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
