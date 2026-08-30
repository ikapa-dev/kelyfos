# Building on KelyfOS

For people putting KelyfOS *inside* something else: an agent framework, an
orchestrator, a CI step, a product. The [cookbook](cookbook.md) is for using it;
this is for depending on it.

Everything here that is code has been executed. Where something has not been,
this page says so rather than printing it anyway.

---


## One command

`kelyfos connect <client>` writes the client's own configuration, in its own
format and its own location, and `--check` then starts the server it named and
completes a real MCP handshake — because "configured" asserted without evidence
is what the command exists to replace.

```sh
kelyfos connect --list          # the clients it writes, and what each was verified against
kelyfos connect claude-code     # writes .mcp.json in this project
kelyfos connect vscode --check  # writes .vscode/mcp.json, then proves the server starts
kelyfos connect generic         # prints the snippet, for anything else
```

It is idempotent, `--remove` uninstalls, and it is a guest in somebody else's
file: other servers and keys it has never heard of both survive.

**The mode it writes depends on where the file lives, not on which client it
is.** A configuration under your home directory — `~/.codex/config.toml`,
`~/.gemini/settings.json` — is created `0600` inside directories created `0700`,
because those are files that commonly grow an API key later and `kelyfos
connect` is often the first thing to create them; a mode set at creation is the
mode the client that writes the key into it will keep. A project-local file
(`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.junie/mcp/mcp.json`) is
meant to be committed and keeps the ordinary mode your umask gives everything
else. **An existing file is never widened**: whatever is already stricter wins,
so a file you tightened yourself stays that way. Deciding by path prefix rather
than by client name is what makes a client added later inherit the rule.

"Where the file lives" is decided **both** ways and the stricter answer wins:
the path you named, and the path it resolves to. Either alone gets a real case
wrong. A project's `.cursor` that is a symlink into your home directory — one
MCP configuration shared across checkouts — resolves inside and gets `0600`; a
`~/.codex/config.toml` that stow or chezmoi links *out* of your home is still
named under it and gets `0600` too, where resolving alone would have called it
project-local and left it `0644`.

**The write is atomic, and it writes *through* a symlink rather than over
one.** It goes to a temporary file beside the target, is fsynced, and is renamed
over it — this is a read-modify-write of a file another program may have open,
and a rename is the only atomic replacement available. Because a rename replaces
a link where an ordinary write would follow it, the link is resolved first and
the replacement happens in the target's own directory: a dotfiles-managed
configuration stays a link to the file you version-control, and the write lands
in the repository. A **dangling** link is written through as well, creating the
file it names — that is a fresh machine before the dotfiles repository is
cloned. A chain more than eight links deep is refused by name rather than
followed. A file that will not parse is refused before anything is written and
is left exactly as it was.

**Two things it gets right that a copied snippet gets right by luck.** The policy
path is written **absolutely**, because a server that has to find its own policy
can find none and run with no ceiling at all — and the working-directory and
variable-expansion rules are asymmetric across every client, so a shared snippet
would attach the wrong policy for half of them. And the surface is `serve-mcp`
and not `mcp`: the first is KelyfOS itself as a server, the second bridges a
client to one sandbox's guest.

**A client's configuration format is an external surface.** It is outside the
drift gate and outside the compatibility promise, re-verified on its own cadence,
which is why every entry carries the tool it was checked against and the date.
The rest of this page is the hand-written path, which is what you need if your
client is not one of the six.

`connect` does not run on macOS. What the binary answers there at all is
`doctor`, `verify`, `version` and `help`; everything else refuses with
`kelyfos doctor` as the way in, so a Mac's configuration is the `limactl` form
in §3, written by hand.


## 1. Four ways in, and how to choose

| | What it is | Choose it when |
| --- | --- | --- |
| **The CLI** | `kelyfos` as a subprocess: `run`, `exec`, `team up`, `log` | You are scripting, or your orchestrator is happy shelling out. Simplest thing that works. |
| **The MCP bridge** | `kelyfos mcp` copies bytes between your standard streams and *one guest's* MCP server | You are writing an agent that works inside a sandbox you chose. This is the interface the product was designed around. |
| **The MCP server** | `kelyfos serve-mcp` is KelyfOS itself as an MCP server: sandboxes, files, snapshots, forks and teams as tools | You have a client — Claude Code, VS Code, anything — and want *it* to create and manage the machines. One entry in a config file. |
| **The E2B shim** | an E2B-compatible REST subset on a local port | You have code already written against the E2B SDK and want it to work against a self-hosted box without a rewrite. |

All four go through the same wall. The CLI, `serve-mcp` and the shim each read
the project's `kelyfos.toml` and are capped by its `[resources]`; the bridge
reads no policy file of its own, because it attaches to a sandbox already
running under the policy whichever door booted it applied. All four write a
flight recorder — there is no entry path that skips the policy, which is the
invariant F-D5 states for MCP and F-D33 applied to the shim.

They do differ in what they can express. The shim serves a fixed REST subset and
cannot run commands at all; the bridge gives an agent one guest's full tool
surface; `serve-mcp` gives a client the host's, including snapshots, forks and
the declared team; the CLI gives you everything. And the shim authenticates
every caller — since v1.1 it mints a token when `KELYFOS_SHIM_TOKEN` is unset and requires it on every route, and running without one takes `--insecure-no-token`. Under that flag its port is a local
privilege surface the other three do not have.

The two MCP doors point in opposite directions and are easy to confuse. `mcp`
is *inward*: you have already chosen a sandbox and you are talking to what is
inside it. `serve-mcp` is *outward*: the client has no sandbox yet, and the
tools are for getting one. A client configured with `serve-mcp` needs the policy
named explicitly — `--policy /path/to/kelyfos.toml` — because the working
directory it launches from is the client's, not yours, and one launched outside
the project would find no policy and run with no ceiling. `docs/mcp-surface.md`
§2.3 has it, and recipe 9 of the cookbook is the configuration for two clients
with a check that proves the file works.

### The one flag that shapes everything else

```
kelyfos run [flags] -- <command>
```

This boots a sandbox, exports `KELYFOS_SANDBOX` into `<command>`'s environment,
runs the command **on the host**, then tears the sandbox down and exits with the
command's own status — unless a time budget fired, which makes the status `124`
whatever the command returned, or something in the guest was OOM-killed, which
turns a zero into `137`. Every `kelyfos exec` and `kelyfos mcp` in that command
attaches to that sandbox without being told which one.

It is the shape to build on, for a reason worth stating plainly: the alternative
— backgrounding `kelyfos run` and signalling it later — is where integrations go
wrong. See [common mistakes](#6-common-mistakes), first entry.

`kelyfos fork` and `kelyfos team up` hold their machines the same way and have
**no** trailing-command form. Background those and wait for the line that says
they are ready.

---

## 2. Python

The whole of it, and it is executed by CI as the `python-mcp-client` recipe in
[`cookbook.md`](cookbook.md):

```python
import asyncio, os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # No host, no port, no API key: the transport is a subprocess.
    params = StdioServerParameters(command="kelyfos", args=["mcp"], env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print(" ".join(t.name for t in tools.tools))

            out = await session.call_tool("exec", {"command": "python3 -c 'print(6*7)'"})
            print(out.content[0].text.strip())
            assert out.structured_content["exit_code"] == 0

asyncio.run(main())
```

Run it inside a sandbox's lifetime:

```sh
kelyfos run --image dev -- python orchestrator.py
```

Three things about that snippet that cost time to find out:

- The SDK is **`mcp`** on PyPI, version 2.0.0 at the time of writing, and its
  models are snake_case: `server_info`, `structured_content`, `is_error`. The
  wire format is camelCase and the Python objects are not.
- **A failing tool call is a result, not an exception.** `exec` on a command that
  exits 3 returns normally with `is_error` set and
  `structured_content["exit_code"] == 3`. That is deliberate — the model is meant
  to see the failure and adapt, not have it raised past it — and an orchestrator
  that only catches exceptions will not notice.
- `env=dict(os.environ)` matters. `KELYFOS_SANDBOX` is how the bridge knows
  which machine to attach to, and a client that sanitises the environment
  strands it.

For the CLI route instead, `subprocess` is enough — but check the exit status
rather than the output. [`reference/exit-codes.md`](reference/exit-codes.md)
lists them; the ones an orchestrator should branch on are `124` (a time budget
fired), `137` (the guest's OOM killer ran) and `127` (no such command in the
guest). A guest command's own status passes through unchanged.

---

## 3. JavaScript, and any other language

**No JavaScript client is reproduced here, because nothing in this repository
executes one.** The rule this project follows is that printed code has been run,
and a TypeScript snippet transcribed from memory is exactly the kind of
confidently-wrong reference F-D4 exists to prevent. What follows is what *is*
verified.

**If you have an MCP client already** — Claude Code, Cursor, anything speaking
the standard — it needs one entry of configuration and no code. Point it at
`serve-mcp`, the outward door, and **name the policy file absolutely**:

```json
{
  "mcpServers": {
    "kelyfos": {
      "type": "stdio",
      "command": "/abs/path/to/kelyfos",
      "args": ["serve-mcp", "--policy", "/abs/path/to/kelyfos.toml"]
    }
  }
}
```

`--policy` is not optional in a client configuration, and this is the paragraph
that says why: the policy is otherwise found by searching upward from the
working directory, and under a client that directory is the client's, not yours.
A server launched from `$HOME` would find no policy and run with **no ceiling at
all**. A `--policy` naming a file that does not exist is an error rather than a
fallback, for the same reason.

When the agent runs on macOS and the sandbox runs in a Lima layer, the whole
command crosses the boundary — and a non-interactive `limactl shell` gets a
minimal `PATH`, so a bare `kelyfos` is not found there even when it exists:

```json
{
  "command": "limactl",
  "args": ["shell", "kelyfos-dev", "--",
           "/abs/path/to/kelyfos", "serve-mcp", "--policy", "/abs/path/to/kelyfos.toml"]
}
```

This repository's own [`.mcp.json`](../.mcp.json) runs
[`dev/mcp-server.sh`](../dev/mcp-server.sh) rather than either of these, because
a VM name and an absolute path do not belong in a file a Linux contributor also
checks out; the script chooses the right form for the machine it runs on.
`kelyfos connect <client>` writes the first form and only the first — an
absolute path to the `kelyfos` binary with `serve-mcp --policy`, never a
`limactl shell` wrapper — so the Lima shape above stays hand-written.

**If you are writing a client from scratch**, the transport is a subprocess and
the framing is newline-delimited JSON-RPC — one message per line, no embedded
newlines, and explicitly *not* LSP `Content-Length` framing. Spawn
`kelyfos mcp`, write a line, read a line. The `three-agent-team` recipe in the
cookbook does exactly this with `printf` and a pipe, so the wire shape is
demonstrated even where an SDK is not:

```sh
{ printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"you","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"command":"uname -a"}}}'
  sleep 5
} | kelyfos mcp
```

The bridge does not reframe: whatever your client sends reaches the guest's MCP
server byte-for-byte, which is what makes an off-the-shelf client work. It does
read a copy, though — each direction is teed into a line scanner whose output is
unmarshalled to write flight-recorder events, and that scanner's ceiling is
16 MiB, so a longer line ends the copy rather than reaching the guest. And when
the bridge closes with tool calls still outstanding it answers those itself,
with error results the guest never sent — see
[common mistakes](#6-common-mistakes).

---

## 4. Patterns for an orchestrator

### Generate the team file, do not hand-write it

A `[team]` section is data, and the natural way to run N agents over N inputs is
to write the toml from your program and then boot it. The schema is in
[`reference/config.md`](reference/config.md); the shape is:

```toml
[team]
name = "suppliers"

[[team.agent]]
name  = "master"
allow = ["example.com"]     # the only agent with a network

[[team.agent]]
name  = "worker"
count = 4                   # worker-1 … worker-4, no egress at all

[[team.edge]]
from = "master"
to   = "worker-*"

[team.store]
enabled = true
```

The rules the generator has to respect, because the parser refuses otherwise:
an agent's `secrets` must each name a domain that is in *that agent's* `allow`;
`count` above 1 cannot be combined with a `workspace`; two agents cannot resolve
to the same name, counting the `worker-1` … `worker-N` a `count` expands into;
and an edge endpoint that matches no agent is an error rather than a no-op.
Inside `[team.agent.resources]` an `idle_timeout` is refused (F-D20), and inside
`[team.agent.spawn.resources]` so are `idle_timeout` and `max_runtime` — the
second is the budget's own `lifetime` under another name.

### Spawn under a budget, rather than deciding for the agent

If the number of workers is a decision the *agent* should make at runtime, grant
it a budget and let it:

```toml
[[team.agent]]
name = "master"
  [team.agent.spawn]
  max      = 4
  image    = ["dev"]
  lifetime = "10m"
```

The master then sees a `team_spawn` tool and can create workers within exactly
that budget. Every grant and every refusal is an audit event. The important
property for an orchestrator is that **no tool can widen a budget** — the policy
file is the ceiling and there is no runtime path around it — so you can hand an
agent this capability without also handing it the ability to grow it.

A spawned worker gets no egress, no secrets and no workspace, ever, and attaches
with exactly one edge, to its spawner. If a worker needs the network, declare it
as a `[[team.agent]]` instead.

### Finding out which sandbox is which

`kelyfos team ps` prints the roster for a human. There are two machine-readable
forms of the same thing, and which you want depends on which door you came
through.

**From an MCP client**, `team_ps` returns it as `structuredContent`: an `agents`
array carrying `agent`, `sandbox`, `via` (`cold` or `fork`), what each has
consumed against its cap, its allowlist, and who it may message. That is the
mapping an orchestrator needs, and it is a tool rather than a file.

**From a shell**, ask the command line for it:

```sh
kelyfos team ps --json
```

It returns the same shape `team_ps` does — an `agents` array whose entries carry
`agent`, `sandbox` and `via` — which is what `kelyfos mcp --sandbox <id>` wants.
It also names the team, its session and which door raised it, which is why
`kelyfos team down` refuses to signal a team a `serve-mcp` server is holding.

Several teams may be up at once, each with its own state and its own record. With
more than one running, `--team <name|session>` says which; with one, nothing
changes. Earlier versions of this page told you to read
`~/.cache/kelyfos/run/team.json` instead. Do not: that path no longer exists —
each team now writes `~/.cache/kelyfos/run/teams/<session>.json`, and it is
internal layout rather than a surface this project promises to keep still
(`docs/compatibility.md` §2). `kelyfos team ps --json` is the answer that is
promised.

### Read the record rather than the output

`kelyfos log --json` is the parseable form and
[`reference/events.md`](reference/events.md) is the schema. For an orchestrator
the useful events are `command.exit` (with `code`), `egress.attempt` (with
`allowed` and `reason`), `resource.timeout` (with `budget`) and
`resource.summary` (the usage receipt at teardown). A team is one session, so
one file covers every agent and the `agent` field says which machine each event
came from.

`kelyfos log --verify` exits non-zero when the chain is broken — an event
edited, a line deleted from the middle, a line reordered. What it cannot see is
a record truncated at the tail: the walk starts at line 1 and follows the links
forward, and nothing in the file says how many events there should have been. If
you are storing these records as evidence, the check is the chain head the
verdict prints, compared against the head you recorded somewhere else; the exit
status alone does not prove no trailing line was removed.

---

## 5. What KelyfOS will not do for you

Worth knowing before you design around it.

- **No control plane.** One host, no scheduler, no queue, no API server. If you
  need to place work across machines, that layer is yours.
- **No live rewiring.** A team's topology is fixed for the run. The single
  exception is a budgeted `team_spawn`, and the worker it creates gets one edge.
- **No GPU, on this backend, ever.** Firecracker has no device passthrough; it is
  the security posture rather than a missing feature.
- **No inbound packets.** Nothing outside opens a connection to a guest across
  its network interface, and a forward is not an exception: a `-p 8080:80` on
  `kelyfos run`, or a `[[forward]]` in `kelyfos.toml`, binds a listener on this
  machine and carries each connection over vsock, so the nftables ruleset is the
  same with a forward as without one (F-D7). That listener binds `127.0.0.1`
  unless `--p-bind` says otherwise.
- **No shared filesystem.** `--workspace` is a copy in and a copy back.

---

## 6. Common mistakes

Every one of these is a real error someone hit, most of them during this
project's own build. They are here with the message you will actually see, so
that searching for it lands you on the answer.

### Backgrounding `kelyfos run` and signalling it

The mistake that produces the strangest bug. `kill -INT` on a backgrounded
`kelyfos run` is not reliably waited for by the shell's `wait`, so a script that
stops a sandbox and then reads its workspace can read it **before the write-back
has finished** — passing on a fast machine and failing on a slow one.

Use `kelyfos run [flags] -- <command>` instead. It has a defined exit point.

### Expecting the workspace directory to survive

The write-back is a **swap, not a merge**: the old directory is renamed away and
the reconstructed one is renamed into place, so that a file the agent deleted is
really gone. The consequence is that a process whose current directory *is* the
workspace ends up in a directory that no longer exists. Step back into it by
name after the run.

Two more consequences a script will hit. The directory renamed away is kept as
`<dir>.kelyfos-previous` until the next successful run clears it, so every run
leaves a sibling directory behind. And the swap is not unconditional: the host
directory is fingerprinted again just before it happens, and if it changed while
the sandbox ran the reconstructed tree lands in `<dir>.kelyfos-out` instead,
with the workspace directory left exactly as it was — so a script that assumes
the directory was replaced can read pre-run state.

### `kelyfos exec` with more than one sandbox running

```
kelyfos: 2 sandboxes are running; pick one with --sandbox: [39a571db 5bf6f351]
```

There is no "current" sandbox. `KELYFOS_SANDBOX` or `--sandbox` disambiguates;
`run -- <command>` sets the first one for you.

### Picking a session out of `kelyfos log --list`

The listing is newest first, and every `log` subcommand defaults to the most
recent session when `--session` is absent, which is almost always what you
meant. Rows are marked with what kind of session they are — `team of N`, or
`serve-mcp, N sandbox(es)` — so a listing can be filtered rather than guessed
at: `kelyfos log --list | grep serve-mcp | head -1` is the server's own record.

### A secret bound to a domain that is not allowed

```
kelyfos: --secret GITHUB_TOKEN@api.github.com: api.github.com is not in --allow [secret.unbound]
    add api.github.com to --allow, or drop the secret — a credential for a domain
    the sandbox cannot reach is a credential nothing will ever use
```

Binding a credential does not permit the domain. `--allow` is the policy;
`--secret` decides what gets attached once it is permitted.

### `mem = 512` in the file is not `--mem 512` on the command line

A bare number is **MiB on the command line** and **bytes in the file**, so
`mem = 512` is refused as under 1 MiB. Write `mem = "512M"`. The asymmetry
exists because `--mem 512` has meant 512 MiB since v0.1 and changing it would
break every command line in the wild; it is the only place the two grammars
differ.

### `disk` is a ceiling, not a size

```
workspace ./project needs an image of 4294967296 bytes, over the 2147483648
byte ceiling; raise it or exclude what does not need to be in the sandbox
```

The `/work` device is sized from the directory — twice its size, or 1 GiB,
whichever is larger. `disk` is the maximum that sizing may reach, checked before
boot. It does nothing at all without a `workspace`.

### `[resources]` values are also defaults

`[resources]` is documented as ceilings, and it is — but an unset flag takes the
ceiling as its value. `cpus = 2` therefore both caps the machine at two cores and
*gives* it two.

### Anything that resolves a name before connecting

The guest has no DNS at all — no resolver, no `/etc/resolv.conf`, UDP/53
dropped. `ping`, raw sockets and any library that ignores `HTTPS_PROXY` will
fail. That is the correct failure: DNS tunnelling defeats a hostname allowlist
completely, so the guest is not given a resolver to tunnel through. Anything
that speaks to the proxy works.

### A client that pins certificates, against a secret-bound domain

```
egress.attempt … reason=tls_pinning_rejected_our_ca
```

The proxy terminates TLS for domains you bound a credential to, and presents a
certificate from a CA minted for that run. A pinning client refuses, correctly.
There is no way to have both a credential the guest cannot read and an unbroken
pin; pick per domain.

### Forking a sandbox that has a network

```
snapshot "prepared" was taken from a sandbox with egress (allowed: github.com),
and forks are vsock-only in v0.x.
```

The guest's address and default route live inside the memory image every fork
shares, so N forks would be N machines each believing it is the same host.
Prepare the template without `--allow`.

### `--image` that does not match the image on disk

Every built or fetched image carries a manifest, and the sandbox refuses to boot
when the flavor you asked for is not the flavor that is there. The point is that
the flavor in your audit trail is a checked fact rather than a label somebody
typed.

### Per-agent `idle_timeout` inside a team

```
idle_timeout is not available per agent yet (F-D20)
```

A team shares one flight recorder, so "has anything happened lately" is a
team-level fact and the key would be inert in exactly the case you wrote it for.
`max_runtime` is per agent and does work. Note the pair of refusals is currently
circular: writing it under `[team.resources]` tells you to move it to
`[team.agent.resources]`, which then refuses it.

### A blocking tool whose channel closes before the answer arrives

`team_ask` and `team_recv` answer when the *other side* acts, not when the
request is written. If your client closes the MCP session before then — a
`printf | kelyfos mcp` pipeline whose stdin ends immediately, for instance — the
bridge waits a few seconds for an answer already on its way, and then **answers
the call itself** with an error result naming the tool:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text",
 "text":"kelyfos: the bridge to this sandbox closed before team_ask answered…"}],
 "isError":true}}
```

That is a normal tool result with `isError` set, so an SDK surfaces it the way
it surfaces any other failing call rather than raising a transport error. It
used to be silence, which is worse than either: a caller told nothing concludes
the call is still running, or that it succeeded and returned nothing (F-D33).

Still hold the channel open for at least as long as the tool's own `timeout_ms`
— an error result is a diagnosis, not an answer. The cookbook's team recipe does
this with a trailing `sleep`; the Python SDK does it for you by keeping the
session open.

The record is not a workaround here either. An ask that goes unanswered is
written when the host-side timeout fires, which is `timeout_ms` later — or
fifteen minutes, if you asked for longer than the host will hold a call open —
not when your client gave up.

### The error an agent sees is not the reason the record gives

Deliberately: an agent branches on a small set of kinds it can act on, and the
transcript records the specific thing that happened. A `team_reply` with a
`correlate` tag nobody is waiting for returns `denied` to the agent and is
recorded as `unknown_correlation`; with no tag at all it returns `denied` and is
recorded `missing_correlation`. Branch on the kind, and read the record for the
detail.

### `team_recv` returning nothing

It does not. An empty window is an **error** of kind `timeout`, not an empty
result — because a model told "nothing" concludes there is nothing to do, while
a model told "timeout" knows only that nothing has arrived *yet*. The wait
argument is `timeout_ms`, an integer of milliseconds, default 60000. The host
clamps it at both ends: anything at or below zero becomes one minute, and
anything above fifteen minutes becomes fifteen, so an orchestrator that asks for
an hour waits fifteen.

That timeout writes **no event**. `outcome: timeout` in the record means an ask
nobody answered; a recv that found nothing is not an outcome, because no message
was involved. Do not wait for the transcript to tell you an agent has gone
quiet.

### Assuming a shim sandbox is unpoliced

It is not, since F-D33: `kelyfos shim` reads the project's `kelyfos.toml`,
`[resources]` caps every sandbox it creates, and each one writes its own flight
recorder. Since v1.1 it also authenticates its caller by default: with
`KELYFOS_SHIM_TOKEN` unset it mints 256 bits at start, prints them once, and
every route requires `Authorization: Bearer <token>`, answering `401` without
it. Running with no credential takes `--insecure-no-token`, and under that flag
the port is unauthenticated — bind it to loopback and treat reaching it as
equivalent to running `kelyfos` on the machine, which is what every other local
account on a shared box can then do.

The E2B SDK is the case that forces the flag: it sends `X-API-KEY` on the
control plane and a `Basic` header derived from the sandbox user on the file
routes, and the shim reads neither. What the flag does *not* turn off is the
rest of what v1.1 added — the `Origin`, `Sec-Fetch-Site` and `Host` refusals,
the JSON-body requirement on `POST /sandboxes`, and the refusal to bind off
loopback without a credential all still apply. A web page still cannot reach
the shim under `--insecure-no-token`; that was the half of the change nobody
can opt out of.

### Running commands through the E2B shim

Not supported, and it returns `501` rather than a `404` that would read like a
bug. The current SDK runs commands over Connect RPC with protobuf, which is a
different protocol stack from the REST endpoints the shim serves. Use
`kelyfos mcp`.

---

## 7. Where to look next

- [`cookbook.md`](cookbook.md) — twenty-one recipes that run, including the
  Python client above
- [`reference/`](reference/) — every command, flag, key, tool, event and exit
  code, generated from the source
- [`teams.md`](teams.md) — the full account of the schema, the broker and the
  store
- [`threat-model.md`](threat-model.md) — what you are and are not getting
