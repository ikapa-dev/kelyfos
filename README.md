# KelyfOS

**A sandbox an AI agent can only reach through tools.**

KelyfOS is a minimal guest operating system for Firecracker microVMs. The guest
has no shell login, no SSH and no network by default — it exposes itself to an
agent as a handful of MCP tools, keeps your credentials outside the box
entirely, and writes down everything that happened in a record the guest cannot
edit.

![KelyfOS in a terminal](docs/media/demo.gif)

> **Status: v0.9, early development, building in the open.** Cold boot-to-ready
> **135 ms** median, snapshot restore **49 ms**, five agents up in **412 ms** —
> x86_64 on a bare-KVM CI runner, ten runs each, by a benchmark workflow in this
> repository rather than by hand.
>
> **v0.9 is the hardening release.** The VMM runs inside the jailer with its own
> syscall filter proved in force rather than assumed, and everything the guest
> spawns is confined by Landlock and a syscall refusal list. An agent is still
> root inside its own guest, and the VM — not the chroot — is still the boundary.
> [**What is enforced, and what is not**](#security) says which is which, in a
> table and a longer list; [`docs/threat-model.md`](docs/threat-model.md) is the
> long version, and it is the thing to read before trusting this with anything.

KelyfOS — from κέλυφος (*kélyfos*), "shell": the guest wrapped around the agent.

## Why

The agent-sandbox runtimes all build control planes and boot a generic
Ubuntu inside. Nobody ships the *guest* as an opinionated product. That is the
gap: an image whose init system speaks MCP, whose egress is deny-all, whose
secrets never enter the VM, and whose audit trail is tamper-evident by
construction.

Three things it does that a container does not:

- **Egress is off, not filtered.** No `--allow` means the machine has no network
  interface at all. There is no rule that has to hold for the guarantee to be true.
- **Secrets never enter the guest.** `--secret GITHUB_TOKEN@api.github.com` keeps
  the value on the host; the proxy attaches it on the way out. `env` in the
  sandbox shows nothing.
- **The record is written by the host.** A guest that could write its own audit
  trail could write a flattering one, so it cannot write one at all. And the
  export carries that record inside it, so whoever you send it to checks it
  themselves — `kelyfos verify report.html`, offline, no key.

## Quickstart

Firecracker needs Linux and KVM. On macOS that means a Lima VM; on Windows,
WSL2; on a Linux box with `/dev/kvm`, nothing.

```sh
git clone https://github.com/p4r4n0rm4l/KelyfOS && cd KelyfOS
```

On macOS, clone it somewhere under your home directory — that is what the Lima
VM mounts, and `limactl shell` keeps your working directory, so the commands
below just work.

Measured end to end — `git clone` to the first `kelyfos exec` output —
**against the v0.9 release**, which is what the commands below actually download.

**KelyfOS's own part is 10 seconds**: firecracker, the CLI, the guest image, the
sudoers grant and `doctor` together 9 s, then the first `kelyfos exec` 1 s. On a
Linux/KVM box that is the whole of it.

On macOS you also pay for the Linux layer, and that part is Lima's rather than
ours: **28 s** when it already has the Ubuntu image, **138 s** when it has to
download it. Both are measured, on the same machine, minutes apart. We are not
going to quote you the flattering one and call it the number.

**On macOS first — a Linux layer with nested virtualisation** (skip on Linux).
This step downloads and boots an Ubuntu VM, and is most of that wall clock:

```sh
brew install lima
limactl start --name kelyfos-dev dev/lima.yaml
limactl shell kelyfos-dev          # everything below runs in here
```

**Then, on Linux or inside that shell.** Nothing here needs a compiler — the CLI
is a static binary and the guest image is prebuilt:

```sh
bash dev/install-firecracker.sh    # the VMM and its jailer
bash dev/install-kelyfos.sh        # the CLI
bash dev/fetch-image.sh            # the guest image

# KelyfOS runs Firecracker inside the jailer — a chroot, a dropped uid, only
# the devices it needs — and the jailer needs root. This grants it for the
# jailer alone, and for nothing else:
echo "$USER ALL=(root) NOPASSWD: $(command -v jailer)" \
  | sudo tee /etc/sudoers.d/kelyfos-jailer
sudo chmod 0440 /etc/sudoers.d/kelyfos-jailer

./bin/kelyfos doctor               # checks all four, the jailer included
```

`kelyfos run --no-jail` works without that grant. It says what is not enforced
on every run that uses it, and the session record says so too — see
[`docs/hardening.md`](docs/hardening.md).

Each of those verifies what it downloaded against a published checksum before
installing it, and shows you doing so — a mismatch aborts with nothing written:

```
Fetching KelyfOS latest image for x86_64 from p4r4n0rm4l/KelyfOS
  SHA256SUMS
  vmlinux-x86_64.gz
  rootfs-x86_64.ext4.gz
  image-x86_64.json
Verifying checksums
vmlinux-x86_64.gz: OK
rootfs-x86_64.ext4.gz: OK
image-x86_64.json: OK
Decompressing

Installed the 'dev' image for x86_64 into ~/.cache/kelyfos/out/x86_64
Run it with:  kelyfos run --image dev
```

**Now run something in it:**

```sh
./bin/kelyfos run --image dev --allow github.com &
./bin/kelyfos exec "uname -a"
./bin/kelyfos exec "git clone --depth 1 https://github.com/kelseyhightower/nocode /work/nc"
./bin/kelyfos exec "curl -sS https://example.com"    # refused: not in the allowlist
./bin/kelyfos log --verify
```

`kelyfos doctor` is the thing to run first on any new machine: it checks nine
things and prints the exact fix for whatever is wrong, tailored to whether you
are on Lima, WSL2, bare Linux or macOS.

### Building it yourself

The downloads above are built from this source at the release tag. They are
**not** bit-for-bit what your own `make image` produces: the build is not
reproducible yet, the two architectures of v0.9 were built on two different
machines, and CI's per-commit build is the `base` flavor while the download is
`dev`. Making that claim true is measured rather than asserted — see
[`PLAN.html`](PLAN.html) P6-9. Building it yourself takes about thirty-five
minutes, because it compiles a cross toolchain, a kernel and a userland:

```sh
bash dev/install-build-deps.sh     # compiler, Buildroot prerequisites, pinned Go
make cli
make image FLAVOR=dev              # or ARCH=x86_64, FLAVOR=base
```

Either way the image carries an `image.json` manifest recording its arch,
flavor, the SHA-256 of both artifacts and the pinned Buildroot and Linux
versions. The sandbox reads it and refuses to boot if it does not match what you
asked for, so `--image dev` can never quietly run something else — the flavor in
your audit trail is a checked fact, not a label you typed.

Release artifacts are checksummed but **not yet signed** — that is P4-3. If you
need to know who built the bytes, build them yourself.

## Attaching an agent

The sandbox is a toolbox, not a computer. The shortest path is to let `kelyfos`
own the agent's lifetime:

```sh
kelyfos run --workspace . --allow github.com -- claude
```

That boots a sandbox, runs your agent with `KELYFOS_SANDBOX` set so its tools
attach to that machine, and tears everything down when the agent exits —
`kelyfos` exits with the agent's own status, so it composes in a script.

There are two doors, and which one a client wants depends on who owns the
sandbox's lifetime. `kelyfos serve-mcp` is the outward one: the client has no
sandbox yet, and the tools are for getting one. `kelyfos mcp` is the inward
bridge to a sandbox that already exists.

A client wants `serve-mcp`, and it must be told where the policy is —
`--policy <path>`, absolutely, because the working directory a client launches
from is the client's and not yours, and a server that finds no policy runs with
no ceiling at all:

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

This repository's own [`.mcp.json`](.mcp.json) runs
[`dev/mcp-server.sh`](dev/mcp-server.sh) instead of naming a binary directly,
because the macOS form has to cross into the Lima layer — `limactl shell
kelyfos-dev -- <abs path> serve-mcp --policy <abs path>` — and a VM name and an
absolute path do not belong in a file a Linux contributor also checks out. The
script picks the right form for the machine it runs on and says what is wrong
when it cannot.

Writing that file by hand is what `kelyfos connect <client>` is for; until it
ships, [`docs/integrating.md`](docs/integrating.md) has the per-client shapes.

The agent then sees six tools — `exec`, `read_file`, `write_file`, `list_dir`,
`upload`, `download` — and nothing else. In a team it sees the team tools too, and a
`[[plugin]]` adds its own namespaced ones — and nothing else still.

## Policy travels with the project

Commit a `kelyfos.toml` the way you commit a `.devcontainer`, and bare
`kelyfos run` picks it up:

```toml
[sandbox]
image     = "dev"
allow     = ["github.com", "pypi.org"]
secrets   = ["GITHUB_TOKEN@api.github.com"]   # names only — never values
workspace = "."

[resources]                 # hard ceilings: a flag may ask for less, never more
cpus        = 2             # cores the guest sees
cpu_quota   = "150%"        # ...but at most 1.5 cores' worth of host CPU time
mem         = "2G"
disk        = "4G"          # ceiling on the packed /work image, refused before boot
scratch     = "512M"        # everything written outside /work
net_mbps_rx = 50
disk_mbps   = 100
max_runtime = "30m"
idle_timeout = "5m"         # no tool call and no traffic for that long ends it
```

`[resources]` are limits, not defaults — `--cpus 8` against `cpus = 2` refuses
at boot and names the line it came from, rather than quietly clamping.

Every one of them but `scratch` is enforced on the **host**: KVM machine config,
a cgroup v2 `cpu.max`, Firecracker's own token-bucket rate limiters, device sizes
and a host timer. The guest runs untrusted code and is never asked to police
itself — `scratch` is the one exception and is named as one: it is a `size=` the
guest's own kernel applies to its tmpfs, bounded underneath by the `mem` the VM
was built with, which is enforced on the host. Much the same is true of the
receipt: a `kelyfos run` session, and every agent in a team, ends with a
`resource.summary` event recording what it consumed beside what it was allowed,
measured from counters the kernel keeps about the VMM process. Sandboxes created
through `serve-mcp`, `fork`, `snapshot restore` and the E2B shim do not carry one
yet. `kelyfos watch` shows the same figures live. See [`docs/resources.md`](docs/resources.md), and
`bash dev/prove-caps.sh` to watch each cap refuse to budge.

## Agent teams

Several sandboxes on one host, with the paths between them written down. A
`[team]` section declares the agents and the edges; `kelyfos team up` boots the
graph. Docker-compose for agent teams — master/workers, a pipeline, a mesh, or
islands: the edge list *is* the topology.

```toml
[team]
name = "suppliers"
  [team.resources]
  cpu_quota = "200%"        # two cores' worth, for all of them together

[[team.agent]]
name = "master"
allow = ["example.com"]     # the only agent that may reach the network

[[team.agent]]
name  = "worker"
count = 4                   # four workers, no egress at all

[[team.edge]]
from = "master"
to   = "worker-*"           # a star: no worker may reach another worker
```

**No guest ever has a network path to another guest.** Every inter-agent message
travels the host broker over the existing vsock channels, is checked against the
edge list, and lands in the audit record — including the ones it refused. The
guest sees seven more MCP tools: `team_send`, `team_recv`, `team_ask`,
`team_reply`, `team_peers`, `team_store_get`, `team_store_put` — plus a
`team_spawn` shown only to an agent whose policy granted a spawn budget.

A team is **one session**, so `kelyfos log --verify` over it verifies the whole
team and says which agents it covered, `kelyfos verify team.html` lets whoever
you send the export to do the same, and `kelyfos log --export team.html`
draws one lane per agent with the message flow between them. `kelyfos watch`
shows the same shape live.

The first `team up` of a given shape boots every agent cold and builds a fork
template in the background; a later one forks the agents that have no egress and no
workspace of their own, where two or more share a shape, from that template in
tens of milliseconds. An agent with egress is always cold-booted — a
fork cannot carry a network identity. `kelyfos team ps` says which path each
machine took.

[`docs/teams.md`](docs/teams.md) is the full account.

## What else it does

| | |
| --- | --- |
| `kelyfos snapshot save\|restore` | freeze a prepared machine, bring it back in ~49 ms |
| `kelyfos fork -n 4` | four divergent copies of one snapshot, sharing its memory image |
| `kelyfos run --workspace ./dir` | your files at `/work`, written back on clean shutdown |
| `kelyfos log --export report.html` | a self-contained session report, carrying the record it was rendered from |
| `kelyfos verify report.html` | re-runs the chain over that record: offline, no key, no network |
| `kelyfos watch` | a live view, one lane per agent when it is a team |
| `kelyfos team up\|ps\|down` | boot a declared team, see it, stop it |
| `kelyfos serve-mcp` | [KelyfOS as an MCP server](docs/mcp-surface.md): any client gets sandboxes, files, snapshots, forks and teams as tools |
| `[[plugin]]` in `kelyfos.toml` | an MCP server of your own, running inside the guest, its tools namespaced into the agent's session |
| `kelyfos shim` | an [E2B-compatible subset](docs/e2b-shim.md) for existing SDK code |
| `kelyfos bench` | reproducible boot and restore timings |
| `kelyfos run --max-runtime 30m` | a wall-clock budget; expiry is SIGTERM, grace, sync-back, exit 124 |

And the parts that make it a thing you reach for rather than tolerate (v0.8):

| | |
| --- | --- |
| `kelyfos pause --as <name>` / `resume` | stop for the day and pick up the *same machine* — its memory, its scratch, its half-finished thing — under the policy it was frozen with |
| `kelyfos diff` / `run --review` | what the agent changed, and a yes before any of it reaches your directory |
| `kelyfos shell` | a real terminal inside the sandbox: job control, line editing, resize. The record always says one was opened and how it ended; what was typed and shown needs `--transcript` |
| `kelyfos run -p 8080:80` | reach a server inside the sandbox. Over vsock, so the firewall is untouched and it works with no network at all |
| `kelyfos runs` / `rerun <id>` | what has run here, and run one again under its own frozen policy |
| every refusal | names the fix: `add allow = ["api.stripe.com"] to kelyfos.toml, or rerun with --allow api.stripe.com` |
| `--notify` | a desktop notification when a run finishes, is blocked, times out, or is waiting for your answer |

## Documentation

| | |
| --- | --- |
| [`docs/README.md`](docs/README.md) | the entry map: what each document is, and where it is thin |
| [`llms.txt`](llms.txt) · [`llms-full.txt`](llms-full.txt) | for machine readers: an index per the llmstxt.org spec, and the whole set in one file, whose current size `llms.txt` states |
| [`docs/reference/`](docs/reference/) | every command, flag, toml key, MCP tool, event and exit code — generated from the source |
| [`PLAN.html`](PLAN.html) · [`PLAN-FEATURES.html`](PLAN-FEATURES.html) | the living plan — every decision and the full progress log, phases then epics |
| [`docs/cookbook.md`](docs/cookbook.md) | fourteen recipes that work: run one, allowlist a domain, fork, build a team, point a client at it, write a plugin, verify the log, pause and resume, review a diff, forward a port |
| [`docs/integrating.md`](docs/integrating.md) | building on it: the four ways in, orchestrator patterns, common mistakes |
| [`docs/mcp-surface.md`](docs/mcp-surface.md) | MCP in both directions: `serve-mcp` as a tool for any client, `[[plugin]]` servers inside the guest |
| [`docs/threat-model.md`](docs/threat-model.md) | what is defended, and what is not |
| [`docs/protocol.md`](docs/protocol.md) | the host/guest wire protocol |
| [`docs/events.md`](docs/events.md) | the audit event schema |
| [`docs/networking.md`](docs/networking.md) | egress design and the nftables rules |
| [`docs/resources.md`](docs/resources.md) | resource limits: units, precedence, what enforces what |
| [`docs/teams.md`](docs/teams.md) | agent teams: the schema, the broker, the store, the budget |
| [`docs/e2b-shim.md`](docs/e2b-shim.md) | the E2B compatibility subset |

## The numbers, and where they came from

Every figure above is measured on the bare-KVM reference — a stock
`ubuntu-latest` GitHub runner with KVM — by `make bench`, which is a workflow in
this repository. Local numbers on a Mac are 6–8× slower because of nested
virtualisation and are never the published ones.

Boot was 123 ms and restore 37 ms at v0.8. The jailer and the guest-profile probe
sit on the boot path and cost about 12 ms each way; the VMM's filter check is
read after boot-to-ready has been taken and is not in the number. Both were
re-measured across that change rather than assumed through it. The
targets — ≤ 300 ms cold, ≤ 100 ms restore — still hold with room. The team
figures replace 366 ms and 215 ms from before the guest kernel moved to the
6.12 LTS line, measured the same way on the same five-agent graph.

The five-agent number is the graph in `dev/demo-team.toml`: 412 ms with all five
booting cold, 286 ms once a fork template is cached. The master boots cold either
way, because a fork cannot carry a network identity.

## Security

Every release before v0.9 said **"not hardened yet"**, and it was true: KelyfOS
relied on the boundary Firecracker gives it and added nothing of its own around
the VMM process or around what a compromised agent could reach inside its guest.
Both layers exist now. Here is what that does and does not mean.

One of them was incomplete until v1.0, and the sentence above was true of the
guest and not of the host. An external audit found that the **workspace block
device** — which the guest writes and the host reads back — let a guest-authored
directory entry decide where the host wrote, and the trust-boundary table did not
list that surface at all. It is closed and listed now; the row below is what
closed it.

**What is enforced.**

| | |
| --- | --- |
| the boundary | a Firecracker microVM: a separate kernel, a hardware boundary. This was always the case and is still the thing that matters most. |
| around the VMM | the jailer: a chroot holding only this sandbox's files, a dropped uid, `no_new_privs`, only the device nodes it needs, and the run's cgroup when the policy set a quota. Every entry point, or none — `run`, `team up`, `fork`, `snapshot restore`, `serve-mcp` and the shim all go through one refusal. |
| the VMM's syscalls | Firecracker's own seccomp filter, **read out of `/proc` on every one of its threads** at boot rather than assumed from the absence of a flag. A VMM without it is refused, not run. [`docs/host-seccomp.md`](docs/host-seccomp.md) lists every syscall it permits, read back out of the running kernel. |
| inside the guest | every process the supervisor spawns — `exec`, a plugin, the shell — is confined by Landlock (writes only `/work`, `/tmp`, `/run`, `$HOME`, `/dev/pts` and `/dev/shm`, plus seven named device nodes) and a seccomp refusal list of 28 syscalls. Per flavor; [`docs/reference/profiles.md`](docs/reference/profiles.md) is generated from the code that enforces it. |
| the network | no interface at all without `--allow`; then deny-all plus a hostname allowlist, with credentials attached by the host's proxy so the value never exists inside the guest. |
| the workspace disk | the guest writes that filesystem, so the host reads it back the way it reads anything hostile: every entry validated and the image refused whole if one is a name the host cannot use, and the extraction written through `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` so a name that got past the check still cannot leave the tree. Guest-chosen modes do not survive onto your filesystem. |
| the record | hash-chained, written by the host, and it names which walls were around each machine — so a transcript cannot make an unconfined run look like a confined one. |

**What is not.** None of this is a claim to be a multi-tenant sandbox for
hostile code; it is a single-host developer tool (D1).

- **An agent is still root inside its own guest**, and always was. The profile
  narrows what root can ask the kernel for; it does not make the kernel smaller.
- **The chroot is not the boundary.** The VM is. The jailer makes an escape from
  Firecracker far less useful; anyone who tells you a chroot is a security
  boundary is selling something.
- **The VMM drops to you, not to a dedicated account** (D29), so a uid it shares
  with your shell is a uid that could signal or `ptrace` your other processes.
  A service account closes that and costs a setup step.
- **Side channels** — timing, cache, speculative execution — are untouched.
  KelyfOS inherits Firecracker's position and adds nothing.
- **The supply chain** is untouched: reproducible builds, signed images and an
  SBOM are P4-3 and are not done. A hardened runtime built from an unverified
  toolchain is a locked door in a wall nobody measured.
- **Anything your policy permits.** A sandbox allowed to reach `api.github.com`
  with a token bound to it can do whatever that token can do.

[`docs/threat-model.md`](docs/threat-model.md) is the long version, including the
trade-off TLS termination represents. [`docs/hardening.md`](docs/hardening.md) is
the specification these layers were built against, and its §5 is a longer list of
what remains reachable.

Report vulnerabilities privately — [`SECURITY.md`](SECURITY.md) has the channel,
and says which findings are in scope and which are documented design decisions.

## Building on it

The guest toolchain — Buildroot, the kernel, Firecracker and Go — is pinned in
[`versions.mk`](versions.mk), and Go modules in `go.mod`. The host build packages
are not pinned, and reproducible builds are still open.
Contributions need a DCO `Signed-off-by` line. The non-goals in `PLAN.html`
section 2 are hard boundaries — no orchestrator, no control plane, no hosted
service.

## License

Apache-2.0.
