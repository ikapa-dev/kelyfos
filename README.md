# KelyfOS

**A sandbox an AI agent can only reach through tools.**

KelyfOS is a minimal guest operating system for Firecracker microVMs. The guest
has no shell login, no SSH and no network by default — it exposes itself to an
agent as a handful of MCP tools, keeps your credentials outside the box
entirely, and writes down everything that happened in a record the guest cannot
edit.

![KelyfOS in a terminal](docs/media/demo.gif)

> **Status: v0.3, early development, building in the open.** Cold boot-to-ready
> is **90 ms** median and snapshot restore **29 ms** (10 runs each, x86_64 on a
> bare-KVM CI runner). **Not hardened yet** — read
> [`docs/threat-model.md`](docs/threat-model.md) before trusting it with
> anything.

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
  trail could write a flattering one, so it cannot write one at all.

## Quickstart

Firecracker needs Linux and KVM. On macOS that means a Lima VM; on Windows,
WSL2; on a Linux box with `/dev/kvm`, nothing.

```sh
git clone https://github.com/p4r4n0rm4l/KelyfOS && cd KelyfOS
```

On macOS, clone it somewhere under your home directory — that is what the Lima
VM mounts, and `limactl shell` keeps your working directory, so the commands
below just work.

Measured end to end — `git clone` to the first `kelyfos exec` output, on a
machine with no Lima VM, no image cache and no KelyfOS anything: **2 minutes 31 seconds on macOS, 9 seconds on a Linux/KVM box**.
Building the macOS Linux layer is 142 s of that — on Linux there is no such step. Measured against the published v0.3 release with Lima's image cache purged; the KelyfOS downloads themselves are 5 s of the total.

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
bash dev/install-firecracker.sh    # the VMM
bash dev/install-kelyfos.sh        # the CLI
bash dev/fetch-image.sh            # the guest image
./bin/kelyfos doctor
```

Each of those verifies what it downloaded against a published checksum before
installing it, and shows you doing so — a mismatch aborts with nothing written:

```
Fetching KelyfOS v0.3 image for x86_64 from p4r4n0rm4l/KelyfOS
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

`kelyfos doctor` is the thing to run first on any new machine: it checks eight
things and prints the exact fix for whatever is wrong, tailored to whether you
are on Lima, WSL2, bare Linux or macOS.

### Building it yourself

The downloads above are the same bytes the build produces — CI builds both
arches from source on every commit — but building takes about thirty-five
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

Under the hood, `kelyfos mcp` bridges any MCP client's standard streams to a
running sandbox; this repository ships a [`.mcp.json`](.mcp.json) that attaches
Claude Code:

```json
{ "mcpServers": { "kelyfos": { "command": "kelyfos", "args": ["mcp"] } } }
```

If the agent runs on macOS while the sandbox runs in the Lima layer, the bridge
speaks stdio, so `limactl` passes it through unchanged:

```json
{ "command": "limactl", "args": ["shell", "kelyfos-dev", "--", "kelyfos", "mcp"] }
```

The agent then sees six tools — `exec`, `read_file`, `write_file`, `list_dir`,
`upload`, `download` — and nothing else.

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
cpus = 2
mem  = "2G"
disk = "4G"
```

`[resources]` are limits, not defaults — `--cpus 8` against `cpus = 2` refuses
at boot and names the line it came from, rather than quietly clamping. See
[`docs/resources.md`](docs/resources.md).

## What else it does

| | |
| --- | --- |
| `kelyfos snapshot save\|restore` | freeze a prepared machine, bring it back in ~29 ms |
| `kelyfos fork -n 4` | four divergent copies of one snapshot, sharing its memory image |
| `kelyfos run --workspace ./dir` | your files at `/work`, written back on clean shutdown |
| `kelyfos log --export report.html` | a self-contained session report you can send to someone |
| `kelyfos watch` | a live view, built only from the audit record |
| `kelyfos shim` | an [E2B-compatible subset](docs/e2b-shim.md) for existing SDK code |
| `kelyfos bench` | reproducible boot and restore timings |

## Documentation

| | |
| --- | --- |
| [`PLAN.html`](PLAN.html) | the living plan, every decision and the full progress log |
| [`docs/threat-model.md`](docs/threat-model.md) | what is defended, and what is not |
| [`docs/protocol.md`](docs/protocol.md) | the host/guest wire protocol |
| [`docs/events.md`](docs/events.md) | the audit event schema |
| [`docs/networking.md`](docs/networking.md) | egress design and the nftables rules |
| [`docs/resources.md`](docs/resources.md) | resource limits: units, precedence, what enforces what |
| [`docs/e2b-shim.md`](docs/e2b-shim.md) | the E2B compatibility subset |

## Security

**Not hardened yet.** The Firecracker jailer (P4-1) and guest seccomp/Landlock
profiles (P4-2) are not done. The accurate description today is *isolation-first
architecture*. [`docs/threat-model.md`](docs/threat-model.md) is explicit about
what that means, including the trade-off TLS termination represents.

Report vulnerabilities privately — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Building on it

Everything is pinned in [`versions.mk`](versions.mk); nothing floats.
Contributions need a DCO `Signed-off-by` line. The non-goals in `PLAN.html`
section 2 are hard boundaries — no orchestrator, no control plane, no hosted
service.

## License

Apache-2.0.
