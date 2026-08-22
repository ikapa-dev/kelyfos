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

**On macOS — a Linux layer with nested virtualisation** (skip on Linux):

```sh
brew install lima
limactl start --name kelyfos-dev dev/lima.yaml
limactl shell kelyfos-dev          # everything below runs in here
```

**Then, on Linux or inside that shell:**

```sh
bash dev/install-firecracker.sh    # pinned build, checksum-verified
make cli                           # the host CLI, ~20s
./bin/kelyfos doctor               # eight checks, each with its exact fix

make fetch-image                   # prebuilt guest image for your arch
```

`fetch-image` checks what it downloaded against the release's published
`SHA256SUMS` before anything reaches your cache, and shows you it doing so — a
mismatch aborts with nothing installed:

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

**Run something in it:**

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

### Building the image yourself

`make fetch-image` downloads the release artifacts and verifies them against a
published `SHA256SUMS`. They are the same bytes `make image` produces — CI
builds both arches from source on every commit — but building takes about
thirty-five minutes because it compiles a cross toolchain, a kernel and a
userland:

```sh
bash dev/install-build-deps.sh
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

The sandbox is a toolbox, not a computer. `kelyfos mcp` bridges any MCP client's
standard streams to a running sandbox; this repository ships a
[`.mcp.json`](.mcp.json) that attaches Claude Code:

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
vcpus     = 2
mem_mib   = 2048
```

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
