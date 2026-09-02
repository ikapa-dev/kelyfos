# KelyfOS

**A sandbox an AI agent can only reach through tools.**

[![CI](https://github.com/ikapa-dev/kelyfos/actions/workflows/ci.yml/badge.svg)](https://github.com/ikapa-dev/kelyfos/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ikapa-dev/kelyfos)](https://github.com/ikapa-dev/kelyfos/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

KelyfOS is a minimal guest OS for [Firecracker](https://firecracker-microvm.github.io/) microVMs, built for running AI agents. The guest has no shell login, no SSH and no network by default. It exposes itself to an agent as a handful of MCP tools, keeps your credentials on the host, and writes an audit record the guest cannot edit.

![KelyfOS in a terminal](docs/media/demo.gif)

- **Egress is off, not filtered.** Without `--allow` the VM has no network interface at all.
- **Secrets never enter the guest.** `--secret GITHUB_TOKEN@api.github.com` keeps the value on the host; a proxy attaches it on the way out.
- **The record is written by the host.** Hash-chained, exportable, and verifiable offline with `kelyfos verify report.html`.
- **Fast.** Cold boot to ready in ~110 ms, snapshot restore in ~40 ms, a five-agent team in about half a second.

> An agent is still root inside its own guest, and the VM is the boundary. Read [`docs/threat-model.md`](docs/threat-model.md) before trusting KelyfOS with anything.

## Requirements

| Platform | Support |
| --- | --- |
| Linux with `/dev/kvm` | Native. Nothing else needed. |
| macOS 15+ on Apple M3 or newer | Via a Lima VM that `kelyfos doctor --setup` provisions for you. Needs nested virtualisation, which older chips lack. |
| Windows | WSL2, planned. See [`docs/compatibility.md`](docs/compatibility.md). |

## Quickstart

```sh
git clone https://github.com/ikapa-dev/kelyfos && cd KelyfOS
```

**macOS only:** set up the Linux layer first, then run everything else inside it.

```sh
brew install lima
kelyfos doctor --setup        # provisions and starts the Lima VM
limactl shell kelyfos-dev     # the commands below run in here
```

The macOS CLI is a download from the [latest release](https://github.com/ikapa-dev/kelyfos/releases/latest) (`kelyfos-darwin-<arch>`). It is unsigned, so after checking `SHA256SUMS` clear the quarantine flag with `xattr -d com.apple.quarantine ./kelyfos`.

**Install** the VMM, the CLI and the prebuilt guest image. Each script verifies its download against the published checksum before writing anything.

```sh
bash dev/install-firecracker.sh    # Firecracker and its jailer
bash dev/install-kelyfos.sh        # the static CLI, into ./bin
bash dev/fetch-image.sh            # the guest image, into ~/.cache/kelyfos

# The jailer needs root. Grant it for the jailer alone:
echo "$USER ALL=(root) NOPASSWD: $(command -v jailer)" | sudo tee /etc/sudoers.d/kelyfos-jailer
sudo chmod 0440 /etc/sudoers.d/kelyfos-jailer

./bin/kelyfos doctor               # checks everything and prints the fix for anything missing
```

**Run something:**

```sh
./bin/kelyfos run --image dev --allow github.com &
./bin/kelyfos exec "uname -a"
./bin/kelyfos exec "git clone --depth 1 https://github.com/kelseyhightower/nocode /work/nc"
./bin/kelyfos exec "curl -sS https://example.com"    # refused: not in the allowlist
./bin/kelyfos log --verify
```

`kelyfos run --no-jail` works without the sudoers grant. It says what is not enforced on every run, and so does the session record.

## Attaching an agent

The shortest path is to let `kelyfos` own the agent's lifetime. This boots a sandbox, runs the agent with its tools attached to that machine, and tears everything down when the agent exits.

```sh
kelyfos run --workspace . --allow github.com -- claude
```

Inside the sandbox the agent sees six tools: `exec`, `read_file`, `write_file`, `list_dir`, `upload` and `download`. In a team it also sees the team tools, and a `[[plugin]]` can add its own.

To give an MCP client the ability to create sandboxes itself, point it at `kelyfos serve-mcp`:

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

`kelyfos connect <client>` writes that file for you in the client's own format, and `--check` completes a real MCP handshake against it. See [`docs/integrating.md`](docs/integrating.md) for the per-client shapes and [`docs/reference/tools.md`](docs/reference/tools.md) for every tool.

## Policy file

Commit a `kelyfos.toml` next to your code and bare `kelyfos run` picks it up.

```toml
[sandbox]
image     = "dev"
allow     = ["github.com", "pypi.org"]
secrets   = ["GITHUB_TOKEN@api.github.com"]   # names only, never values
workspace = "."

[resources]                 # hard ceilings: a flag may ask for less, never more
cpus         = 2
cpu_quota    = "150%"
mem          = "2G"
disk         = "4G"
scratch      = "512M"
net_mbps_rx  = 50
disk_mbps    = 100
max_runtime  = "30m"
idle_timeout = "5m"
```

Limits are enforced on the host, not by the guest. Asking for more than the policy allows is refused at boot with the line it came from. See [`docs/resources.md`](docs/resources.md) and [`docs/reference/config.md`](docs/reference/config.md).

## Agent teams

Several sandboxes on one host, with the allowed message paths declared up front. Think docker-compose for agents.

```toml
[team]
name = "suppliers"

[[team.agent]]
name  = "master"
allow = ["example.com"]     # the only agent with network access

[[team.agent]]
name  = "worker"
count = 4                   # four workers, no egress

[[team.edge]]
from = "master"
to   = "worker-*"           # a star: workers cannot reach each other
```

```sh
kelyfos team up
kelyfos team ps
kelyfos watch               # one lane per agent, live
kelyfos team down
```

No guest ever has a network path to another guest. Every message goes through the host broker, is checked against the edge list, and lands in the audit record. See [`docs/teams.md`](docs/teams.md).

## Commands

| Command | What it does |
| --- | --- |
| `kelyfos doctor` | Check the machine and print the exact fix for anything missing |
| `kelyfos run` / `exec` | Boot a sandbox and run commands in it |
| `kelyfos shell` | A real terminal inside the sandbox |
| `kelyfos snapshot save\|restore` | Freeze a prepared machine and bring it back in ~40 ms |
| `kelyfos fork -n 4` | Four divergent copies of one snapshot |
| `kelyfos pause --as <name>` / `resume` | Stop for the day and pick up the same machine later |
| `kelyfos diff` / `run --review` | See what the agent changed, and approve before it reaches your directory |
| `kelyfos run -p 8080:80` | Reach a server inside the sandbox over vsock, no network needed |
| `kelyfos log --verify` / `--export report.html` | Verify the audit chain, or export a self-contained report |
| `kelyfos verify report.html` | Verify an exported report offline, no key, no guest |
| `kelyfos team up\|ps\|down` | Boot, inspect and stop a declared team |
| `kelyfos serve-mcp` | Expose sandboxes, snapshots, forks and teams as MCP tools |
| `kelyfos connect <client>` | Write a client's MCP configuration |
| `kelyfos shim` | An [E2B-compatible subset](docs/e2b-shim.md) for existing SDK code |
| `kelyfos bench` | Reproducible boot and restore timings |

The full reference, generated from the source, is in [`docs/reference/`](docs/reference/).

## Security

| Layer | What is enforced |
| --- | --- |
| The boundary | A Firecracker microVM: a separate kernel, a hardware boundary. |
| Around the VMM | Firecracker's jailer: a chroot, a dropped uid, `no_new_privs`, only the devices it needs, plus Firecracker's own seccomp filter, verified present at boot. |
| Inside the guest | Every spawned process is confined by Landlock and a seccomp policy, generated from the code that enforces it. |
| The network | No interface without `--allow`. Then deny-all plus a hostname allowlist, with secrets attached by the host proxy. |
| The workspace disk | Read back as hostile input: every entry validated, extraction through `os.Root`, no escape via symlinks or names. |
| The record | Hash-chained, written by the host, naming which walls were around each machine. |

What is **not** covered: KelyfOS is a single-host developer tool, not a multi-tenant sandbox for hostile code. An agent is root inside its guest. The VMM runs as your user, not a service account. Side channels are inherited from Firecracker. Anything your policy permits, the agent can do.

[`docs/threat-model.md`](docs/threat-model.md) is the full account. Report vulnerabilities privately via [`SECURITY.md`](SECURITY.md).

## Performance

Measured by workflows in this repository on a stock `ubuntu-latest` GitHub runner with KVM, never by hand, and re-measured after each release. Numbers on a Mac are 6–8× slower because of nested virtualisation.

| Figure | Result | Measured by |
| --- | --- | --- |
| Cold boot to ready | 111 ms median, 10 runs (103–120 ms) | [`bench.yml`](.github/workflows/bench.yml), `347a402`, 2026-09-02 |
| Snapshot restore | 40 ms median, 10 runs (37–44 ms) | [`bench.yml`](.github/workflows/bench.yml), `347a402`, 2026-09-02 |
| Five-agent team up | 510 ms cold, 391 ms with forked workers, single runs | [`caps.yml`](.github/workflows/caps.yml), `347a402`, 2026-09-02 |

Two runs of the same v1.3.0 tree on the same day gave 122 and 152 ms, so treat a single run as ±15%: the runner pool varies more than the code does. The bars, ≤ 300 ms cold and ≤ 100 ms restore, hold with room. v1.3.0's channel handshake had put up to a probe interval on the boot path; `347a402` removed it.

## Building from source

Releases are built by [`release.yml`](.github/workflows/release.yml) from the tag's own commit, with a signed provenance attestation and an SBOM per architecture. Verify one with `gh attestation verify kelyfos-linux-x86_64 --repo ikapa-dev/kelyfos`. Reproducibility is measured per artifact by [`repro-check.yml`](.github/workflows/repro-check.yml).

Building the guest image yourself compiles a cross toolchain, a kernel and a userland, and takes about 35 minutes.

```sh
bash dev/install-build-deps.sh     # compiler, Buildroot prerequisites, pinned Go
make cli
make image FLAVOR=dev              # or ARCH=x86_64, FLAVOR=base
```

Toolchain versions are pinned in [`versions.mk`](versions.mk).

## Documentation

| | |
| --- | --- |
| [`docs/README.md`](docs/README.md) | The map of every document and where each is thin |
| [`docs/cookbook.md`](docs/cookbook.md) | Recipes that CI runs on a real machine |
| [`docs/integrating.md`](docs/integrating.md) | Building on KelyfOS: the ways in, orchestrator patterns, common mistakes |
| [`docs/mcp-surface.md`](docs/mcp-surface.md) | MCP in both directions: `serve-mcp` and `[[plugin]]` |
| [`docs/threat-model.md`](docs/threat-model.md) | What is defended and what is not |
| [`docs/compatibility.md`](docs/compatibility.md) | What is stable from v1.0 and what may change |
| [`docs/decisions.md`](docs/decisions.md) | Every irreversible choice and why, cited from the source as `D<n>` |
| [`CHANGELOG.md`](CHANGELOG.md) · [`docs/upgrading.md`](docs/upgrading.md) | What changed and what to do about it |
| [`llms.txt`](llms.txt) · [`llms-full.txt`](llms-full.txt) | The whole set for machine readers |

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Every change follows its verification protocol, and commits need a DCO `Signed-off-by` line. KelyfOS deliberately ships no orchestrator, no control plane and no hosted service.

## License

[Apache-2.0](LICENSE). KelyfOS, from κέλυφος (*kélyfos*), "shell": the guest wrapped around the agent.
