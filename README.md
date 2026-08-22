# KelyfOS

A minimal, agent-native guest operating system image for microVM sandboxes.

One command runs an AI agent inside a hardware-isolated VM with deny-all egress,
injected secrets, full audit replay, and millisecond forking.

> **Status: v0.1 — it boots.** Early development, building in the open — v0.3
> will be the first announced release. The guest boots and answers commands over
> vsock; egress policy, secrets and the audit log are Phase 2 work.
> Cold boot-to-ready is **103 ms median** (p95 125 ms, 10 runs, x86_64 on a
> bare-KVM CI runner).
> [`PLAN.html`](PLAN.html) is the living source of truth for scope, architecture,
> decisions and progress — read it first. The user-facing quickstart lands with
> the public launch (P3-7).

KelyfOS — from κέλυφος (*kélyfos*), "shell": the guest OS wrapped around the agent.

## What it is

Two artifacts and a CLI:

- **the image** — a stripped Linux kernel (virtio only, no modules) and a
  read-only rootfs with a tmpfs overlay, built with Buildroot for `aarch64` and
  `x86_64` from one pipeline;
- **the supervisor** — a single static Go binary running as PID 1 inside the
  guest, exposing the machine as MCP tools rather than a shell;
- **`kelyfos`** — the host CLI that boots Firecracker microVMs, bridges MCP to
  stdio, enforces deny-all egress with a domain allowlist, injects secrets at the
  proxy so they never enter the guest, and records every action to a
  hash-chained audit log.

## Repository layout

| Path | Contents |
| --- | --- |
| `PLAN.html` | Living plan, decision log and progress log. Start here. |
| `dev/` | Host setup for the Linux layer: Lima (macOS), WSL2 notes. |
| `image/` | Buildroot external tree and image flavors. |
| `supervisor/` | Guest PID 1 + MCP server (Go). |
| `host/` | `kelyfos` CLI, egress proxy, flight recorder (Go). |
| `shim/` | E2B-compatible REST subset (phase 3). |
| `docs/` | Protocol, events, networking and threat-model documents. |

## Building

Firecracker runs on Linux/KVM only. On macOS the Linux layer is a Lima VM:

```sh
limactl start --name kelyfos-dev dev/lima.yaml
limactl shell kelyfos-dev -- bash dev/install-firecracker.sh
limactl shell kelyfos-dev -- make
```

## Attaching an agent

KelyfOS exposes a running sandbox as MCP tools rather than as a shell. Any MCP
client can attach; `kelyfos mcp` bridges the client's standard streams to the
sandbox.

This repository ships a [`.mcp.json`](.mcp.json) that attaches Claude Code to a
running sandbox:

```json
{
  "mcpServers": {
    "kelyfos": {
      "command": "kelyfos",
      "args": ["mcp"]
    }
  }
}
```

If your agent runs on macOS while the sandbox runs in the Lima layer, the
command has to cross into the VM — the bridge speaks stdio, so `limactl` passes
it through unchanged:

```json
{ "command": "limactl", "args": ["shell", "kelyfos-dev", "--", "kelyfos", "mcp"] }
```

The bridge attaches to the only running sandbox, so start one first:

```sh
kelyfos run --image dev --allow github.com --secret GITHUB_TOKEN@api.github.com
```

The agent then sees six tools — `exec`, `read_file`, `write_file`, `list_dir`,
`upload`, `download` — and nothing else. It has no shell login, no SSH, and no
route to the network except the proxy. Whatever it does is in
`kelyfos log`, and `kelyfos log --verify` will tell you if that record has been
edited since.

## License

Apache-2.0. Contributions require a DCO `Signed-off-by` line — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
