# KelyfOS

A minimal, agent-native guest operating system image for microVM sandboxes.

One command runs an AI agent inside a hardware-isolated VM with deny-all egress,
injected secrets, full audit replay, and millisecond forking.

> **Status: pre-v0.1, under construction.** Early development, building in the
> open — v0.3 will be the first announced release. Nothing here works end to end yet.
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

## License

Apache-2.0. Contributions require a DCO `Signed-off-by` line — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
