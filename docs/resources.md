# Resource limits

How much machine the agent gets, who decides it, and what actually enforces it.

Everything here is enforced **on the host**. The guest runs untrusted code, so a
limit the guest applies to itself is advisory at best (F-D2) — the same reasoning
that puts the egress proxy on the host rather than a firewall inside the VM.

## The precedence model

Two places set limits, and they do not mean the same thing:

| | role |
| --- | --- |
| `[resources]` in `kelyfos.toml` | **hard ceilings.** The committed policy of the project. |
| CLI flags | **requests within those ceilings.** |

A flag may ask for less than its ceiling. A flag asking for **more** does not
win and does not get silently clamped — the sandbox refuses to boot, naming
both the ceiling and the file and line it came from:

```
$ kelyfos run --cpus 8
kelyfos: --cpus 8 exceeds the ceiling cpus = 2 set at ./kelyfos.toml:6
    lower the flag, or raise the ceiling in the policy file
```

Refusing beats clamping because clamping is a silent lie: the agent would run
with limits nobody asked for and the command line would still read `--cpus 8`.

> **This is a change from v0.3**, where `kelyfos.toml` supplied defaults and any
> explicit flag overrode them. That was the right default-shaped behaviour for a
> policy file that declared *preferences*; it is the wrong behaviour for one that
> declares *limits*. A policy you can override from the command line is not a
> limit, it is a suggestion. `[sandbox] vcpus` / `mem_mib` keep the old
> defaults-only meaning for compatibility (F-D10) — use `[resources]` for
> anything you actually want enforced.

With no `[resources]` section there are no ceilings, and flags behave exactly as
they did in v0.3.

## Units

| key | type | examples |
| --- | --- | --- |
| `cpus` | integer — whole cores the guest sees | `1`, `4` |
| `mem`, `disk`, `scratch` | human size, or a bare byte count | `512M`, `2G`, `1073741824` |
| `cpu_quota` | percentage of **one core's worth** of CPU time | `"50%"`, `"150%"` |
| `net_mbps_rx`, `net_mbps_tx` | megabits per second | `10` |
| `disk_iops` | operations per second | `500` |
| `disk_mbps` | megabytes per second | `50` |
| `max_runtime`, `idle_timeout` | duration | `"60s"`, `"30m"`, `"2h"` |

Sizes accept `K`, `M`, `G`, `T` and are powers of two: `1G` is 1073741824 bytes.
A bare number is bytes. The same grammar parses `--disk 2G` and `disk = "2G"`,
from the same function, so the flag and the file can never drift apart.

`cpu_quota` is **absolute, not relative to `cpus`**. `100%` is one core's worth
of CPU time per wall-clock second; `150%` is one and a half. It is not a
percentage of the cores the guest can see, and a quota above `cpus × 100%` is
simply unreachable.

## `cpus` and `cpu_quota` are different questions

This is the distinction most worth understanding, because the two look
interchangeable and are not:

- **`cpus` caps parallelism** — how many cores exist inside the VM. Four cores
  let four threads run at once. It says nothing about how much CPU time they get.
- **`cpu_quota` caps consumption** — how much host CPU time the VM may actually
  burn, whatever it does with its cores.

`cpus = 4` with `cpu_quota = "100%"` gives the guest four cores that together
never exceed one core's worth of work: parallel, but not fast. That combination
is usually what you want for an agent — build systems and test runners assume
several cores and behave badly with one, but you still do not want a runaway
loop eating your laptop.

## What enforces what

Every cap and the mechanism behind it. The mechanism matters: it tells you what
happens at the limit and how hard the limit is.

| cap | enforced by | at the limit |
| --- | --- | --- |
| `cpus` | KVM machine config (`vcpu_count`) | absolute — the cores do not exist |
| `mem` | KVM machine config (`mem_size_mib`) | absolute — the RAM does not exist; the guest OOM-kills (see E1-4) |
| `cpu_quota` | cgroup v2 `cpu.max` on the Firecracker process's own cgroup | throttled — work slows, nothing fails |
| `disk` | size of the packed workspace block device | `ENOSPC` on writes to `/work` |
| `scratch` | `size=` on the tmpfs backing the overlay upper layer | `ENOSPC` on writes outside `/work` |
| `net_mbps_rx` / `net_mbps_tx` | Firecracker token-bucket rate limiter on the network device | throttled |
| `disk_iops` / `disk_mbps` | Firecracker token-bucket rate limiter on the block devices | throttled |
| `max_runtime` / `idle_timeout` | host timer in `kelyfos run` | SIGTERM, grace, sync-back, teardown |

Two of these are absolute because they are hardware: a guest cannot allocate a
core or a byte of RAM that the VM was not built with. The throttles are soft by
nature — they make work slower, not impossible — and the two `ENOSPC` caps are
device sizes, which is why a full scratch is an error the guest sees rather than
a limit the host has to police.

`scratch` and `disk` are separate devices and separate budgets. `/work` is the
workspace block device sized by `disk`; everything else the guest writes lands on
the tmpfs overlay sized by `scratch`. Filling one does not affect the other.

`scratch` defaults to 50% of the **guest's** RAM — the Linux tmpfs default,
relative to `mem`, not to host memory. Stated here because it was previously
implied by inheriting the kernel default.

## What is live today

This document is the specification for the whole of resource governance, and
parts of it are still being built. The parser refuses a key it cannot yet
enforce rather than accepting it and doing nothing — a policy file whose limits
are silently inert is the worst possible outcome for a file whose entire job is
limits.

| key | status |
| --- | --- |
| `cpus`, `mem`, `disk`, `cpu_quota` | **enforced**, including the ceiling behaviour above |
| `net_mbps_rx`, `net_mbps_tx`, `disk_iops`, `disk_mbps` | specified; land with the rate limiters (E1-3) |
| `scratch` | specified; lands with the tmpfs sizing (E1-5) |
| `max_runtime`, `idle_timeout` | specified; land with the time budgets (E1-6) |

Using one of the not-yet-enforced keys is an error that says so and names the
task, so nobody discovers the gap by watching a limit fail to hold.

### How the quota is applied

`cpu_quota` needs the Firecracker process to live in a cgroup with `cpu.max`
set, and how KelyfOS gets one depends on the machine:

- **Under a systemd user session** — the usual case on a developer's box — the
  cgroup is requested through `systemd-run --user --scope`. This is not a
  convenience: a login session's own cgroup is root-owned, and moving a process
  into the subtree systemd delegates to you requires write access to the
  *common ancestor* of both, which is also root's. The user manager is the one
  component that legitimately holds that privilege.
- **As root, or where the cgroup is genuinely delegated** (containers, CI),
  KelyfOS creates the cgroup itself and places the process in it at clone time,
  so there is no window in which the process runs uncapped.

Either way the percentage is translated in the CLI, and the resulting `cpu.max`
is **read back and checked** after launch. If the quota did not land, the
sandbox refuses to start rather than running unlimited while claiming a cap.
If neither path is available, `--cpu-quota` fails with the reason.

## Example

```toml
[sandbox]
image = "dev"
allow = ["github.com"]

[resources]
cpus        = 4          # four cores exist inside the VM
cpu_quota   = "150%"     # ...but together they burn at most 1.5 cores' worth
mem         = "2G"
disk        = "4G"       # /work device size
scratch     = "512M"     # everything written outside /work
net_mbps_rx = 50
max_runtime = "30m"
```

An agent given this can compile in parallel, cannot pin the machine, cannot fill
the disk, and cannot run past half an hour.

## Seeing the limits hold

`kelyfos watch` shows live usage against each cap, and every session ends with a
`resource.summary` event in the flight recorder — peak RSS, CPU-seconds, bytes
in and out, disk bytes written — which `kelyfos log --export` renders as a usage
receipt. Limits that fire leave their own audit events: `resource.oom` when the
guest OOM-killer runs, `resource.timeout` naming which budget expired.

That is the point of enforcing host-side: the record of what the sandbox
consumed is written by the same side that imposed the limits, so it is worth
something.
