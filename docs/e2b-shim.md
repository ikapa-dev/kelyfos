# The E2B-compatible shim

**Status:** best-effort subset, v0.x. Implemented at P3-4; brought under the
project's policy and the flight recorder at F-D33.

KelyfOS is not an E2B clone and this is not a reimplementation of their product.
It exists for one reason: someone with code already written against the E2B SDK
should be able to point it at a self-hosted KelyfOS box and see it work, without
rewriting anything first. Adoption, not parity.

## Running it

```sh
kelyfos shim --addr 127.0.0.1:3000 --image dev
```

Then point the SDK at it:

```sh
export E2B_API_KEY=e2b_0000000000000000000000000000000000000000
export E2B_API_URL=http://127.0.0.1:3000
export E2B_SANDBOX_URL=http://127.0.0.1:3000
```

The key is not checked by anything — the shim has no accounts and no billing —
but the SDK validates its *shape* client-side before sending it anywhere, so it
has to look like an E2B key.

```python
from e2b import Sandbox

sbx = Sandbox.create()
sbx.files.write("/work/hello.txt", "hello from the E2B SDK\n")
print(sbx.files.read("/work/hello.txt"))
sbx.kill()
```

Every `Sandbox.create()` boots a real Firecracker microVM with the same
guarantees as any other KelyfOS sandbox: read-only root, no login, no egress
unless the policy grants it, the project's resource caps, and a flight recorder
of its own.

**The policy file applies here.** The shim reads `kelyfos.toml` the way
`kelyfos run` does — with four gaps, stated here rather than discovered:
`cpus`, `mem`, `cpu_quota`, `scratch` and the four I/O rates cap every sandbox
it creates, and `allow` and `secrets` decide what those sandboxes may reach, but
the **time budgets `max_runtime` and `idle_timeout` are not applied here**. A
shim sandbox lives until it is killed or the shim stops. `workspace`,
`[[plugin]]` and `[[forward]]` are not read here either: a shim sandbox gets no
workspace device — `/work` is the guest's own and nothing written there comes
back to the host — no plugin device, so the guest advertises none of the
project's plugin tools, and no forwarded ports. `serve-mcp` announces its
workspace gap on startup (F-D49); the shim announces none of the four.

The flags on `kelyfos shim` are the operator's, not the client's, and there is
no request parameter that widens any of it — an SDK client cannot ask for a
bigger machine or another domain, which is the point of the door being in the
wall rather than beside it (F-D5, F-D33).

**Every sandbox gets its own record.** `session.start` when it is created,
`session.ready` when the guest answers, a `file.write` with `via: shim` for
every file the SDK writes, an `egress.attempt` for every connection it tries,
and `session.end` when it is killed. `kelyfos log --list` shows them and
`kelyfos log --verify` checks the chain, exactly as for a sandbox `kelyfos run`
started.

**By default the shim does not authenticate anybody.** While it is running, any
process on the machine that can reach its port can boot sandboxes, kill them, and
read and write files inside them. `--addr` binds loopback by default and is the
only thing between it and the network. That is a property of being an
unauthenticated local API, not an oversight, and
[`docs/threat-model.md`](threat-model.md) says so.

**Set `KELYFOS_SHIM_TOKEN` and it does.** Every route then requires
`Authorization: Bearer <token>`, compared in constant time, and answers `401`
without it. The default is unchanged because the shim is a developer's stand-in
for a hosted API on a machine you already trust; what was missing until v1.0 was
the *choice*, since there was no way to require a credential at all.

**And there is a ceiling on how many sandboxes it will hold: 16.** Each one is a
microVM — memory, a disk image, a TAP device, a process — and the policy carried
a ceiling for each of those per machine and none for the number of machines, so
the arithmetic was whatever a caller asked for times whatever the policy allowed.
A caller at the limit deletes one first, which is a request it already has.

## What is implemented

| Area | Endpoint | Notes |
| --- | --- | --- |
| Create | `POST /sandboxes` | Boots a microVM and waits for it to be ready. A `templateID` in the request is echoed back in the response but never honoured — every sandbox runs the image `--image` or the policy set. |
| List | `GET /sandboxes` | Only sandboxes this shim created. |
| Kill | `DELETE /sandboxes/{id}` | Stops it and cleans up. |
| Health | `GET /health` | The shim's own liveness: always `204`, with no sandbox consulted, so it answers before any sandbox exists. |
| Read file | `GET /files?path=…` | Binary-safe. |
| Write file | `POST /files?path=…` | Multipart or octet-stream, binary-safe. The body is read to a ceiling of 64 MiB and the rest is dropped without an error — a larger upload still answers `200`, and both the guest's file and the `file.write` event describe the first 64 MiB. |

The shim only manages sandboxes it created. It will not adopt one started by
`kelyfos run` — an SDK call ending someone's interactive session because the
lifecycle said so is a surprise worth avoiding.

Addressing is by URL rather than by id, which is how E2B reaches envd, so the
shim serves one sandbox at a time and says so plainly when more than one exists.

## What is not implemented, and why

**Command execution.** `sbx.commands.run()` and the process API are not
supported. In the current SDK they do not use REST at all: they use Connect RPC
with protobuf, including server streaming. That is a different protocol stack
from the endpoints above, and implementing it would mean vendoring E2B's
protobuf definitions and tracking their schema — which is the kind of ongoing
compatibility burden a subset exists to avoid.

Anything unimplemented returns **501** with a message saying so, rather than a
404 that reads like a bug.

**For commands, use MCP.** It is KelyfOS's actual interface, it is a published
standard rather than one product's internal API, and it is what the guest is
designed around:

```sh
kelyfos run --image dev --allow github.com
# then point any MCP client at `kelyfos mcp`
```

## The honest summary

If your E2B code creates sandboxes and moves files, it will work here. If it
runs commands — which most of it will — it will not, and you should use the MCP
interface instead. This is documented as a subset because it is one, and saying
otherwise would waste the time of exactly the people it is meant to help.
