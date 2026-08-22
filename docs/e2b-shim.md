# The E2B-compatible shim

**Status:** best-effort subset, v0.x. Implemented at P3-4.

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
guarantees as any other KelyfOS sandbox: read-only root, no login, and no egress
unless the shim was started with `--allow`.

## What is implemented

| Area | Endpoint | Notes |
| --- | --- | --- |
| Create | `POST /sandboxes` | Boots a microVM and waits for it to be ready. |
| List | `GET /sandboxes` | Only sandboxes this shim created. |
| Kill | `DELETE /sandboxes/{id}` | Stops it and cleans up. |
| Health | `GET /health` | envd liveness. |
| Read file | `GET /files?path=…` | Binary-safe. |
| Write file | `POST /files?path=…` | Multipart or octet-stream, binary-safe. |

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
