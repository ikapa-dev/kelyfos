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
```

…and start the shim with `--insecure-no-token`, because the SDK cannot carry the
token the shim otherwise requires (see below).

The key is not checked by anything — the shim has no accounts and no billing —
but the SDK validates its *shape* client-side before sending it anywhere
(`\Ae2b_[0-9a-f]+\Z`), so it has to look like an E2B key.

`E2B_API_URL` is the variable to use, and it is the one the SDK's connection
config consults first. **`E2B_DOMAIN` is not a substitute**: it is a *domain*
rather than a URL, and the SDK composes `https://api.{domain}` from it — which
means TLS and a wildcard name in front of a shim that serves plain HTTP on a
loopback port. `E2B_DEBUG` is a third route to the same place and worth knowing
about, because it defaults to `http://localhost:3000`, which is this shim's own
default address.

**Which release of the SDK this works with is checked rather than promised.**
The E2B Python SDK shipped 2.41.0 through 2.45.1 in three days in August 2026,
and this project pins neither it nor a claim about it: `docs/compatibility.md`
§3 puts the shim outside the compatibility promise, and what KelyfOS tests on
every run of `caps` is the REST surface below — `dev/accept-shim.sh`, over a real
socket, against real microVMs, with no SDK installed (D51). If the SDK's
configuration moves again, this paragraph is what goes stale, and the suite is
what does not.

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

**The shim requires a credential, and mints one if you do not.** When
`KELYFOS_SHIM_TOKEN` is unset it generates 256 bits from `crypto/rand` at start
and prints them once, with the `export` line and a `curl` line:

```
kelyfos E2B shim listening on http://127.0.0.1:3000
  token: 9f3c…  (64 hex characters)
    minted for this process and stored nowhere; required on every route
    export KELYFOS_SHIM_TOKEN=9f3c…
    curl -H 'Authorization: Bearer 9f3c…' http://127.0.0.1:3000/health
```

Every route then requires `Authorization: Bearer <token>`, compared in constant
time, and answers `401` without it. Set `KELYFOS_SHIM_TOKEN` yourself to choose
the value instead — it is then not echoed back, because it is already in your
environment.

**Running with no credential takes `--insecure-no-token`.** While a shim like
that is running, any process on the machine that can reach its port can boot
sandboxes, kill them, and read and write files inside them. That was the
default until v1.1 and is not any more: the argument for it — a tool for a
machine you already trust — answered the wrong question, since an opt-in
credential is a step nobody takes. An opt-out is a choice you can see.
[`docs/threat-model.md`](threat-model.md) has the residual.

**The E2B SDK cannot carry this shim's token.** Read from the SDK's own source
(`e2b` 2.45.1), because this is exactly the kind of claim that goes stale:

| What | Header it sends | Where |
| --- | --- | --- |
| Control plane (`/sandboxes`) | `X-API-KEY: <E2B_API_KEY>`, no prefix | `e2b/api/__init__.py:243` |
| File routes (`/files`) | `Authorization: Basic base64("<user>:")` — the sandbox *user* | `e2b/envd/utils.py:44` |

Neither is a bearer token, and the file routes' `Authorization` header is
derived from the sandbox user rather than from anything you can set. So a
token-required shim answers `401` to `sbx.files.write()`. To drive this shim
with the Python SDK, start it with `--insecure-no-token` on loopback — which is
what `docs/cookbook.md`'s recipe does, and it says why in the recipe. Anything
that is not the SDK — `curl`, your own client, `dev/accept-shim.sh` — sends the
bearer token and needs no flag.

**A web page is not one of those processes.** Localhost plus no authentication is
the exact configuration a page you visit can reach, and `POST /files` is a
CORS-"simple" multipart request, so a plain `<form>` needs no preflight to write
into a live sandbox. Every route therefore refuses, before the token check:

- a request carrying `Sec-Fetch-Site` with anything but `same-origin` or `none`;
- a request carrying an `Origin` header **at all** — refused by its presence
  rather than matched against a list, because there is no browser this shim
  serves and so no origin worth allowing;
- a `Host` header that does not name the address the listener bound to. This is
  the one that catches DNS rebinding, which the other two structurally cannot
  see: a page whose name has been rebound to `127.0.0.1` is same-origin with
  itself. The bound address, any IP literal on the bound port, and `localhost`
  are accepted; a name is what rebinding needs, and a name is what this refuses.
  A `Host` carrying **no port** means port 80 — which is what browsers and Go's
  own client send when the port is the scheme's default — so a shim bound to
  `:80` accepts `Host: 127.0.0.1` and one bound anywhere else does not.

No SDK sends any of those headers, so the quickstart above is unaffected. A
refusal answers `403` and says which check it was.

**And `POST /sandboxes` requires its body to be JSON.** It used to discard the
decode error, so a body that was not JSON — a cross-origin form post, say — cost
the host a microVM. An absent body still means "the defaults"; a malformed one
answers `400`, and the body is read to a ceiling of 64 KiB.

**A bind off loopback needs a credential.** `--addr` accepts any address, and a
shim bound off loopback with no token is reachable from the LAN. `kelyfos shim`
now refuses to serve one: it checks the listener's own address the moment it has
one — after the bind, so `--addr :0` and `--addr localhost:3000` are resolved
first — and stops with a message naming the address and `KELYFOS_SHIM_TOKEN`.
A loopback bind, which is the default and every setup on this page, is
unchanged.

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
