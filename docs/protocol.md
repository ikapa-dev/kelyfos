# KelyfOS host ⇄ guest protocol

**Status:** normative for v0.x. Written at P1-0 before any transport code
existed and implemented by P1-3, P1-5, P1-6, P2-1 through P2-4 and P3-1;
extended in place since, most recently by the `team` channel at E2-1 (§5.6). It
is still a specification rather than a description: if code and this document
disagree about the wire, the code is wrong.

This document defines how the `kelyfos` CLI on the host talks to the supervisor
inside the guest: the transport, the constants, and the wire format of every
channel.

---

## 1. Transport: Firecracker's hybrid vsock

The guest speaks `AF_VSOCK`. The host does **not** — the host side of every
channel is a Unix domain socket. This is Firecracker's design, not a workaround:
Firecracker implements the virtio-vsock device model itself and mediates between
`AF_UNIX` on the host and `AF_VSOCK` in the guest, *"while bypassing vhost kernel
code on the host"* (Firecracker `docs/vsock.md`, v1.16.1).

Three consequences, all of which the implementation depends on:

- **No host vsock kernel module is required.** There is no `vhost_vsock` to load,
  no `/dev/vhost-vsock` to open, and no host-side `AF_VSOCK` socket anywhere in
  KelyfOS. Anything claiming otherwise is describing QEMU, not Firecracker.
- **The vsock UDS is not the Firecracker API socket.** They are two separate Unix
  sockets with two unrelated protocols: the API socket carries HTTP, the vsock
  UDS carries raw channel bytes after a one-line handshake.
- **Ports are multiplexed onto separate Unix sockets, 1:1.** Guest `AF_VSOCK`
  ports map to host `AF_UNIX` paths.

### 1.1 Host-initiated connections (host → guest)

The guest listens on an `AF_VSOCK` port. The host:

1. `connect()`s to the vsock UDS at `uds_path`;
2. sends the ASCII line `CONNECT <port>\n` (`<port>` in decimal, `\n` = 0x0A);
3. reads the acknowledgement line `OK <assigned_hostside_port>\n`.

After that line the connection is a raw bidirectional byte stream to the guest
listener. If the connection cannot be completed, Firecracker closes it instead
of acknowledging. That happens for two reasons, and both are transient:

- nothing is listening on `<port>` in the guest yet;
- the guest's listener has a full accept backlog, which a burst of concurrent
  tool calls can produce.

Neither is "the transport is broken", so a host **MUST** retry a closed
handshake until its own timeout expires rather than failing the first attempt.
Reporting it immediately turns an ordinary burst into sporadic, unreproducible
failures.

> **Implementation rule.** `<assigned_hostside_port>` is an arbitrary number
> chosen by Firecracker (values like `1073741824` are normal). Read the
> acknowledgement one byte at a time up to and including the `\n` and discard it.
> A buffered reader that greedily fills a 4 KiB buffer here will swallow the
> first bytes of channel data on any channel where the guest speaks first.

### 1.2 Guest-initiated connections (guest → host)

The host listens on a Unix socket at **`<uds_path>_<port>`** — the vsock UDS path
with an underscore and the decimal destination port appended. The guest connects
an `AF_VSOCK` socket to CID **2** and that port. **The first frame is the
credential** (§1.7) on every port in the `101xx` range; after it, the connection
is channel bytes from the next byte.

If no host socket exists at that path, the guest's `connect()` fails with a reset.

### 1.7 The channel credential

The guest-initiated channels are authenticated (audit 2026-09-01, A2/A3). The
host mints one credential per machine — 32 bytes of entropy, hex-encoded, 64
characters — and hands it to the supervisor over the `control` channel (§5.4,
op `auth`), the one direction a process inside the guest cannot reach because a
guest vsock listener serves the host's CID alone. The supervisor holds it in
memory only — never in the environment, the command line or a file, each of
which every root process in the guest reads — and presents it as the first
frame of every connection it dials to `10100`, `10101` and `10102`:

```json
{"v":1,"auth":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

The host compares it in constant time and refuses the connection — closing it
before reading anything past that frame — if it is absent or wrong, recording
every refusal as a `channel.refused` event. A peer the kernel names as coming
from another account is refused the same way (`SO_PEERCRED`, where the kernel
says; the credential is the control either way).

The push is timed by a hint rather than by polling. Once its `control` listener
is bound, the supervisor prints one line to its console — `kelyfos-supervisor:
control listening` — and the host, which reads the serial console anyway, makes
its next `auth` attempt the moment that line arrives instead of at the end of
its probe interval. The line is not part of the protocol and carries no trust:
a guest that prints it early only brings forward a connect that fails and is
retried, and a host that never sees it falls back to probing at the cadence it
always used. It exists because every probe is a `CONNECT` the VMM has to carry
into a guest that is busy booting, so probing faster costs the boot it is
trying to shorten, while the hint lands the credential within a millisecond of
the port existing.

Three properties are deliberate:

- **One credential per machine, not per port.** The ready, events and team
  channels are one trust decision: what the guest reports, the host records.
- **A fresh value on restore.** The process doing the restore did not boot the
  machine; the frozen credential belongs to a session that is over, and N forks
  of one snapshot would otherwise share one value across sessions. The host
  pushes a new one over `control` before `resync`, and the supervisor replaces
  what it holds.
- **No fallback.** There is no port, flag or mode that turns the credential
  off. A supervisor that predates the handshake answers `auth` with
  `bad_request`, and the boot fails with a named refusal rather than starting
  a machine whose record could be forged.

The dials a supervisor makes before the credential lands are refused by the
host and retried under the existing dial backoff; a boot costs a few refused
connections, which the record shows as `channel.refused` at the front of the
chain.

### 1.3 CIDs

| Constant | Value | Meaning |
| --- | --- | --- |
| `VMADDR_CID_HOST` | **2** | The host. Fixed by the virtio-vsock specification; guest code connects here. |
| KelyfOS guest CID | **3** | Set per VM via the Firecracker vsock resource's `guest_cid` field. 3 is the lowest CID a guest may take (0, 1 and 2 are reserved). |

The guest CID matters only inside the guest's own address space — the host never
addresses the VM by CID, because the host reaches it through the UDS.

### 1.4 Firecracker configuration

```json
{
  "vsock": {
    "guest_cid": 3,
    "uds_path": "<run_dir>/v.sock"
  }
}
```

`<run_dir>` is the per-sandbox runtime directory the CLI creates (P1-5). All
host-side socket paths in this document are relative to it.

### 1.5 Guest kernel requirements

The kernel fragment built in P1-2 must set, as built-ins — there are no modules:

```
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS_COMMON=y
# CONFIG_VHOST_VSOCK is not set
# CONFIG_MODULES is not set
```

These match Firecracker's own CI guest configuration. No device node is needed:
the guest transport is an `AF_VSOCK` socket with `bind`/`listen` or `connect` on
it, and nothing in KelyfOS opens `/dev/vsock`.

### 1.6 Snapshot caveats (forward note for P3-1 / P3-2)

Two upstream constraints shape the snapshot work; they are recorded here so they
are not rediscovered later:

- **UDS path collisions on restore.** Two VMs restored from one snapshot cannot
  share a vsock UDS path. Firecracker's `PUT /snapshot/load` takes a
  `vsock_override.uds_path`, so each fork must be given its own `<run_dir>`.
- **Open vsock connections do not survive a snapshot; listeners do.** Firecracker
  resets the vsock device across snapshot/restore, and is precise about what that
  costs: *"vsock connections that are open when the snapshot is taken are closed,
  but existing vsock listen sockets in the guest still remain active and can
  accept new connections after resume."* So:
  - the guest's listeners on `10001`/`10002`/`10003`/`10004`/`10005` survive — the supervisor
    MUST NOT tear them down and re-bind, and the host reconnects with a fresh
    `CONNECT` per §1.1. This is why the resync RPC (§5.4) can be the first thing
    the host sends on a restored VM;
  - the guest's **outbound** channels (`10100`, `10101`, `10102`) are severed and
    only the guest can re-dial them, so the supervisor MUST reconnect them
    itself;
  - every connection drops **mid-stream**, so both ends must tolerate that
    without dying — including a half-written frame, which is why a reader
    discards a trailing partial line rather than guessing at it.

  The same reset also fires when a snapshot is *taken*: Firecracker lists "the
  vsock device is reset" among the effects on the still-running source microVM.
  The supervisor therefore cannot distinguish resume-after-save from
  resume-after-restore, and must not try to — the reconnect behaviour above is
  identical in both cases.

---

## 2. Port map

Two ranges, chosen so the direction of a channel is readable from its number:

| Range | Listener | Host reaches it by |
| --- | --- | --- |
| `100xx` | the **guest** listens on `AF_VSOCK` | `CONNECT <port>\n` on `<run_dir>/v.sock` |
| `101xx` | the **host** listens on `AF_UNIX` | guest connects to CID 2, port |

| Port | Name | Direction | Introduced | Purpose |
| --- | --- | --- | --- | --- |
| `10001` | `exec` | host → guest | P1-6 | One command per connection. §5.2 |
| `10002` | `mcp` | host → guest | P2-2 | MCP server. §6 |
| `10003` | `control` | host → guest | P2-1 | Lifecycle and resync RPCs. §5.4 |
| `10004` | `shell` | host → guest | E5-3 | One interactive terminal per connection. §5.7 |
| `10005` | `forward` | host → guest | E5-5 | One forwarded TCP connection per connection. §5.8 |
| `10100` | `ready` | guest → host | P1-3 | Boot-to-ready signal and heartbeats. §5.3 |
| `10101` | `events` | guest → host | P2-4 | Guest-side event stream into the flight recorder. §5.5 |
| `10102` | `team` | guest → host | E2-1 | Team messaging: the guest asks, the host routes. §5.6 |

Host socket paths follow from §1.2: the `ready` channel is
`<run_dir>/v.sock_10100`, the `events` channel is `<run_dir>/v.sock_10101`. The
host must be listening on both **before** the VM is started, or the guest's first
connect attempt races the host and fails.

Ports are unsigned 32-bit. Nothing here uses a port below 1024, which Linux
treats as privileged for `AF_VSOCK` as it does for TCP.

---

## 3. Framing: newline-delimited JSON

Every KelyfOS channel — and MCP itself, see §6 — uses the same framing, with two
exceptions: `shell` (§5.7) is binary-framed, and `forward` (§5.8) is unframed
after its two handshake lines. Everywhere else:

- one message per line, terminated by a single `\n` (0x0A);
- the message **MUST NOT** contain a literal newline anywhere, including inside
  string values (JSON escapes them as `\n`, which is two characters on the wire
  and therefore fine);
- UTF-8, no BOM;
- a `\r` immediately before the `\n` is tolerated on read and never written;
- empty lines are ignored on read, up to 1024 consecutive ones — past that the
  reader fails the connection rather than spin on a peer that sends nothing else.

**Binary data is base64.** JSON strings cannot carry arbitrary bytes, and command
output is arbitrary bytes. Every field whose value is raw bytes is base64
(RFC 4648 standard alphabet, padded) and named so in the schema below.

**Limits.** A reader MUST reject a line longer than **1 MiB** and close the
connection: an unbounded line buffer is a memory-exhaustion bug waiting for the
first `cat /dev/urandom`. Writers therefore chunk: no single frame carries more
than **64 KiB** of pre-encoded bytes.

The MCP channel (port 10002) is one exception, and its limit is **16 MiB**.
Nothing on that channel is chunked — a `read_file` result is a whole file on one
line — and the per-call limit on a file is 8 MiB, so a 1 MiB frame would refuse
messages the tools above it promise to carry. Sixteen was chosen to leave room
for JSON escaping around eight, and that arithmetic no longer holds: a
`read_file` result carries the file twice, once in the text block and once as
`content` (docs/mcp-surface.md §2.2), so a file at the 8 MiB cap is 16,777,216
bytes of payload — this limit exactly — before the JSON around it and before a
single escape. The number stays where it is, because it is what bounds an
untrusted far side; what the guest's server does with an answer that will not
fit is send a refusal naming the size and this limit in its place, rather than
close the connection on the send error (docs/mcp-surface.md §2.2). Nothing of
the oversized frame is written, so the stream is still on a frame boundary and
the session carries on. Both directions and every reader on the channel use the
same number (`proto.MaxMCPLine`), so a message one side will send is a message
the other side will accept.

The team channel (port 10102) is the other exception, and it goes the other
way. Its frame limit is the 1 MiB above, but nothing on it is chunked either —
a `send` carries its whole body on one line — so the bound is put *below* the
frame rather than the frame raised above it. A team message carries at most
**785,664 bytes** of payload before base64 (`proto.MaxTeamBody`), and the
request id the host echoes onto its answer at most **128 bytes**
(`proto.MaxTeamID`); §4 asks an initiator for an id of no more than 64
characters, and 128 bytes is what this channel can enforce on a peer that
ignores that. Both are refused with `bad_request` naming the size and the
limit, before the broker acts on the request.

The payload has to be the smaller number because the frame that delivers a
message is not the frame that sent it: a delivery carries `from` where the
request carried `to`, plus the `correlate` tag a reply has to quote back, so it
is tens of bytes larger than the frame that fitted. Reserving that envelope —
a kilobyte, against a measured worst case of 983 bytes — is what stops the broker accepting a
message it can then never write out (§5.6).

**Unknown fields are ignored.** Every message carries `"v": 1`; a reader that
sees a `v` it does not know MUST fail the message rather than guess.

---

## 4. Common message shape

```jsonc
{ "v": 1, "id": "<string>", ... }
```

| Field | Type | Notes |
| --- | --- | --- |
| `v` | integer | Protocol version. `1` for all of v0.x. |
| `id` | string | Opaque correlation id, ≤ 64 characters, unique within a connection. Chosen by the initiator; echoed in every message about that request. |

Errors use one shape on every channel whose messages carry `v` and `id`:

```json
{"v":1,"id":"a1","error":{"kind":"timeout","message":"command exceeded timeout_ms=5000"}}
```

`kind` is one of `bad_request`, `not_found`, `denied`, `timeout`, `killed`,
`io`, `internal`. `message` is human-readable and never contains a secret value.

The two channels that are not framed this way carry an error as a bare string
instead: `error` on a `shell` exit frame (§5.7) and on a `forward` reply (§5.8).
Neither carries a `kind`, so neither can be classified by the kinds above.

---

## 5. Channels

### 5.1 Connection lifetime

`exec` is **one request per connection**: the host opens a connection, sends one
request, reads frames until the terminating frame, and closes. The `id` field
exists anyway, so that logs correlate and so a later revision can multiplex
without a wire change.

`control`, `ready`, `events`, `mcp` and `team` are **long-lived**: many messages,
either direction, until one side closes. `team` in particular is one connection
for the life of the sandbox, carrying every request that agent makes (§5.6).

### 5.2 `exec` — port 10001, host → guest

Request (host writes one line, then may write nothing else):

```json
{"v":1,"id":"a1","cmd":["L2Jpbi9zaA==","LWM=","dW5hbWUgLWE="],"cwd":"/","env":{"PATH":"/usr/bin:/bin"},"stdin":"","timeout_ms":30000}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `cmd` | array of string | yes | argv, one element per array entry, each element **base64**. Not a shell string: element 0 is the executable, resolved against the *supervisor's* `PATH` and not the one in `env` — the lookup happens before the child's environment is applied. Wrap in `["/bin/sh","-c", …]` when a shell is genuinely wanted, so that choice is visible in the audit log. Each argument is base64 like `stdin` below, because argv can carry arbitrary bytes and a plain JSON string cannot: `encoding/json` silently replaces invalid UTF-8 with U+FFFD on marshal, which would corrupt a non-UTF-8 argument with no error anywhere. |
| `cwd` | string | no | Working directory. Default `/`. |
| `env` | object | no | Environment, **replacing** the default set rather than merging — a sandbox that silently inherits environment is how secrets leak. |
| `stdin` | string | no | base64. Empty or absent means stdin is an immediately-closed pipe, never a terminal. |
| `timeout_ms` | integer | no | Wall-clock limit. `0` or absent means no limit. On expiry the guest sends `SIGKILL` to the process group and terminates with `error.kind = "timeout"`. |

Responses (guest writes zero or more output frames, then exactly one terminating
frame, then closes):

```json
{"v":1,"id":"a1","stream":"stdout","data":"TGludXgga2VseWZvcyA2LjE4LjQ1Cg=="}
{"v":1,"id":"a1","stream":"stderr","data":"…"}
{"v":1,"id":"a1","stream":"exit","code":0}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `stream` | string | `stdout`, `stderr`, or `exit`. |
| `data` | string | base64 of the raw bytes, ≤ 64 KiB pre-encoding. Chunk boundaries are arbitrary and carry no meaning: they are **not** line boundaries. |
| `code` | integer | On `stream: "exit"` only. The process exit status; for a process killed by signal N, `128 + N`, with `signal` naming it. |
| `signal` | string | Optional, on `exit`. E.g. `"SIGKILL"`. |
| `error` | object | Optional, on `exit`. Present when the command could not be run or was cut short. `code` is then `-1`. |

Exactly one `exit` frame is sent per request, including on error. A closed
connection with no `exit` frame is a supervisor crash and the host MUST report it
as such rather than inventing an exit code.

Ordering is guaranteed per stream, not across streams: interleaving of `stdout`
and `stderr` reflects the order the guest read them and nothing stronger.

### 5.3 `ready` — port 10100, guest → host

The last thing the supervisor announces, and deliberately so — and behind the
credential like every guest-initiated channel (§1.7): a ready frame from a
connection that cannot present it is a machine that is not, and the host
refuses it rather than announcing a boot that did not happen. It comes after the
mounts, the confinement profile, the egress environment, every plugin and the MCP
handshake paid with each one, loopback, and the bind of every listener — because
ready means the machine is usable, and a machine whose `tools/list` is still
filling in is one an agent cannot tell apart from a machine that never had those
tools. A sandbox with plugins therefore takes longer to become ready than one
without. The host is listening on `<run_dir>/v.sock_10100` before the VM starts;
the timestamp at which this first frame arrives is the definition of
**boot-to-ready** measured in P1-7.

```json
{"v":1,"type":"ready","boot_id":"7f3a…","arch":"arm64","kernel":"6.12.105","supervisor":"0.1.0","monotonic_ns":41233000,"overlay":true,"profile":"…"}
```

then, every 5 s:

```json
{"v":1,"type":"heartbeat","uptime_ms":5041}
```

`overlay` reports whether the writable overlay was established over the
read-only root. `false` means the guest booted degraded on a read-only
filesystem: still reachable, still diagnosable, but writes will fail. A host
that logs this turns a whole class of confusing `EROFS` reports into one obvious
line at boot.

`profile` names the confinement every process the supervisor spawns is given, and
is absent on an image older than v0.9, which confines nothing. `profile_error` is
why that confinement could not be established, when it could not: a non-empty one
makes the host refuse the machine outright rather than let a sandbox that
confines nothing look like one that does (P5-3).

`monotonic_ns` is the guest's own `CLOCK_MONOTONIC` at the moment of sending —
useful for splitting boot time into kernel time and supervisor time. The host
measures the total itself and never trusts the guest's clock, which before the
resync in §5.4 may be wrong by an arbitrary amount.

### 5.4 `control` — port 10003, host → guest

Request/response, correlated by `id`. Introduced with the supervisor in P2-1.

```json
{"v":1,"id":"c1","op":"shutdown"}
{"v":1,"id":"c1","ok":true,"profile":"…"}
```

Every answer carries `profile` and `profile_error` — the same pair the `ready`
frame carries — and not just the ones that asked for them: the posture is a
property of the machine rather than of the question, and the host may reach a
machine it did not boot. A restored machine sends no ready frame, so the answer
to `resync` is where the host learns what that machine confines (P5-7).

| `op` | Payload | Effect |
| --- | --- | --- |
| `ping` | — | `{"ok":true}`. Liveness without waiting for a heartbeat. |
| `shutdown` | — | `SIGTERM` everything but PID 1, `SIGKILL` what is left after the grace period, flush the filesystems, power off. The host still supervises the Firecracker process and force-kills after a grace period of its own. |
| `trust` | `ca_pem` | Install the egress CA's trust anchor (P2-6). |
| `resync` | `realtime_ns`, `entropy` | Post-snapshot-restore fix-up (P3-1). |
| `auth` | `token` | Store the channel credential (§1.7), presented on every guest-initiated dial. Sent as soon as the guest answers control, and again with a fresh value on every restore. A supervisor that predates the handshake answers `bad_request`, and the boot is refused with a named error. |

```json
{"v":1,"id":"c3","op":"trust","ca_pem":"-----BEGIN CERTIFICATE-----\n…"}
```

`trust` carries a **certificate, never a key**: the guest is asked to trust the
proxy, not given the means to impersonate it. It arrives over this channel
rather than being baked into the image for two reasons — the CA is minted per
run and never persisted (decision D6), so an image-baked one would be wrong for
every run but the one that made it; and the rootfs is read-only, so there is
nowhere to put it until the overlay is up.

The supervisor writes it into the guest trust store *and* points
`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`
and `GIT_SSL_CAINFO` at it. The environment variables are not belt and braces:
Python's `requests` ships its own CA bundle in `certifi` and Node carries its own
roots, and both ignore the system store entirely. KelyfOS can do this only
because it owns the guest's default environment (§5.2) — which is the reason
decision D6 chose termination here and would not choose it on a general-purpose
machine.

```json
{"v":1,"id":"c2","op":"resync","realtime_ns":1787654321000000000,"entropy":"<base64, 32 bytes>"}
```

A restored VM resumes believing the wall clock and its entropy pool are what they
were when the snapshot was taken — for N forks of one snapshot, identically so.
The supervisor applies `realtime_ns` with `clock_settime(CLOCK_REALTIME, …)` and
writes `entropy` into `/dev/urandom`. This is the first *resync* the host sends
on a restored VM, before handing the sandbox back to its caller — and it is no
longer the host's very first message: the fresh channel credential (§1.7) is
pushed over `control` before it, because a restored machine's outbound channels
are refused until the new credential lands. (`ptp_kvm` +
`chrony` were considered and rejected: too heavy for a BusyBox image.)

### 5.5 `events` — port 10101, guest → host

Guest-originated events for the flight recorder. One event per line; the schema
is defined in `docs/events.md` at P2-4, and the host is responsible for the hash
chain — the guest never computes it, because a guest that could forge chain
links could forge its own audit trail.

Connections carry the credential (§1.7) — this is the channel the audit's A2
and A3 forgeries rode, and the reason the handshake exists: an unauthenticated
frame here is a forged line in the record the project's claims stand on.

Implemented at E1-4. The frame is deliberately thin:

```json
{"v":1,"type":"resource.oom","monotonic_ns":4941890000,"pid":57,"comm":"python3","rss_kib":230016}
```

- `type` is a flight-recorder event type from `docs/events.md` §4. The host
  ignores a type it does not recognise rather than recording it: an unknown type
  is either version skew or an attempt to write something arbitrary into the
  audit trail, and neither belongs in the chain.
- `monotonic_ns` is the *guest's* clock, carried for ordering inside the guest
  and never used as the event's timestamp. The host stamps every event with its
  own clock, for the same reason it times boot-to-ready itself (§5.3).
- There is no sequence number and no `prev`. Numbering and chaining are the
  host's, always.

The guest queues these and reconnects after a drop, the way it does for `ready`.
The queue is bounded: this is PID 1, so a host that stops reading must cost a
dropped report rather than a blocked init, and a drop is announced on the
console.

### 5.6 `team` — port 10102, guest → host

Team messaging (E2-1). Request/response, newline-delimited JSON, one connection
held for the life of the sandbox, behind the same credential as the other
guest-initiated channels (§1.7).

This channel runs guest → host, unlike `exec`, `mcp` and `control`, and the
direction is the design. Every other host-initiated channel exists because the
host wants something from the guest; this one exists because an agent inside the
guest wants to reach another agent, and nothing already here can carry that —
`ready` and `events` are one-way reports with no reply path.

The host is the only participant that can answer. It is the only one that knows
the edge list, holds the other guests' channels, and writes the audit record. A
guest asks; a guest is never asked to route, and no guest ever receives a
connection from another guest, because there is no path for one (`docs/teams.md`
§2).

```json
{"v":1,"id":"7","op":"send","to":"worker-1","body":"c3BsaXQgdGhpcw=="}
{"v":1,"id":"7","ok":true}
```

| `op` | meaning |
| --- | --- |
| `send` | Deliver `body` to `to`. Answered when the broker accepted or refused it. |
| `recv` | Take the next message for this agent, waiting up to `timeout_ms`. |
| `ask` | Deliver a question and wait for its answer, up to `timeout_ms`. |
| `reply` | Answer a question, carrying back the `correlate` the broker supplied. |
| `peers` | The agents this one may *initiate* to. |
| `store_get`, `store_put` | The team store, E2-3. Both carry `key`; `store_put` also carries `body`, and an empty `body` deletes the key rather than writing nothing — recorded as a `delete` and not a `put`. |
| `spawn` | Ask for a worker within this agent's declared budget, E2-5. Optional `image`. |

Request fields beyond `op`: `to`, `body` (base64), `correlate`, `key`, `image`,
`timeout_ms`. Response fields beyond `ok`: `from`, `body`, `peers`, `correlate`,
`agent`, `error`.

`timeout_ms` on `recv` and `ask` is clamped at both ends. Zero, absent or
negative — which is what an overflowing millisecond count becomes — waits one
minute rather than not at all, and anything above fifteen minutes waits fifteen.
Clamped rather than refused: an agent asking to wait a long time is not
misbehaving, and one that wants longer asks again.

`agent` on a response is load-bearing rather than informational, and it names a
different agent on each of the two responses that carry it. Alongside `peers` it
is the asker's own authoritative name: a guest is told its name on the kernel
command line, but a fork inherits its template's command line and would therefore
report the template's name — so the host returns the name it holds, and **the
guest MUST prefer it** over anything it read from `/proc/cmdline` (F-D24). On a
`spawn` result it is the *newly created worker's* name, which the guest hands
back to its caller and never adopts as its own. The host never reads a guest's
opinion of its own identity off the wire: it knows which agent a connection
belongs to because it is the side that bound the socket.

`correlate` is minted by the broker and echoed by the guest. A guest cannot
invent one: a reply whose correlation the broker does not recognise, or that
belongs to a question put to a different agent, is refused. That matters because
a reply is the one message that crosses without an edge being checked — it
completes a call the broker is already holding open — so the tag is what stands
in for the edge.

The store bounds what one team can make the host hold: a key of at most 1 KiB,
10,000 keys per team, 1 MiB per value and 64 MiB per team. Each is refused with a
`denied` error the agent sees, rather than quietly swallowed.

The value limit an agent can actually reach is the smaller of two. A `store_put`
carries its value in `body`, so the channel's 785,664-byte payload bound (§3)
refuses an oversized value with `bad_request`, naming that limit, before the
store's 1 MiB `denied` is ever reached. The store still enforces its own
megabyte — it is the component that owns the byte budget, and the two limits
are checked in different places for different reasons — but the channel is the
only route a guest has to it, so `bad_request` at 785,664 bytes is the refusal
an agent sees.

A refusal is an `Error` with one of the kinds in §4 plus `no_edge`,
`no_such_agent` and `unreachable`. There is no silent drop: an agent that may
not send something is told so, and told why. An answer the host cannot fit in
a frame is refused the same way, with `internal` naming the frame limit — the
rule the MCP channel already follows (§3), arrived at here for the same reason.
Nothing of the oversized frame is written, so the stream is still on a frame
boundary and the connection carries on rather than closing under the caller.

---


### 5.7 `shell` — port 10004, host → guest

One connection is one interactive terminal. Added by E5-3 as an **additive
revision**: a supervisor without it refuses the connection, and everything else
on every other channel is unchanged.

**This is the one channel that is not newline-delimited JSON**, and the reason is
the traffic. A terminal stream is binary, high-rate and latency-sensitive; base64
inside a JSON envelope would cost a third of the bandwidth and a copy per
keystroke to carry bytes that are already bytes. So the framing is:

```
| kind: 1 byte | length: 4 bytes, big-endian | payload: length bytes |
```

`kind` is `1` for **data** — raw terminal bytes, in either direction — and `2`
for **control**, whose payload is one JSON object. A frame longer than **1 MiB**
is refused and ends the connection: a terminal writes in small bursts, a paste
is the largest thing it sends, and a length prefix that cannot be trusted cannot
be resynchronised from.

Control frames, all of them small and rare:

| Direction | Shape | When |
| --- | --- | --- |
| host → guest | `{"op":"open","cwd":…,"cols":…,"rows":…,"cmd":…,"args":…}` | first frame, and the only one that starts anything |
| host → guest | `{"op":"resize","cols":…,"rows":…}` | the host's window changed |
| guest → host | `{"op":"exit","code":…,"signal":…,"error":…}` | the shell ended, or never ran |

`cmd` and `args` on the open name the binary to run. When `cmd` is empty the
guest runs its own default instead — the first of `/bin/sh`, `/bin/ash`,
`/bin/bash` that exists — which is what the host asks for when it has no way to
know what a flavor ships.

`error` on the exit is present only when the shell never ran at all: the guest
could not allocate a pty, could not open the slave, or could not start the
command. It is sent with `code: 1`, and the host turns it into the command's
error rather than reporting it as an exit status.

**A resize is a control frame and not an escape sequence** because of who has to
be told: `TIOCSWINSZ` on the pty, by the kernel, so that full-screen programs
redraw. An escape sequence would be something the *shell* had to understand.

The supervisor allocates the pty, opens the slave, and spawns the shell with
`Setsid` and `Setctty` so it is a session leader with that terminal as its
controlling one — which is what makes job control, line editing and `isatty()`
work. Without it a shell on a pipe has none of them and every program it runs
decides it is not interactive.

**A closed connection with no exit frame is a supervisor that died**, which is a
different thing from a shell that ended — the same distinction §5.2 draws for
`exec`. When the *host* hangs up, the guest sends `SIGHUP` to the shell process
itself: a shell left running on a terminal nobody is reading is a process that
never ends. The signal goes to that one process and not to its process group, so
a child the shell left running on that terminal is not hung up with it.

### 5.8 `forward` — port 10005, host → guest

One connection is one forwarded TCP connection. Added by E5-5 as an **additive
revision**, on the same terms as §5.7.

Two lines of JSON, and then the connection is the bytes:

```
host  → guest   {"v":1,"op":"open","port":80}
guest → host    {"v":1,"ok":true}
                …the stream, in both directions, unframed…
```

A refusal is the same line with `"ok":false` and an `error` saying what the
guest's own dial returned:

```
guest → host    {"v":1,"ok":false,"error":"nothing answered on port 80 inside the sandbox: …"}
```

Neither line may exceed **4 KiB**, which is more than a port number and a
sentence need and bounds what an unterminated line can make the other side
buffer.

**After the handshake there is no framing at all**, and that is deliberate: a
TCP bridge that framed its payload would be re-implementing TCP inside TCP. It
also means both ends must keep reading with the *same* buffered reader that read
the handshake line — a second reader drops whatever the first had already
buffered, which for a server that speaks first is the beginning of its greeting.
A half-close is passed through in both directions, because a client that has
finished sending and is waiting to read needs the other end to see EOF.

**The guest dials its own loopback**, `127.0.0.1:<port>`, and never its NIC —
which the supervisor brings up at boot whether or not the sandbox has a network,
because otherwise a forward into the commonest kind of sandbox could not work at
all (F-D55, `networking.md` §3.0). That
is the whole reason inbound forwarding is possible at all without weakening
anything: the packet is created inside the machine, so nothing arrives across the
TAP, the nftables ruleset that makes the network egress-only never has to make an
exception, and `nft list ruleset` is identical with a forward and without one
(F-D7, docs/networking.md §3).


## 6. MCP over vsock

From P2-2 the supervisor runs an MCP server on port `10002`.

**Framing is the MCP stdio transport's framing, unchanged.** The specification is
explicit, in every revision from 2025-06-18 through 2026-07-28:

> Messages are delimited by newlines, and **MUST NOT** contain embedded newlines.

This is *not* LSP-style `Content-Length` header framing. There are no headers.
One JSON-RPC message per line.

The 2026-07-28 revision states outright that the binding is not tied to standard
streams:

> Standard streams are the canonical channel, but nothing in this binding depends
> on them except the process lifecycle. The wire format (one newline-delimited
> JSON-RPC message per line over a reliable bidirectional byte stream) works
> unchanged over Unix domain sockets, TCP connections, or any similar channel.

A vsock channel is exactly such a stream, so KelyfOS is a conforming custom
transport rather than a dialect.

### 6.1 `kelyfos mcp` is a pass-through

Because both ends already use the same framing, the bridge (P2-3) is a byte
copier, not a translator:

```
MCP client ──stdio──► kelyfos mcp ──UDS + "CONNECT 10002\n"──► guest :10002
```

It MUST NOT reframe, reorder, buffer whole messages, or parse the JSON-RPC to
decide anything, and it MUST forward bytes onward unmodified. It may *observe*
messages to feed the flight recorder. It has two protocol responsibilities of
its own, and no others. The first is consuming the `OK …\n` acknowledgement line
(§1.1) before the first byte of MCP traffic, and never emitting that line to the
client's stdout — the spec forbids writing anything to stdout that is not a valid
MCP message. The second is that when the guest's end of the stream closes with a
tool call outstanding, the bridge answers that call with a JSON-RPC error of its
own (F-D33): a client left waiting forever on a dead sandbox is worse than a
client told the sandbox is gone. Both are messages the bridge *originates*;
neither modifies one it was given.

`stderr` stays a logging channel in both directions' spirit: the bridge may write
diagnostics there, and an MCP client is required not to treat that as failure.

---

## 7. Versioning

`v` is bumped only for a breaking change to an existing message. Adding a field,
a message type, an `op`, or a port is not breaking: readers ignore unknown fields
and MUST NOT fail a message for containing one.

Because the supervisor ships inside the image and the CLI ships on the host, the
two can be different builds. The `ready` frame carries `supervisor`, and the host
logs it with every session and records it, so which supervisor answered is on the
session's record rather than inferred from the CLI's own version.

---

## 8. Conformance checklist

| Requirement | Task |
| --- | --- |
| Guest kernel exposes `AF_VSOCK` with the symbols in §1.5 | P1-2 |
| Guest listens on `10001`, connects out to `10100` | P1-3 |
| CLI writes `guest_cid: 3` + `uds_path`, listens on `_10100` before boot | P1-5 |
| `exec` implements §5.2 exactly, including the `OK …\n` read rule | P1-6 |
| Boot-to-ready measured from first `ready` frame | P1-7 |
| Supervisor serves `control` per §5.4 | P2-1 |
| MCP server on `10002` with §6 framing | P2-2 |
| `kelyfos mcp` forwards bytes unmodified, and originates only the two messages in §6.1 | P2-3, F-D33 |
| `events` feeds the hash-chained recorder | P2-4 |
| `resync` applied on every snapshot restore; per-fork `vsock_override` | P3-1, P3-2 |
| Supervisor re-dials `10100`, `10101` and `10102` after a snapshot reset | P3-1, E2-1 |
| Every guest-initiated connection presents the session's credential; the host refuses and records a connection without it | §1.7, audit 2026-09-01 A2/A3 |
| A forward's stream is unframed, and the handshake reader keeps reading it | E5-5 |
| `team` channel serves §5.6, and the guest prefers the host's `agent` on `peers` | E2-1, E2-9 |

---

## 9. Sources

- Firecracker `docs/vsock.md`, tag `v1.16.1` — hybrid vsock design, the
  `CONNECT`/`OK` handshake, `<uds_path>_<port>`, `vsock_override`, and the vsock
  snapshot limitation.
- Firecracker `docs/snapshotting/snapshot-support.md`, tag `v1.16.1` — the exact
  vsock reset semantics quoted in §1.6 (connections closed, listeners retained)
  and the reset's effect on the source microVM at snapshot creation.
- Firecracker `resources/guest_configs/microvm-kernel-ci-aarch64-6.1.config`,
  tag `v1.16.1` — the guest kernel symbols in §1.5.
- Model Context Protocol specification, revisions 2025-06-18, 2025-11-25 and
  2026-07-28, *Transports → stdio* — the framing rule quoted in §6.
- virtio specification, virtio-vsock — CID 2 is the host; guest CIDs start at 3.
