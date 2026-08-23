# Daily-driver QoL — the shapes, before the code

*Status: specification for v0.8, written before Epic E5 builds it. The parts
that need a shape agreed in advance are here; the parts that are wrappers over
machinery that already exists are not, because there is nothing to decide about
them.*

*Where this document and the code disagree during the epic, the code is wrong
and this page is the thing to argue with. After the epic, the reverse — and the
E4 exit exam found four places where that reversal had not been made, so it is
worth saying twice.*

---

## What this epic is for

Every feature here removes a friction someone hits *after* they have already
decided to use KelyfOS. None of them is why anyone would try it. All of them are
why someone would keep using it, and the difference between a tool you reach for
and a tool you tolerate is made almost entirely of these.

There are eight, and they promote together as v0.8. Four need a shape settled
first, and this document settles those four:

| | Needs a shape because |
| --- | --- |
| **Named sessions** — `pause`, `resume`, `sessions` | there is a store on disk, and its layout is a promise |
| **Diff and review** — `kelyfos diff`, `run --review` | the manifest is a format two commands share |
| **Interactive shell** — `kelyfos shell` | it adds a channel to `docs/protocol.md`, which is a versioned wire format |
| **Port forwarding** — `-p host:guest` | inbound is the invariant the network layer is built around, and this has to not break it |

The other four — actionable denials, run history, `logs -f`, `--notify` — are
described in the plan and need nothing decided here.

---

## 1. Named sessions

```
kelyfos pause --as before-the-migration
kelyfos resume before-the-migration
kelyfos sessions
kelyfos sessions rm before-the-migration
```

A paused session is a snapshot with everything it needs to become the same
machine again, under a name a person chose.

### 1.1 The store

```
~/.cache/kelyfos/named/<name>/
  state              the Firecracker memory-state file
  memory             the memory image
  meta.json          what the machine was: arch, flavor, vcpu, memory, network
  workspace.ext4     the workspace disk, when there was one
  plugins.ext4       the plugins device, when there was one
  kelyfos.toml       the policy this machine was running under, frozen
  session            the flight-recorder session id this machine belonged to
```

The first five are exactly what `snapshot save` already writes, which is the
point: `pause` is `snapshot save` plus a teardown plus two more files, not a
second mechanism.

**`<name>` is checked, not trusted.** Letters, digits, dot, dash and underscore,
at most 64, not starting with a dot — the same rule `sandbox_snapshot` applies,
for the same reason: a name becomes a directory.

### 1.2 The frozen policy, and why it is frozen

`resume` runs the machine under `kelyfos.toml` **as it was when the machine was
paused**, not as it is now.

This is the one decision in named sessions that could go either way, so here is
the reasoning. A resumed machine is the *same machine*: its memory holds
addresses, environment variables and open file descriptors that were built under
the old policy. A guest whose `HTTPS_PROXY` points at a port the new policy does
not open is not a machine running under the new policy — it is a machine that no
longer works, in a way that looks like a bug in KelyfOS.

So the policy travels with the snapshot, exactly as the addressing does (D22),
and `resume` says so when they differ:

```
kelyfos: this session was paused under a kelyfos.toml that has since changed.
    Resuming under the frozen copy, which is what the machine's memory expects.
    2 differences: [resources] cpus 2 → 4, allow gained api.github.com
    To run under the current policy, start a new sandbox rather than resuming.
```

Naming the differences is the part that matters. "The policy changed" tells
somebody to go and diff two files; this tells them whether they care.

**The ceiling still applies to what a resume may ask for.** The frozen policy is
what the machine runs under; it is not a way to smuggle a machine past the
current policy's ceiling. A resume whose frozen policy exceeds the current one is
refused, naming both — the same rule `sandbox_restore` follows, which found its
own version of this hole at E4-2 (F-D39).

### 1.3 Workspace timing

**Sync-back happens at final shutdown, never at pause.**

A pause is a machine you intend to come back to. Writing its workspace back to
the host at that moment would mean the host directory changes under someone who
did not ask for it, and then changes again when the session finally ends — twice
for one run, once unexpectedly. The workspace image stays in the store and comes
back with the machine.

The consequence is worth stating plainly: **a paused session holds your files
inside it.** `sessions` shows the size so it is visible, and `sessions rm` says
what it is about to discard.

### 1.4 Events

`session.pause` and `session.resume`, in the machine's own chain, carrying the
name and — on resume — whether the policy differed. A paused session's chain is
not closed by the pause: it is the same session, and closing it would make
`--verify` describe a machine that is still there as finished.

---

## 2. Diff, and review before sync-back

```
kelyfos run --workspace . --review -- <command>
kelyfos diff
```

### 2.1 The manifest

Packing a workspace already walks the tree. The manifest is what that walk
records, written into the image's own directory beside it:

```json
{"schema": 1, "packed": "2026-08-23T17:00:00Z", "root": "/abs/host/dir",
 "entries": [
   {"path": "src/main.go", "mode": "0644", "size": 1841, "sha256": "…"},
   {"path": "src", "mode": "0755", "dir": true}
 ]}
```

`sha256` is of the file's contents. Not the fingerprint `Fingerprint()` computes
for change detection — that one mixes in modification times, which is right for
"did this change under me" and wrong for "is this the same file", and the
difference has already cost this project one defect (F-D45).

Directories carry mode and nothing else. Symlinks carry their target in place of
a digest. Anything else — a socket, a device node — is not packed and is not in
the manifest, so it cannot appear as deleted afterwards.

### 2.2 The comparison

At shutdown the guest tree is walked again and compared entry by entry:

```
 M src/main.go        +18 −4
 A src/parse.go       +96
 D testdata/old.json  −214
```

`A`/`M`/`D`, then numstat for text and a byte delta for anything that is not.
Mode changes are `M` with the modes named. A file whose contents are identical
and whose mode changed is still a change, because it is one.

### 2.3 `--review`

The summary prints and sync-back **waits**. Answering yes syncs; answering no
routes the result to `<dir>.kelyfos-out`, which is P3-10's existing diversion
mechanism rather than a new one — the host directory is untouched until an
explicit yes.

The answer is a `run.review` event carrying the decision and the counts. A
declined review is a fact worth keeping: it is the one place the product asks a
person to make a judgement, and a transcript that recorded only the accepted ones
would be a record of agreement rather than of what happened.

**Non-interactive is a refusal, not a default.** `--review` with no terminal does
not silently sync and does not silently divert: it diverts *and says so*, with a
non-zero exit, because a flag whose whole purpose is asking a person becomes a
trap the moment it answers on their behalf.

---

## 3. The interactive shell

```
kelyfos shell
kelyfos shell --transcript
```

### 3.1 The channel

A new port on the existing vsock plumbing, host → guest, added to
`docs/protocol.md` as an **additive revision**: a supervisor that does not
implement it refuses the connection and everything else keeps working.

```
PortShell = 10004   // host -> guest
```

Two frame kinds, and the asymmetry is deliberate:

- **Data** is raw bytes, not JSON. A terminal stream is binary, high-rate and
  latency-sensitive, and base64 inside a JSON envelope would cost a third of the
  bandwidth and a copy per keystroke for no benefit. The stream is the payload.
- **Control** is a JSON frame, for the things that are not the stream: the
  opening request (which shell, what size, what environment) and window resizes.

They share a connection by being length-prefixed: one byte of kind, four bytes of
length, then the payload. That is the whole framing, and it is written down here
rather than discovered from the code.

### 3.2 What the supervisor does

Allocates a PTY, spawns the flavor's shell as its session leader with the PTY as
its controlling terminal, and copies. On resize it issues `TIOCSWINSZ` — which is
the reason resize is a control frame rather than an escape sequence in the
stream: an escape sequence is something the *shell* would have to understand, and
this is something the *kernel* has to be told.

The host puts its own terminal in raw mode for the duration and restores it on
every exit path, including a panic. A tool that leaves your terminal unusable
after it crashes is a tool people stop running.

### 3.3 What is recorded, and what is not

**Always:** `shell.start` and `shell.end`, with duration and exit status.

**Only with `--transcript`:** the terminal stream, stored beside the session log
as a separate file — not inside the chain, because a hash-chained record is for
facts about what happened and a terminal stream is an artefact.

The default is off (F-D8), and the reason is not squeamishness. An interactive
shell is where someone pastes a token to test something, types a password into a
prompt that does not echo but does *arrive as keystrokes*, or works through
something they would rather not have minuted. Recording that by default would
make the honest thing — using the shell — the risky thing. The session log still
says a shell was opened, for how long, and how it ended, which is what an
auditor needs to know that it happened.

---

## 4. Inbound port forwarding

```
kelyfos run -p 8080:80 -- <command>
```
```toml
[[forward]]
host  = 8080
guest = 80
```

### 4.1 The invariant this must not break

The network layer's guarantee is that **nothing reaches the guest from outside**.
It is enforced by nftables: the forward chain drops everything in both directions
across the TAP, and the input chain permits exactly one destination — the proxy
port on the host address (docs/networking.md §3).

A forward that added an nftables rule would be a hole in that. So it does not.

### 4.2 The transport is vsock, not the network

```
host listener (127.0.0.1:8080)
  ↕ vsock
supervisor
  ↕ loopback inside the guest
guest-local port 80
```

The host binds a listener; each accepted connection opens a vsock stream to the
supervisor; the supervisor dials the guest's own loopback. **No packet crosses
the TAP in either direction**, so the firewall is untouched, the invariant holds
as literally as it did before, and `nft list ruleset` looks the same with a
forward as without one.

That is the whole of F-D7, and it is why the feature is possible at all.

### 4.3 Loopback by default, LAN by explicit request

The host listener binds `127.0.0.1`. `--p-bind 0.0.0.0` is the way to expose it
to the network, and it warns, loudly and every time:

```
kelyfos: -p 8080:80 --p-bind 0.0.0.0 exposes this sandbox's port 80 to every
    machine that can reach this one. There is no authentication on it.
```

No configuration file key does this. A LAN exposure should be a thing somebody
typed, in the session where it happened, rather than a line in a file somebody
inherited.

### 4.4 Events

`forward.accept` per accepted connection, with the peer address, the host port
and the guest port. Not per packet and not per byte: a connection is the unit
somebody would ask about.

Teardown closes every listener. A port that outlives its sandbox is a port that
answers for a machine that no longer exists.

---

## 5. What this epic will not do

**No `--daemon`.** `pause` and `resume` cover the case a daemon would exist for,
and a background service is a thing to install, to upgrade and to have go wrong
while you are not looking.

**No remote anything.** Every forward binds loopback by default and every
transport is a subprocess or a socket on this machine. KelyfOS is a
single-host developer tool (D1), and the day that stops being true it should be a
decision rather than a drift.

**No shell recording by default**, per F-D8 and §3.3 above.

**No new policy surface.** Everything here is bounded by the `kelyfos.toml` that
already exists, and none of it adds a way to widen one — the same invariant E4's
tools are held to (F-D5).

---

## 6. Conformance

| Requirement | Task |
| --- | --- |
| This spec | E5-0 |
| `pause` / `resume` / `sessions`, frozen policy, sync-back at final shutdown | E5-1 |
| `kelyfos diff`, `run --review`, the manifest format, `run.review` | E5-2 |
| `kelyfos shell` over the PTY channel, `shell.start` / `shell.end`, `--transcript` | E5-3 |
| Actionable denials with a fix line, one catalog | E5-4 |
| `-p host:guest`, `[[forward]]`, loopback default, `forward.accept` | E5-5 |
| `kelyfos runs`, `rerun`, `logs -f` | E5-6 |
| `--notify` on finish, block, timeout and review prompt | E5-7 |
