# Refusals

*Concept, with one generated half: [`reference/denials.md`](reference/denials.md)
is the catalog itself, written by `make docs` from the code that raises it.*

A sandbox is a thing that says no. It says no to a domain nobody allowed, to a
flag above a ceiling, to a message along an edge that was never declared. Each
of those refusals is the product working correctly, and each of them lands on
somebody who now has to work out what to type instead.

So every refusal KelyfOS makes names its own fix:

```
$ curl http://api.stripe.com/v1/charges
kelyfos: api.stripe.com is not in this sandbox's allowlist [egress.host]
    add allow = ["api.stripe.com"] to kelyfos.toml, or rerun with --allow api.stripe.com
```

Three parts, always in this order. Every refusal *the catalog raises* has them;
the refusals raised while reading `kelyfos.toml` or validating a team plan do
not, and are not in the catalog — they name their own file and line instead,
because the thing to go and look at is the line you wrote.

**The refusal.** What was asked for and why it was not permitted, naming the
specifics — the domain, the ceiling, the file and the line it came from. A
refusal that says "not permitted" and stops has told the reader only that they
are stuck.

**The ID**, in brackets. It is stable, it is the heading to look up in
[`reference/denials.md`](reference/denials.md), and it is what a program matches
on. Prose is written for people and gets rewritten; an ID does not.

**The fix**, indented on its own line, naming something the reader can type or
edit. One line, because a refusal is read in a hurry.

## Where they come from

One catalog, `internal/denial`, holding the message and the fix together as one
record. They cannot drift apart, because they are not two things in two files.

Two checks keep it honest, and they run in opposite directions:

- `make docs` regenerates [`reference/denials.md`](reference/denials.md) from
  the catalog, and CI fails on any diff (F-D4). The documentation cannot
  describe a refusal the product does not make.
- The same run fails the build if a catalog entry is raised nowhere in the
  source. A refusal documented but never made is a promise with no code behind
  it.

Every example on that page is rendered by the code that raises it, so what you
match against what your terminal showed you is the same string.

## What is not in the catalog

**Failures are not refusals.** "The upstream did not answer" is not a decision
KelyfOS made; nothing the reader types changes it; and a fix line reading "try
again" is how people learn to stop reading fix lines. Those errors say what
happened and stop.

**A fix line never widens the policy on anyone's behalf.** It says what to edit;
a person edits it. This is the same invariant the MCP tool surface is held to
(F-D5): the ceiling in `kelyfos.toml` is not something the software can talk
itself past, and a refusal that offered to raise it would be exactly that.

**A refusal KelyfOS never sees cannot be in a catalog KelyfOS raises from.** The
catalog is checked in both directions — `make docs` fails the build for an entry
nothing raises (F-D4) — so an entry with no raise site would be a documented
promise with no code behind it, which is the condition that check exists to
prevent. One refusal falls squarely in that gap and is worth naming here, because
it is the one people will meet:

> **Attaching a debugger to a process already running inside a guest fails**,
> with `Operation not permitted`, on every flavor — including `dev`, whose
> profile deliberately leaves `ptrace` out of its refusal list.

That is the guest kernel answering a syscall the host never sees. Every process
the supervisor spawns is confined by its own Landlock domain, and Landlock
refuses `ptrace` between *sibling* domains; two commands in the same sandbox are
siblings. It is a protection nobody asked for and it is real: it also means one
command cannot read another's `/proc/<pid>/exe` or otherwise introspect it.

**What still works, which is the part that matters:** a debugger that *launches*
its target. A child inherits its parent's domain and is therefore not a sibling,
so tracing what you started is permitted; only attaching to something already
running is refused. On `base` even launching is refused, by the seccomp half, and
that is the per-flavor difference `dev` exists to make.

Neither image ships a debugger, so this is about what you install into a `dev`
sandbox rather than about `strace` and `gdb` by name.

The reasoning, the alternative that was rejected, and why this is not a knob is
D33 in `PLAN.html`; the profiles themselves are
[`reference/profiles.md`](reference/profiles.md).

## When nobody is watching

Everything above assumes somebody is looking at the terminal. The case this
product creates is the opposite: a sandbox you started and stopped watching.
`--notify` — or `notify = true` in `kelyfos.toml` — sends a desktop notification
at the four moments where a person is wanted back:

| | What it says |
| --- | --- |
| the run finished | `exited 3 after 1m30s`, or `finished cleanly after 4s` |
| something was blocked | the refusal's first line, once per distinct refusal |
| a budget expired | `the max_runtime budget of 30m expired after 30m` |
| a review is waiting | `3 added, 1 modified, 0 deleted in project — write them back?` |

`notify-send` on Linux, `osascript` on macOS, and the terminal bell when neither
is there — which needs nothing installed. The run says which one it found, in
its own header, because a notification that never arrives is indistinguishable
from one that was never asked for.

Three rules, and they are the whole design:

**A notification never fails a run.** Every send is best effort with a five
second timeout and a discarded error. The acceptance runs with a notifier that
exits non-zero, one that never returns, and none at all, and checks the exit
status is untouched each time.

**The message is data, never script.** On macOS the text is passed as arguments
to `osascript` and read back inside the script with `item 1 of argv`, rather
than pasted into an AppleScript string. A domain or a command name can contain a
quote, and a notification is not a place to have an injection bug.

**Off unless asked.** A tool that starts sending desktop notifications because
you upgraded it is a tool people learn to distrust.

The fix line does not travel with the notification. A refusal's first line is
what is sent; the fix stays on the terminal, which is where somebody has to go
to apply it anyway.

## For programs

A catalogued refusal is a `*denial.Refusal`, carrying its ID and the values it
named. A policy-file or team-plan refusal is an ordinary error and
`denial.Of` does not recognise it, so a program that branches on IDs should
treat "no ID" as its own case rather than as "not a refusal":

```go
if r, ok := denial.Of(err); ok && r.ID() == "budget.sandboxes" {
    // wait for a slot rather than reporting a failure
}
```

Team refusals cross the broker as a `team.Error`, whose `Message` is the same
rendered text — ID, fix line and all — so an agent reading the error it was
handed has the fix in front of it too.

## Who gets told, when the client will not show it

An egress refusal is written to whatever made the request, and for HTTPS that is
usually where it stops. A refused `CONNECT` is answered with `403` and a body,
and curl prints `Received HTTP code 403 from proxy after CONNECT` and throws the
body away; most other clients do the same. Plain HTTP carries it through
untouched, because there the refusal *is* the response, and so does a
secret-bound domain, where the proxy terminates TLS and answers inside it.

The other reader is the person watching the run, and they are the one with the
policy file open. So the first time a domain is refused, the host prints the
refusal and its fix line to its own stderr:

```
$ kelyfos run --allow example.com
kelyfos: api.stripe.com is not in this sandbox's allowlist [egress.host]
    add allow = ["api.stripe.com"] to kelyfos.toml, or rerun with --allow api.stripe.com
```

Once — deduplicated on the advice rather than on the attempt. A program that
retries forty times, or that tries the same host on 80 and again on 443, is one
line to add to one file, and saying so forty times is noise dressed as detail.
Every attempt is still in the record; it is the *advice* that is printed once.

Refusals are also events. Every one of the egress denials appears in the flight
recorder with its reason, and every refused tool call is in the transcript
(E4-4), so a refusal is auditable whether or not the person it landed on
mentions it. See [`events.md`](events.md).
