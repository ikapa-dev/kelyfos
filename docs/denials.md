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

Three parts, always in this order.

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

## For programs

A refusal is a `*denial.Refusal`, carrying its ID and the values it named:

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

## What is not covered yet

Inbound port forwarding (`-p`) arrives at E5-5, and its refusals join this
catalog when it does — the catalog is complete for the refusals that exist, not
for the ones that are planned.
