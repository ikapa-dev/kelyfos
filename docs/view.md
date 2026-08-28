# `kelyfos view` — the localhost read-only viewer

*Mixed, written after the code*, the same way `retention.md` and `otlp.md`
were: this task (P7-12) is a live-serving wrapper around a page P7-8 already
specifies exactly (`internal/report`), so there was no independent shape to
write down ahead of the code — the shape is that page's. What's genuinely new
here, and what this document exists to state precisely, is the server around
it: the one place KelyfOS opens a listening socket, and every condition that
comes with that.

## 1. What this is, and what it deliberately is not

`kelyfos view --session <id>` starts an HTTP server on `127.0.0.1`, prints
its URL once, and serves the same report `kelyfos log --export` writes to a
file — the run map, the agent sheets, the reach matrix, the store panel and
the timeline — except live: an open browser tab is pushed new events as the
session records them, over Server-Sent Events (SSE), instead of needing to
be re-exported or reloaded.

It is a reader. It is:

- **one session, not a fleet.** There is no list of machines, no dashboard
  of everything running on this host — D7's "no web dashboard" non-goal is
  still in force for that shape; D60 narrowed it, by name, to exactly this.
- **nothing persisted beyond what already exists.** The page is rendered
  fresh from the session's own flight recorder on every request; nothing
  this command writes outlives the process.
- **no authentication system.** The one-shot, per-process token described
  below is the whole story — no login, no accounts, no cookie that outlives
  the process, no config file that grants standing access.
- **not a hosted service.** It binds loopback only, and refuses to be
  anything else — see §2.
- **not a way to change a sandbox.** Every route answers `GET`/`HEAD` only.
  There is no button, form or endpoint anywhere on this page that can touch
  a running sandbox, its team membership or its flight recorder. If a
  future change ever needs one, that is a different, larger decision than
  this one — D60 draws that line explicitly, and this implementation does
  not cross it.

This is the one place in KelyfOS that opens a listening socket. Every other
command that offers something "live" — `kelyfos watch`, `kelyfos log -f`,
`kelyfos log --export --refresh` (P7-9) — does it by reading a local file on
a clock, with no socket anywhere in the path. `kelyfos view` exists for the
one case that genuinely needs a socket: an update pushed to an already-open
tab without the tab or the CLI polling a file on its own schedule. D60
records the renegotiation that admitted it, narrowly, and this document is
the other half of that: not just what is *allowed*, but exactly what is
*required* of it before it may run.

## 2. Starting it

```
$ kelyfos view --session a1b2c3d4
kelyfos view: http://127.0.0.1:54217/?token=9f2c...e01a
  loopback only · token required on every route · GET/HEAD only — docs/view.md
  exits when session a1b2c3d4 ends, after 30m0s idle, or on Ctrl-C
```

`--session` defaults to the most recent session, the same convention
`kelyfos log` and `kelyfos watch` use, resolved the identical way theirs is
(`resolveSession`, `sandbox.Root()`) — never by taking a path out of a URL.
There is no flag to change the bind address, the token requirement, the
method allowlist or the Host check. `--idle-timeout` (default 30 minutes) is
the one adjustable setting this command has.

`kelyfos view` never starts on its own — no other command launches it — and
it never opens a browser itself. It prints the URL and stops there; opening
it is yours to do.

It exits on its own in exactly three cases: the session's flight recorder
records `session.end` (the same signal `kelyfos log --export --refresh`
watches for); `--idle-timeout` passes with nobody connected and nothing new
to report; or Ctrl-C / `SIGTERM`.

## 3. The security model, condition by condition

Each of these is enforced structurally — in the router, the listener, or a
test that fails if the property stops holding — not by convention or by
"nothing currently calls the wrong thing."

**Loopback only, kernel-assigned port, no relaxing flag.** The listener is
opened by a function that takes no arguments (`host/view.go`'s
`bindLoopback`, `net.Listen("tcp", "127.0.0.1:0")`) — there is nowhere in
the process a flag, a config key or an environment variable could hand it a
different address, which is a stronger guarantee than "the default is
loopback." `TestBindLoopbackTakesNoArguments` asserts the zero parameter
count by reflection so a refactor that adds one fails the build's own test
suite, not just a review.

**A 256-bit token, minted once per process, required everywhere.** 32 bytes
from `crypto/rand`, hex-encoded, generated fresh every time `kelyfos view`
starts and never written to disk. It is required on every route this
process serves, including the SSE stream — there is no unauthenticated
endpoint, not even a health check. Comparison is `crypto/subtle.ConstantTimeCompare`,
never `==` or `strings.Compare` — length is compared first (the token's
length is fixed and public; only its content is secret), then every byte in
constant time.

*How it reaches the browser without ever being a CLI argument*: it is baked
into the printed URL as a query parameter, the same mechanism Jupyter and
code-server use for exactly this problem — a secret that has to reach a
browser this process never launches, without landing in shell history or
`ps` output the way a bare argument would. The page's own script reads it
back out of `window.location.search` and forwards it onto the `EventSource`
request it opens for `/events`. Callers who would rather keep it out of a
URL entirely (a curl invocation's own shell history, an access log) can send
`Authorization: Bearer <token>` instead; both forms are accepted, and both
are compared in constant time.

*The honest caveat about this mechanism, stated rather than hidden*: a token
in a URL can end up in browser history, and — if the page ever linked
off-origin — in a `Referer` header sent to that other origin. This page
never does: its CSP is `default-src 'none'` with `connect-src 'self'`, so
there is nothing on it to link anywhere else. The caveat is about the
mechanism in general, not about a way this particular page leaks it.

**The `Host` header must match the address actually bound.** Every request's
`Host` header is checked against `net.Listener.Addr().String()` — literally
the same string the printed URL carries. A request whose `Host` names
anything else is refused with `403`, regardless of whether its token is
correct. This is the standard defence against DNS rebinding: a page served
from `evil.example.com`, whose DNS answer happens to be `127.0.0.1`, would
still send `Host: evil.example.com` — checking against the literal bound
address, not merely "is this loopback," is what catches that.

**`GET` and `HEAD` only, structurally.** The router refuses every other
method with `405` and an `Allow: GET, HEAD` header, on every route,
regardless of token or `Host` validity — checked before either of those, so
a `POST` never even gets far enough to have its token examined. There are
exactly two routes in the whole process (`/` and `/events`); neither has a
handler that could mutate anything even if a method check were somehow
bypassed.

**A strict, hash-pinned Content-Security-Policy.** `default-src 'none'`;
`script-src` names only the exact SHA-256 hash of this page's one inline
script, nothing else — no `'unsafe-inline'`, no host source; `style-src
'unsafe-inline'`, unchanged from what the exported report itself already
uses for its (large, pre-existing, non-guest-influenced) `<style>` block and
this task's own `style="…"` attributes; `connect-src 'self'` is what lets
the page's own `EventSource` reach `/events` under an otherwise-`'none'`
default; `base-uri`, `form-action` and `frame-ancestors` are all `'none'`.
The policy is sent as an HTTP header — the more robust of the two places a
CSP can live — not as a `<meta>` tag: the exported report's own `<meta>` CSP
(`internal/report/template.go`) is *removed* from the live page (asserted
present exactly once before removal, so a change to that template fails
loudly rather than silently serving the wrong policy), because it says
`default-src 'none'` with no `script-src` override at all — correct for a
page that carries no script, and incompatible with one that does.

`TestCSPHashMatchesTheActuallyServedScript` fetches a real page from a real
server, extracts the actual `<script>…</script>` content, hashes it, and
asserts that hash is exactly what the served `Content-Security-Policy`
header allows — so editing the script without the hash following it would
fail this test, not just look fine in a diff.

**The live update carries data, never markup.** The one inline script never
writes to `.innerHTML`, `.outerHTML`, or calls `insertAdjacentHTML` or
`document.write` — checked directly (a substring search for `innerHTML`
finds nothing in the served page) and by design: every value taken from an
SSE message is placed with `.textContent`, and the script builds new DOM
nodes with `document.createElement`/`appendChild` rather than by writing
strings into the tree. It does not currently write any SVG attribute at
all — see §4 for why the run map, agent sheets and reach matrix do not need
one — so "numeric SVG attributes only" is a ceiling this script stays well
under rather than a capability it exercises.

**The flight recorder is opened read-only.** Every read in this command —
the initial page render and the background poll loop that feeds the SSE
stream — goes through `os.ReadFile`, which opens `O_RDONLY`. No write handle
to a session's `events.jsonl` is ever opened by this command.

**No path from the URL reaches the filesystem.** The session id is resolved
exactly the way `kelyfos log` and `kelyfos watch` resolve it —
`resolveSession` and `sandbox.Root()`/`recorder.Path`, reused rather than
reimplemented — once, from `--session`, before the server ever starts. No
route handler takes a path fragment, a query parameter or a header and uses
it to open a file.

**Exit on session end or idle timeout.** A background loop re-reads the
flight recorder once a second, the same "poll a growing file" shape
`kelyfos log --export --refresh`'s own loop uses. The moment it observes
`session.end`, it broadcasts one final `end` message to every open tab (the
end reason, the final event count) and the process exits — not "keeps
serving so a browser can reload for a nicer final page," because the task's
own condition is that the process exits when the session ends, and a
lingering server contradicts that more than a plain status line costs. With
nobody connected and `--idle-timeout` elapsed since the last request, it
exits the same way.

## 4. Why the run map, agent sheets and reach matrix are not updated live

They are declared once — from `session.policy` and `team.topology`, both
written once, near the start of a session or at team boot (P7-2, P7-3) — and
do not change again for the life of a session. What *does* change as a
session runs is the timeline: new commands, file writes, egress attempts,
team messages. That is exactly what the live feed under "Live" on the page
carries: one compact, single-line summary per new event, appended as plain
text as it is recorded. A page that tried to redraw the (static) run map on
every SSE message would be solving a problem this record's own shape does
not have.

The live feed is a supplement, not a second copy of the authoritative
record: it is built from a smaller, live-feed-scoped formatter
(`host/view.go`'s `viewLogLine`), not from the same renderer `kelyfos log`
uses, and it does not carry full command output — only a short description
of each event. The record itself is `kelyfos log`'s to replay exactly, and
is embedded, base64, at the foot of the page exactly as it is in a static
export; `kelyfos verify` reads it from there the identical way.

## 5. What a reader curling it directly gets

`/events` streams standard SSE: `event: update` or `event: end`, then one
`data: ` line carrying a JSON object (`{"count":…, "head":…, "lines":[…]}`
or `{"count":…, "reason":…}`). Every string field is escaped by Go's
`encoding/json` (which HTML-escapes `<`, `>`, `&` and every control byte by
default) before it is ever written to the wire, and every identity-like
field (an agent name, a path, a hostname) is additionally passed through
`internal/proto.SafeText` — the same control-byte defence `kelyfos log`'s
own event printer uses — because a raw terminal escape sequence in a
guest-chosen path is a hazard for whoever `curl`s this stream into a
terminal, not only for a browser.

## 6. The residual risk, stated rather than buried

**Loopback is reachable by every local user on a shared host.** Binding
`127.0.0.1` does not make this process private to the user who started it —
any other account on the same machine can connect to the port exactly as
easily as the person who ran `kelyfos view`. **The token is what actually
separates users here, not the loopback interface.** Chrome 142's Local
Network Access prompt, where present, adds a browser-side gate on a *public*
page reaching *any* private address — it helps against a hostile web page
and changes nothing about another local account reaching the port directly.

A Unix domain socket at mode `0600` would be a strictly stronger boundary —
the filesystem, not a guessable-in-principle 256-bit value, would decide who
can connect at all — and no browser can open one. That is the cost of this
being a page a browser opens rather than a socket a purpose-built client
does: D60 chose the page, deliberately, and this is what that choice costs.
If this token were ever compromised — logged somewhere, shoulder-surfed from
a terminal, read out of shell history because it landed in a URL pasted
into another program — a new one is one restart away, since it is minted
fresh, in memory only, every time the process starts.

## 7. What deliberately did not make this cut

Everything D60 restates as still forbidden: a fleet view of more than one
session; persistence beyond the session files that already exist;
credentials, cookies, or a second run of `kelyfos view` sharing the first
one's token; and any route, on any page, that can change a sandbox. None of
these were half-built and cut — they were never started, because building
toward any of them would have meant crossing a line D60 draws on purpose.
