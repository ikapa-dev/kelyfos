# Changelog

**This file is the source, not a mirror.** The release workflow cuts a release's
notes from the section below that matches its tag, and refuses to publish a tag
that has no section (D50). Nothing regenerates this file and nothing copies it
somewhere else, because a second copy of the truth that nothing keeps honest is
the failure the generated reference exists to prevent.

Versioning follows [`docs/compatibility.md`](docs/compatibility.md), which is
normative from v1.0 and says what a major, a minor and a patch may each do.
Releases before v1.0 predate that promise and made none.

Dates are the tag's, not the merge's. Timings are measured on the bare-KVM
reference described in the README and re-measured per release.

---

## Unreleased

### Added
- **`kelyfos team graph`**: renders a team's topology straight from
  `kelyfos.toml`, with nothing booted — the same plan-time checks
  `kelyfos team up` runs before it boots anything, including the refusal a
  `[[plugin]]`/`[[forward]]` beside `[team]` already gets. The picture: every
  agent, the resolved edges, the domains and secrets each agent reaches, and
  the store's rules — including the access every key with no matching
  `[[team.store.key]]` rule has by default. `kelyfos team ps --graph` draws
  the identical picture for a running team, read from that team's own
  recorded `team.topology` and `session.policy` events rather than from the
  file. `kelyfos watch` gains two panes alongside the existing one — a map
  (`2`/`m`) and an agent sheet (`3`/`s`, caps beside live counters) — both
  read off the same fold, and the map's "refused since boot" section covers
  every real `team.refused`/`team.store`/`team.spawn` reason, each with the
  fix line `internal/denial`'s catalog already writes for it where one
  exists. Both graph commands also say, explicitly, what a recorded
  `team.topology` cannot tell them: a worker spawned at runtime after boot,
  and whether an empty store rule list means the store is off or open to the
  whole team (P7-7).
- **`--json` on `kelyfos team ps`, `kelyfos team graph` and `kelyfos watch`**:
  the extensibility surface for a view this phase did not think of, and
  cheaper than a plugin system. Before this, only `bench`, `log` and `verify`
  could be piped. `kelyfos team ps --json` returns the identical shape the
  `team_ps` MCP tool has always returned as `structuredContent`. `kelyfos team
  graph --json` and `kelyfos team ps --graph --json` return the resolved
  topology as data instead of a drawing — agents, edges, resources, access and
  the indirect-reach pairs the terminal view already draws in prose. `kelyfos
  watch --json` prints one snapshot of `internal/digest`'s own fold — every
  counter, the session header, the policy and topology events verbatim, bounded
  the same way the live view already is — and exits, instead of opening the
  TUI; it carries no timeline, which `kelyfos log --json` already is. Documented
  in `docs/teams.md` §8.5 (P7-10).
- **`kelyfos log --export-otlp`**: maps a session's chain to an OTLP-JSON
  trace export — `invoke_agent` per agent (or the sole implicit agent of a
  non-team session), `execute_tool` per command, every egress attempt or
  refusal as a span event on the agent it belongs to. Versioned apart from
  the flight recorder and never an input to `kelyfos verify` (D59): the
  `gen_ai.*` semantic conventions this targets are still marked
  "Development" with no stabilisation timeline, so a future revision of them
  changes only this mapping, never a hashed byte. An inbound W3C
  `traceparent` on `session.policy` continues that trace instead of starting
  a new one (`docs/otlp.md`, P7-11).
- **`kelyfos log --export` against a session that has not ended, and
  `--refresh` to keep it current.** The export always rendered whatever the
  flight recorder held; what was new is `--refresh`, which rewrites the same
  destination on a timer (`--refresh-every`, default 2s), atomically, for as
  long as the session runs, and adds a `<meta http-equiv="refresh">` tag so a
  browser tab already open on the file reloads itself and shows the latest
  rewrite. No socket anywhere in that path — a CLI process rewriting a file
  and a browser polling it — so it is the honest answer to "live" for anyone
  who does not want a listener, and it exists whether or not `kelyfos view`
  (P7-12) does. The loop stops on its own once `session.end` appears in the
  chain (that final write drops the refresh tag, since nothing more is
  coming) or on Ctrl-C (P7-9).

### Fixed
- **A single oversized, guest-influenced field could make the flight recorder
  permanently unreadable from that line on.** The record is a hash chain read
  with a bufio.Scanner capped at 8 MiB, and nothing bounded what a caller could
  put in a line before it reached that cap. Two doors did: the egress proxy
  validated a CONNECT target's characters but never its length, and the MCP
  bridge base64-encoded a whole command's stdout or stderr into one
  `command.output` event with no chunking at all. Both are closed now — the
  proxy rejects a host over 253 bytes (RFC 1035) before it is ever considered
  for recording, and exec output crossing the MCP bridge is chunked the same
  way `kelyfos exec` already chunks it. `Append` itself also refuses,
  unconditionally, to write a line its own readers could not read back,
  whatever field made it that large and whatever door produced it.
- **`kelyfos snapshot restore` could run a restored guest's egress unaudited
  for the whole restore.** It wired the proxy's audit hooks only after
  `sandbox.Restore` returned — but `Restore` resumes the guest and lets it
  round-trip over the control port (clock/entropy resync, the seccomp check)
  well before it returns, and `InstallTrustAnchor` ran after that, itself a
  control-port round trip with a read deadline a hostile guest controls the
  far end of. Every egress attempt, secret use and withheld-credential
  decision in that window went unrecorded: the proxy still enforced its
  allowlist, but nothing told the flight recorder about it. The audit hooks
  are now wired — with the sandbox id already known, same as the other four
  places in this product that build a proxy — before `sandbox.Restore` is
  ever called, so nothing the guest does from the moment it resumes goes
  unaudited.
- **A path-scoped credential (`Scope.Path`, endpoint locking) could be
  attached to a request whose literal, on-the-wire bytes an origin server
  would route outside the bound path.** The check compared the *decoded*
  request path against the bound prefix, but Go sends the *escaped* path
  upstream verbatim, and the two can be made to differ in ways a real server
  re-segments and Go's own parser has no opinion on at all: a `;`
  matrix-parameter a Tomcat/Jetty container strips before routing, a raw
  backslash IIS/.NET treats as a separator, an overlong UTF-8 encoding of `/`
  a lenient legacy decoder accepts. The old check enumerated only the two
  encodings Go's own parser treats specially (`%2f`, `%2e`), which is not the
  same claim as "safe on every origin this could be bound to". It is now an
  allowlist: the escaped path may contain only unreserved characters, `/`,
  and the one vetted exception (`%20`, for an ordinary encoded space in a
  path segment) — anything else, including any other percent-encoding,
  withholds the credential instead of trying to reason about what a
  particular server would do with it.
- **An exported report's own tamper-evidence markers could be defeated by an edit that a
  verifier's own doc comment already said should be refused.** `marked()` reads each of the six
  values a page states about itself (chain head, event count, session, and — the sharpest case —
  the signing key's fingerprint, the exact check P6-19 added so a swapped signing key could not
  hide behind a fingerprint the reader trusts) by looking for one `<code id="...">` or, failing
  that, one `<span id="...">`. On finding the `<code>` count ambiguous (2+), it fell through to
  check `<span>` instead of refusing outright — so an editor could show a fake value in a visible,
  duplicated `<code>` tag and hide the true value in a lone `<span>` for the same id, and
  `marked()` would hand back the true value, agreeing with the record while the page a human
  reads shows the fake one. `kelyfos verify` now refuses to answer for a marker that is ambiguous
  across *either* tag kind, matching what `marked()`'s comment already promised.
- **Four lower-severity gaps, each a guest able to spend host resources or a record able to say
  something false.** The egress proxy accepted an unbounded number of connections, never set a
  read deadline on one, and let `http.ReadRequest` consume an unbounded header block before
  giving up — a guest could hold connections open forever or force unbounded memory per
  connection while it parsed; a concurrency cap, a read deadline, and a header-size bound close all
  three — the bound is a releasable limiting reader rather than a plain `io.LimitReader`, since the
  latter would keep charging a request's body against the same budget as its headers and silently
  truncate any legitimate upload once the two together crossed the limit (found in review) — and
  the host's own denial-deduplication map is now bounded the
  same way against a guest trying unboundedly many disallowed hostnames. The team wire bounded a
  request's id and body but never its store key, so an oversized key reached `internal/team`'s
  store unchecked; `Store.Put`'s own length check also ran after its access check, so an oversized
  key denied for an unrelated reason was recorded in full before its length was ever examined —
  the wire now refuses an oversized key outright, and `Get` and `Put` both check length before
  anything else. A guest file named with a quote character was not refused, and the comment
  claiming quoting already covered it was wrong: a quote is not whitespace and closes the
  double-quoted debugfs command early; `validName` now refuses it. And an absolute-form
  `https://` request sent straight to the proxy without a `CONNECT` was recorded as
  `mode: plain` / `not_encrypted` even though it is a real, certificate-validated TLS fetch —
  a new mode and withheld reason say what actually happened instead.
- **A symlink planted inside a tree the sandbox may write let `write_file` and `upload` reach
  anywhere on the host, including the raw block devices behind the guest's own read-only root and
  workspace.** `writableFor` was a pure lexical check — `filepath.Clean` plus a prefix comparison
  against the writable trees — and the write itself was a bare `os.WriteFile`/`os.MkdirAll` on
  whatever path the agent supplied, so neither ever asked what a path component actually pointed
  at. Creating a symlink costs a confined exec nothing beyond what it already has —
  `LANDLOCK_ACCESS_FS_MAKE_SYM` is granted on every tree write is — so `ln -s /dev/vda /work/escape`
  followed by `write_file("/work/escape", …)` reached the disk without the tool ever naming it.
  Both call sites now walk the path component by component with `Lstat` and refuse if any
  component — including a pre-existing symlink at the final one — is a symlink, once as part of the
  writability decision and again immediately before the write itself, since a symlink can be
  planted in the gap between the two.
- **The egress proxy allowed a connection based on a hostname string and never checked where that
  hostname actually resolved to, so an allowlisted domain that is DNS-hijacked, or simply taken
  over, could be pointed at `169.254.169.254` — a cloud instance's metadata endpoint, on port 80,
  already in the proxy's always-allowed port set — and an ordinary guest CONNECT to that
  already-allowed name would be tunnelled straight there.** `allowsHost` and `secretsFor` only ever
  looked at the string a guest's CONNECT or request line named; nothing in `tunnel`, terminate's
  upstream leg, or `forwardHTTP` ever looked at the address DNS actually sent the connection to.
  All three now dial through a `net.Dialer.Control` hook that runs once per address a resolver
  returns, immediately before the connect syscall for that address, refusing loopback, link-local
  (169.254.0.0/16 included) and other private/reserved space — skipped only when the host being
  dialled is already a literal IP address, since nothing is resolved there for DNS to have
  hijacked, which is also why this changes nothing for the many tests in this package that dial
  real loopback test servers by address. The refusal is recorded in the flight recorder the same
  way any other egress denial is, as a new `unsafe_resolved_address` reason with an
  `egress.resolved_addr` catalog entry naming the address and explaining why retrying will not help.
- **A guest OOM kill or a plugin call/crash on a restored, forked or resumed sandbox left no trace
  in the flight recorder.** `sandbox.Options.OnGuestEvent` is what turns a guest's report into a
  recorder line, and `sandbox.go`'s `serveEvents` drops the frame outright, silently, when it is
  nil. That was correct for a fresh `sandbox.New` boot and for a team member forked from a
  template — `host/team.go`'s `memberOptions` already solved exactly this problem once, per its
  own comment — but every other door that resumes a machine with `sandbox.Restore` built a bare
  `sandbox.Options{}` with no handler at all: `kelyfos fork`, `kelyfos snapshot restore`,
  `kelyfos resume`, and `serve-mcp`'s `sandbox_restore` and `sandbox_fork` tools. `memberOptions`'s
  inline closure is now `guestEventRecorder`, one function shared by all six call sites. Three of
  them also had to open their recorder before calling `sandbox.Restore` rather than after: the
  guest starts reporting the instant the machine resumes, and a recorder opened only once every
  fork in a batch had finished, or only long enough to append a single resume event and close
  again, missed whatever the guest said in between.
- **`kelyfos snapshot restore` read no policy file at all, unlike `run` and `fork` (which enforce
  `[resources]` ceilings) and unlike `serve-mcp`'s `sandbox_restore` — the identical operation
  through the MCP door, which already calls `checkSnapshotFits` and `restoreAllow` before
  restoring.** A restored machine got no ceiling, no allowlist narrowing and no secrets from
  `kelyfos.toml`, a gap `docs/compatibility.md` and `docs/resources.md` already disclosed by name
  but the asymmetry with the MCP door was undocumented. `snapshot restore` now takes `-policy`,
  resolved by `loadPolicyAt` exactly the way `run` and `fork` resolve it — a named file that does
  not exist is an error, and with nothing named it walks up from the working directory and applies
  whatever `kelyfos.toml` it finds. Found or named, a restore is held to it the same three ways
  `sandbox_restore` already holds one to it: `checkSnapshotCeiling` refuses a frozen machine whose
  recorded vcpu or memory is over the ceiling (Firecracker takes both from the state file, so
  there is nothing to clamp — only allow or refuse), `restoreAllowCeiling` refuses reaching a
  domain the policy does not permit, and `restoreSecrets` defaults `--secret` from the policy's
  own `secrets` when none are typed, dropping rather than erroring on the ones this particular
  restore cannot reach. This is a real default-behaviour change: a working directory with a
  `kelyfos.toml` above it — this repository's own included — now gets its restores held to it by
  default, the way its `run`s and `fork`s already were.
- **`count` under `[[team.agent]]` had no upper bound, unlike every sibling numeric field, so
  `count = 999999999999` in a `kelyfos.toml` crashed the whole `kelyfos` process with an
  unrecoverable Go OOM abort — from parsing the policy file alone, before any topology, budget or
  scratch check ran.** `host/teamplan.go`'s `expandCount` allocates `make([]string, 0, count)` per
  agent group as the very first thing `planTeam` does with a parsed count, so a large enough number
  was never a slow boot or a refused plan — it was a slice the allocator could not satisfy and an
  abort no `recover` catches. `count` is now capped at 64 in `internal/config/team.go`, refused at
  parse time with the same clear error `count < 1` already gets, rather than left to fail wherever
  the number was first used. 64 is headroom over anything this project's own examples or
  `max_sandboxes`'s default of 4 suggest a real team needs — `docs/teams.md` documents the ceiling
  next to `count`. `FuzzConfigParse` gained the finding's own reproduction as a seed and an
  invariant checking every parsed `Count` against the ceiling, alongside a dedicated unit test for
  the boundary itself.
- **The guest-facing team and events channels' accept loops had no connection cap and no read
  deadline, unlike the egress proxy's identical accept loop, fixed for exactly this shape by S5a —
  the fix was never mirrored to these two sibling listeners.** Both are unix sockets any process
  inside the guest can dial directly over vsock, not only through the supervisor's own
  well-behaved clients, and `serveTeam`/`serveEvents` spawned one goroutine per `Accept` with
  nothing bounding how many could be outstanding or how long one could sit open having sent
  nothing at all — enough silent connections and no connection, including a real one, could ever
  be served again. Both loops now acquire a 128-connection semaphore before `Accept`, the same cap
  and the same before-not-after placement `internal/egress/proxy.go` uses, and set a 10-second read
  deadline on an accepted connection that is cleared the moment its first frame parses — a
  connection already mid-conversation is never punished for an idle gap before its next request,
  which on the team channel can legitimately be arbitrarily long.
  `TestSilentTeamConnectionsAreCappedAndReclaimed` and `TestSilentEventsConnectionsAreCappedAndReclaimed`
  fill each cap with connections that never write and prove a legitimate connection queued behind
  it is still served once the deadline reclaims a slot, rather than stuck for good.
- **An oversized or malformed MCP frame — one over the 16 MiB channel limit, or one carrying a
  literal, unescaped newline — used to kill the whole session over a single bad frame, and could
  lose even the one reply meant to explain why.** `mcpSession.serve`'s read loop answered any
  non-EOF read error with a best-effort, id-less parse error and unconditionally closed the
  connection; for an oversized frame, `bufio.Scanner` gives up having buffered exactly the frame
  limit and no more, so the rest of that same line was still unread on the wire when the close
  raced it — the close could interleave with, or be cut short by, those unread bytes, and the
  reply was not guaranteed to arrive. Every call still in flight on the connection was lost with
  it, for a defect in one frame that had nothing to do with them. The session now recovers instead
  of closing: on `proto.ErrLineTooLong` it drains the rest of the oversized line first (a new
  `proto.Reader.DrainOverlongLine`, reading straight off the connection since the scanner's own
  buffer holds nothing past its limit) so the reply is never racing unread bytes, and on a frame
  that decoded to a complete, newline-terminated line but failed `json.Unmarshal` (the embedded-
  newline case, now reported as `*proto.MalformedFrame`) there was never anything to drain — the
  stream was already back at a clean boundary. Both cases reply and keep serving. Getting the
  first case right needed `proto.Reader` itself to stop reusing a `bufio.Scanner` after any error:
  one does not resume cleanly — the very next `Scan()` hands back its already-buffered, oversized
  data as if it were a normal final token, which is what a caller actually observed instead of the
  `ErrLineTooLong` it expected — so a successful drain now rebuilds the scanner in place
  (`resetScanner`) before resuming. The host bridge's own observer had the identical flaw one
  level up: `tee` in `host/mcpobserve.go` drove the client→guest and guest→client copies through a
  `bufio.Scanner` of its own for the flight recorder's sake, so the same oversized-line give-up
  closed the pipe the real byte copy reads from — silently dropping every byte sent afterward on
  that connection, from either side, regardless of how gracefully the guest handled the frame.
  `tee` now relays an oversized line's remainder raw and rebuilds its own scanner to resume
  observing what comes after, rather than ending the copy. `kelyfos mcp` also no longer exits 0
  when the bridge closes with a call still outstanding: `answerOutstanding` already wrote the
  client a synthetic error and a stderr line saying so, but returned nil regardless, so the one
  thing a wrapper script or supervisor process checks — `$?` — said success; it now returns a
  non-zero `exitError`. Verified against a real sandbox's MCP channel with both a frame just over
  `proto.MaxMCPLine` and a frame with a literal embedded newline: the session now answers each and
  keeps serving normal calls afterward, including a `write_file` whose event still lands in the
  flight recorder, rather than the bridge exiting silently.
- **`kelyfos exec` silently mangled an argument containing invalid UTF-8 bytes.**
  `proto.ExecRequest.Cmd` was a plain `[]string` JSON field, unlike `Stdin`, which
  docs/protocol.md §3 already requires base64 for because "every field whose value is raw bytes
  is base64": `encoding/json` marshals a Go string as UTF-8 and silently replaces any byte
  sequence that is not valid UTF-8 with U+FFFD, so an argv entry built from arbitrary bytes — a
  filename, a fetched credential, anything not guaranteed to be text — arrived in the guest
  corrupted, with no error anywhere on either side. `cmd` now gets the same treatment `stdin`
  already had: each argv element is base64-encoded by the host before the request is sent
  (`proto.EncodeCmd`) and decoded by the supervisor before it reaches `exec.Command`
  (`proto.DecodeCmd`), an invalid element failing the request with `error.kind = "bad_request"`
  rather than being silently accepted. The array structure is unchanged — only each element's
  encoding — so argv boundaries stay visible on the wire. Every place that builds an
  `ExecRequest` (`kelyfos exec`, `sandbox.Exec`, the guest's own `exec` MCP tool) and the one
  place that decodes it (`runCommand`) were updated in lockstep, since this is a wire-protocol
  change. Verified live against a rebuilt guest image: an argument built from the four bytes
  `0x80 0x81 0x82 0x83` — not valid UTF-8 on their own — now round-trips through `kelyfos exec`
  byte-for-byte instead of coming back as four U+FFFD replacement characters.
- **A TOML array element containing a comma inside its own quotes broke parsing of the whole
  policy file.** `parseArray` (internal/config/config.go) split the raw bracket contents on every
  `,` with `strings.Split` before `parseString` ever saw an element, so `args = ["x", "--y=a,b"]`
  under `[[plugin]]` — or the same shape under `[sandbox]`/`[[team.agent]]` allow and secrets,
  spawn images, or store read/write — tore the second element in two at the internal comma and
  failed with a misleading "expected a quoted string" error instead of loading. The split is now
  a quote-aware scan (`splitTopLevel`): it walks the bracket contents tracking whether the cursor
  is inside a `"..."` string, honoring `\"` as an escaped quote that does not close it, and only
  splits on a comma seen outside quotes. Verified with the finding's own repro — a `kelyfos.toml`
  with `[[plugin]] args = ["x", "--y=a,b"]` — which now loads with the two-element array intact.
- **`resource.summary`, the usage receipt written once at teardown, was emitted from only two of
  the places a session actually ends.** `kelyfos run` and a team member's own `stop` sampled and
  wrote one; `kelyfos serve-mcp`'s per-sandbox `close()` (which also covers the two early-boot-
  failure paths in `servemcptools.go` that route through it), `kelyfos resume`, and `kelyfos
  snapshot restore` did not, so a session ending through any of those three doors left a
  `session.start`/`session.ready`/`session.end` chain with no receipt of what it actually spent in
  between. Each now samples and appends the same event immediately before its own `Shutdown`,
  following the pattern the two working sites already used. Separately,
  `internal/sandbox/network.go`'s `BlockedPackets` — the egress firewall's own nftables drop
  counter — had no caller anywhere in the product; it is now read into a new `blocked_packets`
  field on every `resource.summary` event (zero for a sandbox with no network interface at all,
  same as one that blocked nothing), through one small helper shared by every teardown path rather
  than a nil check repeated at each. Verified live in the Lima VM: a `kelyfos serve-mcp` session's
  sandbox now writes a `resource.summary` ahead of its `session.end`, and a `kelyfos run --allow`
  session that made a connection attempt outside its allowlist now reports a nonzero
  `blocked_packets` on that same event. `kelyfos bench`'s throwaway boot-timing VMs and the
  fork-template cache's own build-and-snapshot machine (`host/teamtemplate.go`) were left alone —
  neither opens a flight recorder session at all, by design, so instrumenting them is a bigger
  change than this pass covers. The third sub-item of this finding — giving `kelyfos.toml` parse
  errors and team-plan check errors their own `denial` catalog IDs — was left alone too: both
  already carry the file and line that produced them, and `docs/reference/denials.md`'s own banner
  already states, on purpose, that refusals from those two paths are excluded because "the thing to
  go and look at is the line you wrote" — reversing that is a product decision, not a gap.
- **`Append`'s own size backstop only looked at six of the event struct's fields, though its
  comment claimed to cover "whatever field made it that large."** `clipLargestField`
  (internal/recorder/recorder.go) named `Data`, `Args`, `Host`, `Path`, `Name` and `Cmd` by hand;
  an oversized value anywhere else — `EvError.Message`, `Reason`, `Tool`, and every other string
  field on `Event` — was invisible to it, so `fitUnderMaxLine`'s clip loop found nothing to clip,
  exhausted its attempt budget, and `Append` refused the whole event: the event vanished from the
  record instead of being clipped and kept, the same failure mode S1 closed for `Data` and `Host`
  specifically. No current caller can put an oversized value in one of the missed fields, so this
  was latent rather than reachable, but the backstop's whole point is to hold even for a door this
  code does not yet know about. `clipLargestField` now finds its candidate by walking the struct
  with reflection (`largestStringField`) instead of a hand-maintained list — every string field,
  plus the fields of `*EvError` — so a field added to `Event` next month is covered the day it
  lands rather than the day someone reads this function and remembers to add it. `Cmd` keeps its
  separate `[]string` handling, since reflection over string-kinded fields does not see it.
  `FuzzAppendFieldValues` now drives one event through `setAllStringFields`, its own independent
  reflective walk, so a future field reachable by that walk but missed by `clipLargestField`'s own
  walk fails the fuzz run rather than needing a code read to find. Verified with the finding's own
  repro — a 9 MiB `EvError.Message` on an otherwise-empty event — which failed closed before this
  fix (confirmed by temporarily disabling the new code path) and now clips and keeps the event,
  verifying like any other clipped field.
- **`shim.Policy.Secrets` held `[]egress.Secret` — values, not pointers — the one container in the
  product that broke the pattern every other secret-holding container follows.** `Secret.String()`
  deliberately has a pointer receiver so it can redact: a `*Secret` formats as
  `Secret{NAME@domain scheme=Bearer}`, but a bare `Secret` value is outside that method's receiver
  set, so a stray `%v`/`%+v` on it falls back to reflecting over the struct fields — including the
  unexported `value` holding the plaintext credential — and prints it. Nothing formats
  `shim.Policy` as a whole today, so the gap was dormant, but it stood next to `egress.Policy.Secrets`
  and every other secret container in this codebase, all of which already carry `[]*egress.Secret`
  for exactly this reason. `shim.Policy.Secrets` is now `[]*egress.Secret` too; `host/shim.go`'s
  population of it (`shimCmd`, from `--secret` and the policy file) appends the already-owned
  pointer instead of dereferencing it, and `shim/shim.go`'s use of the field when building the
  sandbox's `egress.Policy` collapses to a plain slice assignment now that the two field types
  match. `TestPolicySecretsNeverFormatTheirValue` (shim/policy_secrets_test.go) pins it: it builds a
  `Policy` with a real parsed secret and asserts `%v`/`%+v` on the `Policy`, on `Policy.Secrets`, and
  on a `Secrets` element never contain the token, the same shape `TestSecretValueNeverFormats`
  already pins for a bare `Secret`.
- **`kelyfos runs --all` treated a locked-down or otherwise unreadable session directory as if it
  had never existed, in silence.** `readRun` (host/runs.go) passed every `os.Open` error, not just
  the "no such session" case, through the same bare `false` its caller reads as "nothing here" —
  so a permission-denied directory (or any other read error) vanished from the listing exactly like
  a directory that genuinely was not a session, with nothing distinguishing the two. docs/events.md
  §6 states the listing's guarantee as a count, "one row per session directory, no more and no
  fewer," which a silent drop breaks. `readRun` now returns its error separately from its found/not-
  found bool: `os.IsNotExist` still means "no session, say nothing," the same as before, but any
  other error — permission denied, an I/O error — is reported by `readRuns` as a
  `kelyfos: could not read session <id>: <err>` line on stderr instead of being folded into
  "missing." Verified live in the Lima VM with the finding's own repro: two session directories, one
  `chmod 000`'d — `kelyfos runs --all` now lists the readable one and warns about the other, where
  the prior binary listed only the readable one with no warning at all.
- **The host and supervisor MCP argument summarisers were two independent, byte-for-byte duplicated
  implementations — `summariseArgs` (host/servemcpaudit.go) and `summarisePluginArgs`
  (supervisor/pluginhost.go), each with its own copy of the `maxArgBytes`/`maxArgsBytes`/
  `maxArrayBytes` constants and its own copy of `clipUTF8`.** They were in exact lock-step by
  discipline rather than by construction: the shared low-level `proto.SafeText` the pair both call
  is genuinely unified, but nothing stopped a future edit to one copy's redaction or bounding rules
  from landing without the other, which would have made a supervisor-recorded plugin call redact
  differently from a host-recorded tool call with no way to notice. The shared logic — key sorting,
  `contentKeys` handling, the compact/clip rendering, the `maxArgsBytes` line budget, and `clipUTF8`
  itself — now lives once, in a new `internal/argsummary` package both binaries import; only what is
  genuinely caller-specific stayed local (host's `clipField`, which also bounds the tool name and
  sandbox id fields `summariseArgs` never touched). `contentKeys` and the three size constants are
  identical between the two callers, so those moved whole rather than being kept as two decisions
  that happened to agree. Both `summariseArgs` and `summarisePluginArgs` are now one-line wrappers
  over `argsummary.Summarise`; every existing test in both packages, and both fuzz targets, pass
  unchanged against the shared implementation, and `internal/argsummary` carries its own test suite
  covering the same guarantees directly.
- **`dev/demo-team.sh`'s teardown check false-failed on a shared host.** Step 6 asked `pgrep
  firecracker` a host-wide question — whether *any* Firecracker process exists anywhere on the
  machine — after tearing down its own five (or six, with the step-5 spawn) sandboxes, so any
  unrelated Firecracker session running alongside it on a shared dev box reported a teardown leak
  even though the demo's own VMs came down cleanly (F18, reproduced live during the security
  review that found it). The script already tracks each agent's sandbox ID in `$M`/`$W1`-`$W4` (and
  the step-5 spawn in `$NEW`) to report per-agent PASS/FAIL earlier in the run, so those are reused
  rather than adding new tracking: before `team down` runs, it now reads each sandbox's own
  `firecracker.pid` from `$RUN_ROOT/firecracker/<sandbox-id>/root/` — the same jail run-directory
  `internal/sandbox.jailRunDir` builds — and after teardown it asserts specifically that none of
  those PIDs are still alive, rather than asking whether Firecracker is running anywhere on the
  host.
- **`kelyfos snapshot restore` could write its `resource.summary` receipt after the `session.end`
  that is supposed to close the chain.** F14's fix wired `resource.summary` into a `defer`
  registered right after `sandbox.Restore` succeeds, but the CA-install-error, interrupted
  (Ctrl-C), and `vm_exited` exits still appended `session.end` inline, immediately before their
  own `return` — code that runs *after* that defer was registered, so on every one of those three
  paths the defer necessarily unwound afterward, writing `resource.summary` behind an event
  `docs/events.md` documents as the one that closes the file. `session.end` is now written from its
  own `defer`, registered before the resource-summary one so defers unwind last-registered-first
  and it fires second, the same ordering `run.go`'s own `reason`/`session.end` defer already keeps
  against its usage defer; the three sites set a `reason` variable instead of appending inline.
  Verified live in the Lima VM: a restored sandbox's `-json` log now shows `resource.summary`
  immediately ahead of `session.end` on both the interrupted and the `vm_exited` path.
- **`TestSnapshotRestoreRealVMWiresAuditBeforeResume` asserted through a binary the guest image
  doesn't carry, and silently discarded the exit code that would have said so (F20) — not a gap in
  S2/P6-4's restore-audit fix.** `guestEgressAttempt` drove the guest with `curl`, and its own doc
  comment claimed curl is what the base and dev image flavors both carry;
  `image/flavors/base/buildroot.fragment` says the opposite — base is "BusyBox and musl and nothing
  else. No TLS client" — curl is dev-only (`BR2_PACKAGE_LIBCURL_CURL`, in the dev fragment), and
  `requireRealSandbox` never asks for the dev flavor specifically. On a base-flavor guest, which is
  what this VM normally builds, the guest's shell answered "curl: not found" with `EXIT=127`, no
  request was ever made, and the exit status was thrown away, so a missing binary looked identical
  from the caller's side to a connection error. `fixed_order_captures_the_attempt` failed on both
  its assertions as a result, while `old_order_missed_the_attempt` passed regardless — it only
  checks for the ABSENCE of `egress.attempt`/`secret.withheld`, which is guaranteed whether or not a
  real attempt was made, so the guard subtest meant to prove its sibling meaningful reported green
  in exactly the situation where neither subtest proved anything. `guestEgressAttempt` now drives
  the guest with BusyBox wget, which both flavors carry, and returns its exit code instead of
  dropping it; both subtests now assert that code is not 127, failing loudly and by name rather than
  proceeding on a false premise. That alone only closes one way to no-op, so both subtests also
  count real hits on the upstream test server and assert the count moved: `forwardHTTP`
  (`internal/egress/proxy.go`) reaches it over a genuine `RoundTrip` whether or not
  `OnEvent`/`OnSecret`/`OnWithheld` are wired, so a rising count proves a request truly landed there
  — independent of the recorder chain the old-order subtest is busy saying is silent. Root-caused by
  the repository owner's review of PR #6, who re-ran the fixed ordering by hand against the same
  base image with wget in place of curl and got the correct events in the correct order, confirming
  S2/P6-4 works correctly on real hardware and this was always a test bug.

### Changed
- **A `kelyfos.toml` combining `[team]` with `[[plugin]]` or `[[forward]]` is now refused by `kelyfos
  team up` (and `serve-mcp`'s `team_up`), at plan time, instead of silently booting a team where
  neither did anything.** Both keys are file-level and always parsed next to an ordinary `[team]`
  section, but `packPlugins` and `resolveForwards` — the two functions that actually launch a plugin
  or open a forward — are only ever called from the single-sandbox doors (`kelyfos run`,
  `serve-mcp`'s own sandbox), never from a team boot. A file naming either alongside `[team]` used to
  load without complaint and produce a team with no plugin tools advertised and no forwarded port
  listening; it is now refused by name, with the line, and with the fix (drop the block, or run that
  plugin or forward outside `[team]`). Ruled not a breaking change (D66): the combination never
  worked, so nothing that depended on its effect can be broken by this — only the earlier silence
  about it. `[[plugin]]` and `[[forward]]` continue to work exactly as before outside `[team]`.

---

## v1.0 — 2026-08-25

The promise release. Everything below is in it.

Built by `.github/workflows/release.yml` from this tag's own commit — the first
release this project did not assemble by hand. `v1.0-rc1` and `v1.0-rc2` came
first, deliberately: rc1's build failed at the SBOM attestation, which is a step
no release had ever run, and rc2 is the one the quickstart numbers above were
measured against. This tag is byte-identical to rc2 in everything that builds;
what changed between them is documentation.

### Added
- **A compatibility promise** — [`docs/compatibility.md`](docs/compatibility.md):
  what stabilises, what deliberately does not, and a deprecation mechanism that
  did not exist. Guest confinement profiles are explicitly allowed to narrow in a
  minor release, because a profile that cannot be tightened without a major
  release is a profile nobody tightens.
- **Signed exports.** `kelyfos log --export --sign-key` signs a report with an
  ed25519 key of yours; `kelyfos verify --key` checks it against a key the reader
  already holds rather than one the file supplied itself.
- **`kelyfos verify`** — re-runs the hash chain over an exported report offline,
  on a machine with no sandbox and no guest. The record travels inside the HTML.
- **`kelyfos connect <client>`** writes six clients' own MCP configuration in
  their own formats and locations; `--check` starts the server it just configured
  and completes a real MCP handshake.
- **A macOS build of the CLI.** `doctor` owns the Lima layer, `verify` checks a
  report somebody sent you, and every command that needs a guest refuses with the
  way in. It is a smaller program than the Linux one and says so.
- **The release is a workflow**, not a laptop: both architectures from the tag's
  own commit, `SHA256SUMS` regenerated from scratch and checked in both
  directions, provenance and SBOM attestations, and an SBOM per architecture
  covering all three places an image comes from.
- **`CHANGELOG.md`, [`docs/upgrading.md`](docs/upgrading.md)**, and issue and
  pull-request templates.

### Fixed
- **The audit chain stopped reporting legitimate records as tampered with.**
  Verification now works from the bytes as written rather than by re-marshalling,
  so a reader tolerates a field it has never heard of, and a record with no
  digests is refused instead of passing.
- **A guest-authored directory entry could decide where the host wrote.** The
  workspace block device is a guest→host surface the threat model did not list.
  Every entry is now validated and the image refused whole if one carries a name
  the host cannot use, and extraction goes through `openat2` with
  `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, so a name that got past the check
  still cannot leave the tree. Reported by an external security audit.
- **`write_file` and `upload` could write anywhere the guest asked**, including
  the block devices the confinement profile deliberately withholds, because the
  supervisor is PID 1 and the profile does not confine it. Both are now held to
  the same three lists the profile is built from.
- **`--review` no longer destroys an edit made while somebody was reading it.**
  The workspace is re-fingerprinted immediately before the rename and diverted on
  a mismatch, and the previous tree is kept until the next successful run.
- **A credential bound with a path now binds one endpoint** rather than expanding
  to subdomains, and is withheld — with a `secret.withheld` event saying which and
  why — from a request whose `Host` header disagrees with the host the guest asked
  to connect to.
- Exhaustion clamps: a timeout ceiling, key-count and key-size accounting in the
  team store with a delete that makes it smaller, a bounded output total per
  command, and a refusal that records a digest rather than a body.

### Documentation
- **Every hand-written document re-read against the code that implements it.**
  174 confirmed findings across 21 documents, 157 corrected. The record is
  [`dev/docs-audit-2026-08-25.md`](dev/docs-audit-2026-08-25.md). It also found
  eighteen defects in the code.

---

## v0.9 — 2026-08-24
### the boundary is the hardware, and everything around it is locked too

The hardening release. Every release before it said "not hardened yet", and that
was true: KelyfOS relied on the boundary Firecracker gives it and added nothing
of its own around the VMM process or inside the guest.

### Added
- **The VMM runs inside the jailer** — a chroot holding only this sandbox's
  files, a dropped uid, `no_new_privs`, only the device nodes it needs, and the
  run's cgroup where the policy set a quota. Every entry point or none: `run`,
  `team up`, `fork`, `snapshot restore`, `serve-mcp` and the shim all go through
  one refusal.
- **Firecracker's own seccomp filter is read out of `/proc` on every one of its
  threads** at boot and the VMM refused if it is absent — rather than assumed
  from the absence of a `--no-seccomp` flag.
- **Everything the guest's supervisor spawns is confined by Landlock** and a
  seccomp refusal list, per flavor, generated into
  [`docs/reference/profiles.md`](docs/reference/profiles.md) from the code that
  enforces it.
- **The record names which walls were around each machine**, so a transcript
  cannot make an unconfined run look like a confined one.

### Breaking changes
1. **A guest command that writes outside `/work`, `/tmp`, `/run` and `$HOME` is
   refused.** It succeeded before. One of this project's own cookbook recipes did
   exactly that — `mkdir /prepared` at the filesystem root — and now prepares in
   `/tmp`. There is no way to permit that and still refuse `/etc`: a Landlock rule
   covers a tree, so granting the root grants everything under it.
2. **A snapshot taken before v0.9 restores into the guest it captured, which
   confines nothing it spawns.** Warned about rather than refused — the host walls
   are properties of the run you are starting now and all still apply, so refusing
   would make old snapshots unusable to buy nothing. See
   [`docs/upgrading.md`](docs/upgrading.md).
3. **Attaching a debugger to a process already running inside a guest fails**
   with `Operation not permitted`, on every flavor including `dev`. Each confined
   process gets its own Landlock domain and Landlock refuses `ptrace` between
   siblings. Launching a program *under* a debugger still works, because a child
   inherits its parent's domain.

---

## v0.8 — 2026-08-23
### the daily driver feels like one

### Added
- **`kelyfos pause` and `kelyfos resume`** — stop for the day and pick up the
  same machine tomorrow, not a copy of its files.
- **`--review`** shows what changed in the workspace before you keep it.
- **A real terminal** — `kelyfos shell`, with a pty, resizes and signals.
- **Port forwarding** — `kelyfos run -p 8080:80` and `[[forward]]` in
  `kelyfos.toml` reach a server inside the sandbox.
- **Every refusal names its own fix**, with a stable identifier scripts can
  branch on, generated into [`docs/reference/denials.md`](docs/reference/denials.md).
- **`kelyfos runs`** lists what has run here, and `kelyfos rerun` runs one again.
- **A desktop notification** when a run finishes and you have walked away.

---

## v0.7 — 2026-08-23
### any MCP client can drive it; any MCP server can run inside it

### Added
- **`kelyfos serve-mcp`** — KelyfOS itself as an MCP server, so any client can
  boot, run, snapshot and fork sandboxes as tools. The policy is the ceiling and
  no tool can raise it.
- **`[[plugin]]` servers inside the guest**, with namespaced tools. A plugin that
  dies costs its own tools and nothing else.
- **Prepare once, fork many** — snapshot a machine you have set up, then bring it
  back repeatedly.
- The MCP channel carries whole files: its frame limit is 16 MiB rather than the
  1 MiB the rest of the protocol uses.
- A restore is held to the policy, and snapshots record how large a machine they
  came from.

---

## v0.6 — 2026-08-23
### any LLM can build on KelyfOS from the docs alone

### Added
- **The reference is generated from the source and CI fails when it drifts** —
  every command, flag, `kelyfos.toml` key, MCP tool, event and exit code.
- **The cookbook's recipes are executed**, not illustrated: CI extracts each one
  and runs it on a real machine.
- **`llms.txt` and `llms-full.txt`** for machine readers, per the llmstxt.org
  spec.

### Documentation
- The first documentation inventory read every document against the code and
  found real drift, including a normative document that had gone two epics
  without being touched. It also found four defects that were product work rather
  than documentation, recorded rather than fixed.

---

## v0.5 — 2026-08-23
### agent teams as code

### Added
- **`[team]` in `kelyfos.toml`** declares agents and the edges between them;
  `kelyfos team up` boots the graph. Master/workers, a pipeline, a mesh.
- **A broker** carries messages along declared edges only, and refuses the rest
  with a recorded `team.refused`.
- **A team store**, shared by default and narrowed per key.
- **One team, one transcript** — every member's events in one chain.
- **Resource budgets that compose**: per-agent caps inside a team-wide ceiling.

---

## v0.4 — 2026-08-23
### the user decides how much machine the agent gets

### Added
- **`[resources]` in `kelyfos.toml`** — `cpus`, `cpu_quota`, `mem`, `disk`,
  `scratch`, `net_mbps_rx`/`tx`, `disk_iops`, `disk_mbps`, `max_runtime`,
  `idle_timeout`. Every cap is imposed on the host, because a limit the guest
  applies to itself is advisory at best.
- **`[resources]` are ceilings, not defaults.** `--cpus 8` against `cpus = 2`
  refuses at boot and names the line it came from rather than quietly clamping.
- **`bash dev/prove-caps.sh`** drives each cap past its limit and checks it held.

---

## v0.3 — 2026-08-22
### a sandbox an agent can only reach through tools

The first announced release. `v0.3-rc1` was tagged the same day and is the same
tree.

### Added
- **One command hands an agent a sandbox**: `kelyfos run --workspace . --allow
  github.com -- claude`.
- **Egress is off, not filtered.** No `--allow` means no network interface
  exists at all.
- **Secrets never enter the guest.** The host's proxy attaches them on the way
  out; `env` inside the sandbox shows nothing.
- **A host-written, hash-chained audit record**, with `kelyfos log --verify`, a
  standalone HTML export, and a live `kelyfos watch`.
- **Snapshots and forks.**

---

## v0.2 — 2026-08-22
### a toolbox, not a computer

Tagged at the end of phase 2; no release was published. The guest supervisor
exposes itself as MCP tools — `exec`, `read_file`, `write_file`, `list_dir`,
`upload`, `download` — over vsock, and there is no shell login and no SSH.

---

## v0.1 — 2026-08-22
### it boots

Tagged at the end of phase 1; no release was published. A minimal bootable
Buildroot guest with a supervisor on vsock.

---

## v0.0 — 2026-08-22
### environment and scaffold

Tagged at the end of phase 0; no release was published. The pinned toolchain,
the repository layout, and an acceptance test that passed.
