# KelyfOS egress

**Status:** normative for v0.x. Written at P2-5, with secret injection added by
P2-6 and the restore path by D22. The threat-model discussion lives in
[`docs/threat-model.md`](threat-model.md).

## 1. The default is no network

A sandbox whose allowlist is empty has **no network interface at all**. Not a
firewalled one, not one with an allowlist that permits nothing — no NIC. There
is nothing to misconfigure, and no rule that has to hold for the guarantee to be
true.

A non-empty allowlist is what creates a NIC, and it creates one whose only
reachable destination is a proxy on the host. `--allow github.com,pypi.org`
writes that list on the command line; the `allow` key under `[sandbox]` in
`kelyfos.toml` fills it when the flag was not typed, so a sandbox started with
no `--allow` at all, in a project whose policy file has an `allow` list, does
get a NIC.

## 2. Topology

```
   guest                            host
   ┌─────────────────┐              ┌────────────────────────────────┐
   │ eth0            │              │ kelyfos<id>  (TAP)             │
   │ 169.254.a.b+1   │═════════════▶│ 169.254.a.b                    │
   │                 │  virtio-net  │    │                           │
   │ HTTPS_PROXY =   │              │    ├─ nftables: only the proxy │
   │ http://host:port│              │    │                           │
   └─────────────────┘              │    └─▶ egress proxy ─▶ internet│
                                    │         allowlist + audit      │
                                    └────────────────────────────────┘
```

Point-to-point /30 per sandbox, carved out of **169.254.0.0/16** — link-local
space (RFC 3927), which nothing routes and no site allocates, so a sandbox
cannot collide with the host's real networks.

**One address in that range is the exception, and it is reserved.**
`169.254.169.254` is the cloud instance metadata address — AWS, GCP, Azure and
every hypervisor that copied them — so it is routed on exactly the machines
KelyfOS is most likely to run on. The /30 that contains it,
`169.254.169.252/30`, is therefore never handed to a sandbox. Left in, it would
have arrived for one sandbox id in 16,384: `ip addr add` installs a connected
route for the whole /30, and on a host carrying the usual /32 route for the
metadata address the longest prefix wins, so the *sandbox* is what breaks —
the proxy's replies leave by the physical NIC instead of the TAP, and egress
hangs with no error anywhere. On a host that reaches its metadata through a
broader route, the host's own metadata is what goes instead. Either way the
symptom is a hang, which is the hardest kind of failure to attribute.

The /30 index is derived from the sandbox id rather than handed out by a
counter, so two `kelyfos run` invocations cannot race for a range; a collision
retries with the next index, and so does the reserved index above — advancing
costs one of the thirty-two tries and the next index is an ordinary /30. The
host takes the first usable address and the guest the second, and the proxy's
port is kernel-assigned rather than fixed, which is why every example here
writes it as a placeholder.

**No NAT and no IP forwarding**, and neither is missing by accident — nothing
needs them. The proxy binds directly on the host's TAP address, so guest traffic
terminates on the host. The only process that
reaches the internet on the guest's behalf is the proxy, which means the
allowlist is not a filter the guest routes through; it is the only door.

## 3. The nftables template

One table per sandbox, named after it, so teardown is a single delete and two
sandboxes can never interfere:

```
table inet kelyfos_<id> {
        chain input {
                type filter hook input priority filter; policy accept;
                ip daddr <host_ip> iifname != "<tap>" counter drop
                iifname "<tap>" jump kelyfos_guest_in
        }

        chain kelyfos_guest_in {
                ip daddr <host_ip> tcp dport <proxy_port> accept
                counter drop
        }

        chain forward {
                type filter hook forward priority filter; policy accept;
                iifname "<tap>" counter drop
                oifname "<tap>" counter drop
        }
}
```

Three details are deliberate and easy to get wrong:

- **The base chains have `policy accept`, not `policy drop`.** A base chain on
  the `input` hook with a drop policy filters *all* traffic to the host, not
  only the sandbox's — on a developer's machine that means locking yourself out
  of your own box the first time you run `kelyfos`. Isolation comes from
  matching `iifname` and dropping explicitly, which affects nothing else.
- **The first line of `input` is what makes `<host_ip>` private**, and it is not
  a faster spelling of the jump below it. An address on a TAP is a local address
  of the host like any other, so a *local process's* connection to it never
  reaches the TAP at all: the kernel routes it over `lo`, the jump's `iifname`
  match never fires, the packet falls through to `policy accept`, and the proxy
  — with the operator's credentials attached — answers whoever asked. Measured,
  not argued: with only the jump in place, a process on the host dialling
  `<host_ip>:<proxy_port>` is served, and the source address the kernel picks
  for it is `<host_ip>` itself. Matching on the destination and dropping
  anything that did not arrive on this sandbox's own interface closes that, and
  closes the LAN case with it — a packet for `<host_ip>` that arrives on the
  physical NIC because the host answered ARP for it has `iifname != <tap>` too,
  and the same line drops it. The guest's packets do arrive on the TAP and reach
  the jump exactly as before. This was F9 of the 2026-08-28 review; the proxy's
  own `Peer` check is the other half, and each is there for the day the other is
  wrong.
- **`forward` drops in both directions.** IP forwarding is off and nothing turns
  it on, but a rule that states the intent survives someone else's sysctl.

Each drop carries a `counter`, which `nft list table` will show you.

**The `input` chain's counter is deliberately not part of `blocked_packets`.**
The session receipt's figure is the guest's — `resource.summary` documents it
beside numbers it calls "from the guest's point of view" — and the drops in
`kelyfos_guest_in` and `forward` are all packets this sandbox sent or would
have received. The F9 rule's are not: they are packets *somebody else*
addressed to the host's TAP address, from another process on this machine, from
another sandbox, or from the physical segment. Adding them in would attribute
another party's traffic to this sandbox's receipt. `BlockedPackets()` therefore
sums every chain but `input`, and `ForeignPacketsDropped()` reads that one on
its own.

### 3.0 The guest always has a loopback interface

`lo` is brought up by the supervisor at boot, whether or not this sandbox has a
NIC. Without it the kernel leaves loopback DOWN on a machine with no `ip=`
argument, and nothing inside can bind or reach `127.0.0.1` — which the E5 exit
found the hard way, because a forwarded port dials exactly that (F-D55).

Loopback is not a network path to anywhere: no packet on `lo` can leave the
machine, by definition. Leaving it down denies a sandbox the ability to talk to
itself — a local server, a runtime's own health check, a test suite binding
`127.0.0.1` — and buys nothing.

### 3.1 A forwarded port adds nothing to this

`kelyfos run -p 8080:80` makes a server inside the sandbox reachable from the
host, and **the ruleset above is unchanged** — same table, same chains, same
rules, byte for byte. There is no `dnat`, no accept, and no rule anywhere that
mentions a forwarded port.

It works because no packet crosses the TAP. The host binds a listener on its own
loopback; each connection it accepts becomes a vsock connection to the
supervisor; the supervisor dials `127.0.0.1` **inside the guest**. The packet
that reaches the server is created inside the machine, on its own loopback, so
there is nothing at the interface for a firewall rule to have an opinion about
(F-D7, `protocol.md` §5.8).

That is the whole reason the feature is allowed to exist. The network layer's
guarantee is that nothing reaches the guest from outside, it is enforced here,
and a forward that added a rule would be a hole in it. `dev/accept-forward.sh`
captures the ruleset with two forwards and with none and diffs them.

Loopback is also where the *host* listener binds. `--p-bind 0.0.0.0` is the way
to put it on the LAN, it warns every time, and no key in `kelyfos.toml` does it:
a LAN exposure should be something somebody typed in the session where it
happened rather than a line in a file somebody inherited.

## 4. No DNS in the guest (decision D16)

There is no DNS responder on the TAP address, nothing in the guest's
`/etc/resolv.conf`, and UDP/53 is dropped along with everything else.

A guest configured with `HTTPS_PROXY` never resolves anything: it sends
`CONNECT github.com:443` to the proxy, and the proxy is what resolves. Worth
being exact about the order, because it is the reason the allowlist means
anything: **the decision is made on the name, before any resolution happens.**
The proxy matches `github.com` against the allowlist as a string and only then
dials, so there is no window in which a name resolves to an address that is then
checked. DNS in the guest is not load-bearing for any traffic KelyfOS intends to
permit, and DNS anywhere is not load-bearing for the policy.

Removing it closes the oldest hole in every allowlist. DNS tunnelling defeats a
domain allowlist completely — the data leaves inside query names, to a resolver
that was explicitly permitted, and a policy that checks hostnames cannot see it.
A prompt-injected agent with UDP/53 to anywhere has a covert channel however
careful the HTTP rules are.

The cost, stated plainly: anything that resolves before connecting — `ping`, raw
sockets, a library that ignores proxy environment variables — fails. For a
deny-all sandbox that is the correct failure.

### 4.1 The name is checked first, and then the address it resolved to

Deciding on the name is what makes the allowlist mean anything, and it is not
sufficient on its own: an allowlisted domain that is hijacked, expired or simply
taken over can resolve wherever its new owner likes, and the classic destination
is `169.254.169.254`, the cloud instance metadata endpoint — on port 80, already
inside the proxy's permitted port set. So there is a second check, on the
address, at the one point every dial passes through: `net.Dialer.Control`, which
fires once per address a resolver hands back, after resolution and immediately
before the connect syscall. A domain with several A/AAAA records is checked on
each attempt Go's Happy Eyeballs fallback makes, not merely on its first, and a
refusal there means nothing was sent and nothing was read.

The refused ranges are a table with a comment per entry, not a stack of
predicates. `internal/egress/dial.go` holds it; the ranges are RFC 1122's
`0.0.0.0/8`, RFC 1918 private space, **RFC 6598 CGNAT `100.64.0.0/10`** — where
Alibaba Cloud's metadata service lives, at `100.100.100.200`, and where every
Tailscale and WireGuard mesh peer lives — loopback, link-local, RFC 6890's IETF
protocol block, the three documentation ranges, RFC 2544 benchmarking space,
multicast, RFC 1112's reserved `240.0.0.0/4` with the broadcast address in it,
and the v6 equivalents. Two entries are not ranges in the ordinary sense:

- **`168.63.129.16/32`** is the Azure wireserver: the instance metadata endpoint
  on every Azure VM, sitting in ordinary public address space. No range rule
  will ever catch it, so it has a line of its own.
- **NAT64 `64:ff9b::/96`, 6to4 `2002::/16` and the deprecated IPv4-compatible
  `::/96`** are not refused as prefixes — `64:ff9b::8.8.8.8` is a legitimate way
  to reach `8.8.8.8`. The v4 address they carry inside is extracted and checked
  against the same table, which is what refuses `64:ff9b::a9fe:a9fe`: the
  metadata address wearing a v6 costume. 6to4 matters for the same reason in
  reverse — a host with 6to4 configured really does put IPv4 packets on the wire
  to the embedded address.

**The proxy never chains to another proxy.** Both upstream transports are built
field by field from a zero value, with `Proxy` deliberately nil, so a host whose
environment carries `HTTPS_PROXY` or `HTTP_PROXY` — every corporate laptop —
does not send the sandbox's traffic there. This is not only a routing
preference: an upstream proxy is what would then resolve the name, so the
address check above would be asked about the corporate proxy rather than about
where the allowlisted domain actually points, and the whole of §4.1 would be
routed around on the plain-HTTP and direct-TLS paths. The `CONNECT` tunnel and
the terminated leg always dialled directly, so the behaviour used to differ by
path with nothing saying so (F15).

**The refusal names no address to the guest.** It says the name "resolved to an
address this proxy will not dial", and the address goes to the flight recorder
as the attempt's `resolved_addr`. A guest that is told where an allowlisted name
resolves has been handed the result of a DNS lookup it has no resolver to
perform — one allowlisted name at a time, that is a map of the host's network.
The operator is the one who needs the address, and the operator reads the
record (F14).

## 5. What the guest is told

The NIC is configured by the kernel from the boot arguments, so nothing in the
guest has to be trusted to bring the network up correctly:

```
ip=<guest_ip>::<host_ip>:<netmask>::eth0:off
kelyfos.proxy=<host_ip>:<proxy_port>
```

`ip=` is handled by `CONFIG_IP_PNP` before userspace starts. The supervisor
reads `kelyfos.proxy` from `/proc/cmdline` and puts it in the environment every
command inherits:

```
HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy  = http://<host_ip>:<port>
NO_PROXY, no_proxy                                = localhost,127.0.0.1
```

Both cases are set because the convention is split down the middle: curl and
most C programs read the lowercase form, Go and much of the JVM world read the
uppercase one.

When a secret is bound to a domain, the guest is also handed the trust anchor
for the run's CA — over the `control` channel after boot, never on the kernel
command line — written to `/etc/ssl/certs/kelyfos-egress-ca.pem`, appended to
`/etc/ssl/certs/ca-certificates.crt` and `/etc/ssl/cert.pem`, and named by five
more variables:

```
SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE,
NODE_EXTRA_CA_CERTS, GIT_SSL_CAINFO   = /etc/ssl/certs/kelyfos-egress-ca.pem
```

Five rather than one because the usual defeater of a system trust store is that
nothing uses it: Python's `certifi` and Node's bundled roots ship their own. The
guest is KelyfOS's own image, so these can be set authoritatively instead of
hoped for.

One capability note this image's own build makes true (IA-I3): the guest's
`python3.12` is built WITHOUT the `_ssl` module, so five of these six
variables are inert for Python inside the guest — a Python client cannot
terminate TLS against the CA no matter what the environment says. TLS-level
work from the guest goes through `curl`, which is present and honours the
store. Nothing security-critical rides on it: the terminated leg belongs to
the proxy either way.

## 6. What the proxy enforces

- `CONNECT host:port`, absolute-URI HTTP requests and origin-form ones — a bare
  `GET /path` with a `Host:` header — are accepted only when `host` matches the
  allowlist: the target is read from the URL when it carries a host and from
  `Host:` otherwise, so every shape is decided against the same string. A bare
  hostname matches itself and its subdomains, so `--allow github.com` also
  permits `api.github.com`. A leading `*.` is stripped rather than read as a
  wildcard, so `--allow *.github.com` normalises to `github.com` and permits the
  apex too; the same normalisation lower-cases the entry and trims trailing
  dots.
- **Ports are restricted to 80 and 443, for every sandbox this product boots,
  and there is no `kelyfos.toml` key that widens that.** This is a fixed
  property of the proxy rather than an omission: `egress.Policy` has a `Ports`
  field, but nothing in this codebase ever sets it — every `Policy` this
  product constructs leaves it empty, which is why `egress.DefaultPorts()`
  (`80`, `443`) is what actually applies, always. `Policy.EffectivePorts()` is
  the one place that fact is computed; today `allowsPort` is its only caller,
  and it is what P7-2's `session.policy` and the P7-7/P7-8 views will read
  once they exist, instead of the field directly, because the field alone
  reads as "nothing is permitted" rather than "the fixed default applies"
  (P7-4, D65). Promoting
  `Ports` to a real key was considered and set aside: nothing has asked for a
  sandbox that can reach an arbitrary port, and widening what every sandbox in
  this product can reach is a bigger, more security-relevant change than
  fixing the fact that the existing, correct default was invisible.
- **The proxy serves one address and closes every other connection unread.**
  `Peer` is the guest's own end of the /30, and a connection from anywhere else
  is closed before a byte is read from it, before a deadline is set, and before
  anything can attach a credential on its behalf — recorded as an
  `egress.attempt` with reason `foreign_peer`, and answered with nothing at all.
  No status line, no fix line, no confirmation that there is a proxy here:
  everything the guest is told exists to help the guest, and a caller that is
  not the guest is not owed it. Because no request was ever parsed there is no
  destination to name, so `host` and `port` are absent on those events and the
  address the connection came from is in `peer` — the same field a team
  delivery and a forwarded port already use for "who connected". It is not put
  in `host`: `kelyfos log`, `kelyfos view`, `kelyfos watch`, the HTML report and
  the digest all read `host` as somewhere the sandbox tried to reach, and the
  digest counts it against that domain, so a source address there would make
  five readers say the guest named a host it never named. One event per
  distinct address, not one per connection: this is the only refusal here a
  local process can drive in a loop without the guest doing any work.
  **The address is in the chain and every reader shows it.** `kelyfos log`,
  `kelyfos view`, `kelyfos watch` and the exported HTML report all print
  `from <address>` on such a refusal, so it is distinguishable on screen from an
  ordinary blocked egress with an empty host. Every one of them puts the peer
  through the guest-text sanitiser first, because it is an address a local
  process chose. It is deliberately kept out of the digest's per-domain table
  and its blocked count: those are the sandbox's receipt, and a knock from
  somewhere else on the machine is not the sandbox's traffic.
  The other half of this is the ruleset's own `ip daddr … iifname != …` drop in
  §3; the address the proxy binds is not, and never was, what kept the port
  private (F9).
- A refusal is answered with `403` and a body naming the domain and the edit
  that would allow it (`[egress.host]` in [`denials.md`](denials.md)). For plain
  HTTP the guest reads it; for a refused `CONNECT` most clients discard the
  body, so the host prints the same refusal once, on its own stderr — `kelyfos
  run`, `team up` and `snapshot restore` do; `serve-mcp` and the shim record it
  without printing, because there is no terminal of yours to print to.
- Every attempt is written to the flight recorder as an `egress.attempt` event,
  allowed or blocked, with the reason and the byte counts
  (`docs/events.md` §4).
- Allowed connections record `mode`, which says **how much of the connection the
  proxy could read**. Four values, and the distinction is the whole point of
  the field (decision D6):

  | `mode` | What the proxy saw |
  | --- | --- |
  | `tunnelled` | Nothing. A `CONNECT` relayed without being opened. |
  | `terminated` | Everything. A secret is bound to this domain, so the session was decrypted to attach the credential. |

  A credential's HOST scope is the same dot-anchored match the allowlist
  uses: bound to `example.com`, it attaches on `www.example.com` too — pinned
  by the security suite as IA-I1 describes, and stated here so nobody has to
  discover it from the record. Path scopes, by contrast, are exact; a path
  never covers a prefix.
  | `plain` | Everything. An ordinary HTTP request, which any proxy that forwards it necessarily parses, rewrites and re-issues. Nothing was decrypted because nothing was encrypted. |
  | `direct_tls` | Everything. An absolute-form request naming an `https://` target, sent straight to the proxy with no `CONNECT` — the proxy fetches it anyway, over a real, certificate-validated TLS connection it performs itself, so something genuinely was encrypted even though no `CONNECT` or termination was involved. |

  `plain` exists because the alternative was recording it as `tunnelled`, and
  that is the one thing this field must never do: **understate what the host
  could see.** Anyone grepping for `terminated` to find the traffic the proxy
  read would have missed every plaintext request on port 80 (F-D33). `direct_tls`
  exists for the same reason, the other way round: recording it as `plain` would
  claim nothing was encrypted about a fetch that used real TLS, which is exactly
  the kind of understatement `plain` was added to prevent.

- **A terminated connection is bounded, and one of those bounds is a ceiling
  rather than a rule the guest can satisfy.** It is the expensive kind — the proxy has decrypted it,
  it is holding a credential for it, and it occupies one of the 128 connection
  slots — and until F16 nothing limited it once the `CONNECT` was answered. That
  now includes the inner TLS handshake, which sits between the moment the raw
  connection's own deadline is cleared and the moment the terminated leg's clock
  exists, and so had no bound in either direction: five bytes of a truncated TLS
  record header held a slot for as long as the guest cared to wait, measured at
  forty-five seconds. It gets the same ten seconds a header block gets, applied
  to both directions at once, since a handshake nobody is reading is stuck
  exactly as surely as one nobody is sending. The
  first request on a raw connection has always had a 1 MiB header budget and a
  10-second header deadline; both were cleared before the terminated leg began,
  which then parsed every further request itself with no ceiling of any kind.
  Go supplies none either: a 16 MiB header line parses into memory without
  complaint, measured. So, per request: the same 1 MiB budget, reset each time
  and released before the body so a transfer is never charged to a header; and
  the same 10-second deadline, started when the first byte of the request
  actually arrives rather than when the proxy began waiting. That 10 seconds
  is the ceiling the code names; the cut arrives well inside it in practice
  — about two seconds, measured against a dribbling client — so anything
  slower than a couple of seconds per byte-drip is already gone. The gap *between*
  two requests is a different thing — a client thinking, not a client stalling —
  so it gets two minutes, with ten minutes as the total a connection may spend
  idle across its whole life, and 4096 as the most requests one may carry. A
  header block over budget is answered `431`, recorded as `header_too_large`,
  and the connection closes after a short bounded drain so the refusal is not
  discarded by the reset that closing on unread data would otherwise cause.
  Scope that promise to the client it helps: the drain rescues one that
  *pauses*, and a client that blasts the whole oversized block in one write
  can still see the reset land first — a connection reset where the pausing
  client got bytes. The refusal is recorded either way, and the connection
  closes either way; what is not promised is which of the two the client
  observes. `header_too_large` rather than `bad_request` on purpose: `bad_request` says
  the proxy could not parse a request, and this says it refused to. The
  connection's own summary still reads `allowed` with `mode: terminated`, which
  is a statement about the connection — policy permitted it and the proxy
  decrypted it — and stays true of one that carried three good requests before
  the fourth was refused.

  **The body has a clock too, and it is the one the first pass at this missed.**
  Both header bounds were being cleared before the body and never re-armed, so a
  guest could send a request declaring a megabyte and then dribble — the
  finding's own words were "a byte a minute" — and hold the tunnel open,
  decrypted, holding the credential and one of the 128 slots, indefinitely. The
  body now carries a rolling ten-second bound, re-armed as bytes actually
  arrive, so a stalled transfer is closed and a real one of any size is not.

  Be exact about what that does and does not promise. A rolling stall bound
  cannot bound throughput: a guest that dribbles just fast enough to keep
  re-arming it is not stalling by this definition, and no per-read rule will
  ever say otherwise. What bounds that guest is the last of the four, a **one
  hour ceiling on the whole connection**, which does not care whether the time
  was spent silent, slow or busy. It is a ceiling, not a rule — the guest cannot
  satisfy it, only reach it. Every deadline this leg sets is clamped to it, and
  that clamp is the only thing that reaches a guest which never leaves a single
  request: the loop's own ceiling check runs *between* requests, so a body that
  never ends never returns to it, and a guest dribbling faster than the stall
  bound never stalls.

  **The write side carries a rolling bound of its own**, and an earlier version
  of this paragraph said the ceiling covered it. That was wrong, and untested:
  every deadline in the proxy was a *read* deadline, so a guest that asked a
  secret-bound origin for a large body and then simply stopped reading blocked
  the proxy inside its own response write — where neither the ceiling's
  top-of-loop check nor its clamp is ever reached, because both run between
  requests. Measured with the ceiling shrunk to twelve seconds, the proxy was
  still delivering twenty-seven seconds past it, and the cost is worse than one
  held slot: the accept loop takes its semaphore *before* accepting, so enough
  of these stop the proxy accepting at all, and teardown waits on them. The
  response copy now carries the same rolling ten-second bound the request body
  does. Ten minutes
  of *cumulative* idle across the connection is the fourth, and it now charges
  the time spent reading request headers as well as the gaps between requests:
  charging only the gaps bounded silence rather than occupancy, which let 4096
  requests each taking the full ten-second header deadline add up to eleven
  hours of held slot while the idle budget barely moved.

  **How long the proxy waits for the ORIGIN to answer is a separate bound, and
  it is ten minutes.** The bounds above are about what the guest may do to the
  proxy; this one is about what an allowlisted origin may do to it — accept the
  connection, complete TLS, and then say nothing, holding a goroutine, a socket
  and, on the terminated leg, the credential. One thing the plain path does
  that needs writing down: the Host header of a plain request is REWRITTEN to
  the target the request line names, because the proxy rebuilds the request
  rather than forwarding it — a lying Host on an absolute-URI plain request
  cannot reach the origin. It is why the plain leg's no-Host and evil-Host
  shapes answer 200 where the terminated leg would refuse (the security
  suite pins both). Both transports set
  `ResponseHeaderTimeout`, which neither Go's default nor a zero value supplies,
  and both set it to the same ten minutes the cumulative idle budget already
  enforces. It shipped at thirty seconds and was raised (**D74**): thirty is
  below the time a non-streaming completion from a model API legitimately takes
  to its first byte, which is the traffic this proxy exists to broker, and a
  connection that has waited ten minutes has spent the whole idle budget and is
  closed by the ceiling clamp regardless. It bounds only the wait for the first
  byte of the response head, never the body behind it — the body is the rolling
  stall bound's.
- **A credential can be bound to an endpoint rather than a domain.**
  `--secret NAME@host/path` binds it to that path on that host *exactly* — no
  subdomains, because naming an endpoint and then expanding to a family of hosts
  would contradict the thing the path was written to do. A request outside it
  still goes; it goes without the credential, and a `secret.withheld` event says
  which secret and why. Scope narrows *injection*, never egress: `allow` is
  where egress is decided, and putting a second egress policy inside the
  credential grammar would make one typo a hard outage.

  The path must already be in normal form — no `.` or `..` segments, no
  doubled slashes; a trailing slash names a collection. A scope written
  `/repos//` used to approve `/repos/`, which an origin that strips matrix
  parameters resolves to `/repos` — one segment wider than the bound prefix
  (P7-14). It is now refused where it is typed, with the form to write
  instead; a scope that somehow exists in another form covers nothing.

  Two things it deliberately does **not** narrow, because a reader will assume
  otherwise. It does not narrow what the proxy *decrypts*: termination is still
  decided by the host, so binding `T@api.example.com/v1` still terminates every
  request to `api.example.com`, including the ones that will never carry the
  credential — `mode: terminated` continues to mean what it always meant. And a
  path is only compared when it is literal and already in normal form: a request
  carrying an encoded slash or dot, or dot segments, is not measured against the
  scope at all, because the path this proxy would match and the path the server
  routes are then two different strings.

- **A credential that comes back is replaced before the guest sees it**, and
  what this is *not* matters more than what it is. It is **echo suppression**:
  it matches the bound values and nothing else. It is not credential detection —
  pattern-matching a byte stream the agent is about to parse would mean a false
  positive silently corrupting a tarball or a JSON document, undiagnosable from
  inside the guest, which D37 declined outright rather than deferred.

  Three limits, first rather than last, because a reader who misses them will
  assume more than this does. **The tunnelled majority is not covered and never
  can be** — the proxy relays ciphertext for every domain with no secret bound,
  so there is nothing to match. **A compressed body is not matchable**: where a
  credential is bound the proxy asks the origin not to compress —
  `Accept-Encoding: identity` on the terminated and plain-HTTP legs' requests —
  so a compliant origin's response is matchable end to end, and the guest's own
  encoding preference is overridden for exactly those requests. An origin that
  compresses anyway — every `Content-Encoding` line and coding is checked, gzip
  and br alike — gets its response **refused**, not delivered: the guest reads a
  `502` naming the encoding and the host in the body's place, and a
  `secret.unscrubbable` event records the refusal. The first fix passed the
  body through unread and only recorded it; the adversarial review of
  2026-09-01 (H4) priced that as recording the leak rather than stopping it —
  httpbin's `/gzip`, the audit's own repro, compresses whatever the request
  asked for — so the compressed response is now refused. A response with no
  body (HEAD, 204, 304) is delivered with no event. An origin serving
  pre-compressed objects — an object store with `Content-Encoding` in the
  object's own metadata — is refused on every fetch of such an object while a
  credential is bound. The proxy does not decompress to scrub and re-compress:
  that would break the byte-for-byte framing it deliberately preserves. **A
  value under eight bytes is not
  scrubbed**, because replacing a short string everywhere it appears would
  corrupt far more than it protects — and `--secret` warns about that at parse
  time now, where the user can still choose a longer credential. Trailers are
  scrubbed like headers: a chunked response's trailer values arrive after the
  body, and they used to reach the guest unexamined (the same audit, A4).

  The replacement keeps the byte length exactly. That is not cosmetic: a
  terminated connection carries many requests, and a body whose written length
  disagreed with its `Content-Length` would poison every exchange after it. A
  `secret.scrubbed` event records that bytes were altered, once per credential
  per *response*, not per connection: the de-duplication is built fresh for each
  response, so a keep-alive connection whose five responses each echo the same
  token produces five events.

- **Every tunnelled and forwarded byte is on a clock, and the tunnel's clock
  spans the whole tunnel.** The audit of 2026-09-01 (A12) found tunnels
  carrying nothing at all: 128 idle CONNECTs pinned the egress semaphore for
  the sandbox's life. A tunnel now closes after five minutes with **no bytes in
  either direction** — one clock for the whole tunnel, re-armed by a byte moving
  either way, so a keepalive or a one-way transfer of any length (a long
  download, an upload to an origin that answers only at the end) keeps it open
  while it is making progress. The first cut of this clock was per direction and
  cut exactly those one-way transfers; that is the adversarial review of
  2026-09-01's H3. No arm can outrun the one-hour connection ceiling the
  terminated leg already had, so a dribbling guest is bounded too. The
  plain-HTTP leg's request body carries the same rolling stall clock (a guest
  that declares a body and stops sending it is answered `408`) beside the
  write-side clock and the hour's ceiling. When the proxy itself ends a
  connection the `egress.attempt` records `reason` `stalled` or
  `ceiling_reached`, on an allowed attempt if the transfer had begun.

- **Certificate pinning breaks for a secret-bound domain, by construction.**
  This is the cost D6 accepted, and it belongs here as well as in the threat
  model. A terminated domain is presented a certificate minted by the run's own
  CA, so a client that pins a public key or a certificate — rather than trusting
  a root — will refuse the connection, and it is right to: there genuinely is
  something in the middle. The credential also goes only to the host the tunnel
  was opened and verified against: a request that addresses a different name in
  its `Host:` header is still sent, without the credential, and a
  `secret.withheld` event says so. Go prefers a request's own `Host` header over
  the connection's target when it writes upstream, so before v1.0 a guest could
  open a tunnel to a bound domain and have the credential presented to another
  name on the same edge.
  The pinning refusal is recorded as an `egress.attempt` with
  `reason: tls_pinning_rejected_our_ca`, so it appears as a policy event and not
  as a network fault. That reason covers any handshake failure on a terminated
  domain, not only a pinned one — pinning is the cause worth naming, and the one
  to suspect first. There is no way to have both a bound credential the guest
  cannot read and an unbroken pin; the choice is per domain and is made by
  whoever writes `--secret`.

- Inside a `[team]`, all of this is **per agent**: each agent builds its own
  TAP, its own proxy and its own nftables table from its own `allow` and
  `secrets`,
  and there is deliberately no team-wide allowlist. See
  [`docs/teams.md`](teams.md).

## 7. Privilege

Creating a TAP and loading nftables rules needs `CAP_NET_ADMIN`. The CLI runs
those two steps through `sudo -n` — **non-interactive**, so on a machine where
sudo would prompt it fails immediately rather than blocking a boot on a password
nobody is there to type:

```
egress needs CAP_NET_ADMIN via passwordless sudo (creating a TAP and loading
nftables rules)
```

It fails with that message rather than silently starting a sandbox with no
network.

The VMM runs under the jailer unless `--no-jail` is passed, and the jailer needs
passwordless sudo as well, alongside `ip` and `nft` — and so does the `rm` that
removes the jail directory afterwards, whose contents the jailer left owned by
root. The network is already up before the VMM starts: the TAP
first, then the proxy bound on it, then the nftables table that makes the proxy
the only reachable destination, and only then a machine that can send a packet.
Which posture a machine ran under is recorded as `jailed` on the session
(P5-1, [`docs/hardening.md`](hardening.md) §2).
