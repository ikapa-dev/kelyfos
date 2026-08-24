# KelyfOS egress

**Status:** normative for v0.x. Written at P2-5, with secret injection added by
P2-6 and the restore path by D22. The threat-model discussion lives in
[`docs/threat-model.md`](threat-model.md).

## 1. The default is no network

A sandbox with no `--allow` flag has **no network interface at all**. Not a
firewalled one, not one with an empty allowlist — no NIC. There is nothing to
misconfigure, and no rule that has to hold for the guarantee to be true.

`--allow github.com,pypi.org` is what creates a NIC, and it creates one whose
only reachable destination is a proxy on the host.

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
cannot collide with the host's real networks. The /30 index is derived from the
sandbox id rather than handed out by a counter, so two `kelyfos run` invocations
cannot race for a range; a collision retries with the next index. The host takes
the first usable address and the guest the second, and the proxy's port is
kernel-assigned rather than fixed, which is why every example here writes it as
a placeholder.

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

Two details are deliberate and easy to get wrong:

- **The base chains have `policy accept`, not `policy drop`.** A base chain on
  the `input` hook with a drop policy filters *all* traffic to the host, not
  only the sandbox's — on a developer's machine that means locking yourself out
  of your own box the first time you run `kelyfos`. Isolation comes from
  matching `iifname` and dropping explicitly, which affects nothing else.
- **`forward` drops in both directions.** IP forwarding is off and nothing turns
  it on, but a rule that states the intent survives someone else's sysctl.

Each drop carries a `counter`, which `nft list table` will show you. Nothing
reads it yet: `kelyfos log` reports what the **proxy** saw, so a packet the
firewall dropped before it reached the proxy is counted here and appears in no
event. Carrying that count into the session receipt is open work.

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

## 6. What the proxy enforces

- `CONNECT host:port` and absolute-URI HTTP requests are accepted only when
  `host` matches the allowlist. A bare hostname matches itself and its
  subdomains, so `--allow github.com` also permits `api.github.com`.
- Ports are restricted to 80 and 443. No policy key widens that.
- A refusal is answered with `403` and a body naming the domain and the edit
  that would allow it (`[egress.host]` in [`denials.md`](denials.md)). For plain
  HTTP the guest reads it; for a refused `CONNECT` most clients discard the
  body, so the host prints the same refusal once, on its own stderr — `kelyfos
  run` and `team up` do; `serve-mcp` and the shim record it without printing,
  because there is no terminal of yours to print to.
- Every attempt is written to the flight recorder as an `egress.attempt` event,
  allowed or blocked, with the reason and the byte counts
  (`docs/events.md` §4).
- Allowed connections record `mode`, which says **how much of the connection the
  proxy could read**. Three values, and the distinction is the whole point of
  the field (decision D6):

  | `mode` | What the proxy saw |
  | --- | --- |
  | `tunnelled` | Nothing. A `CONNECT` relayed without being opened. |
  | `terminated` | Everything. A secret is bound to this domain, so the session was decrypted to attach the credential. |
  | `plain` | Everything. An ordinary HTTP request, which any proxy that forwards it necessarily parses, rewrites and re-issues. Nothing was decrypted because nothing was encrypted. |

  `plain` exists because the alternative was recording it as `tunnelled`, and
  that is the one thing this field must never do: **understate what the host
  could see.** Anyone grepping for `terminated` to find the traffic the proxy
  read would have missed every plaintext request on port 80 (F-D33).

- **A credential can be bound to an endpoint rather than a domain.**
  `--secret NAME@host/path` binds it to that path on that host *exactly* — no
  subdomains, because naming an endpoint and then expanding to a family of hosts
  would contradict the thing the path was written to do. A request outside it
  still goes; it goes without the credential, and a `secret.withheld` event says
  which secret and why. Scope narrows *injection*, never egress: `allow` is
  where egress is decided, and putting a second egress policy inside the
  credential grammar would make one typo a hard outage.

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
  so there is nothing to match. **A compressed body is not covered**: the
  terminated transport deliberately does not decompress, so a client that asked
  for gzip gets gzip, and gzip of a credential does not contain the credential.
  **A value under eight bytes is not scrubbed**, because replacing a short
  string everywhere it appears would corrupt far more than it protects.

  The replacement keeps the byte length exactly. That is not cosmetic: a
  terminated connection carries many requests, and a body whose written length
  disagreed with its `Content-Length` would poison every exchange after it. A
  `secret.scrubbed` event records that bytes were altered, once per credential
  per connection.

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
network. Running the whole VMM under the jailer, with the network set up before
privileges are dropped, is P4-1.
