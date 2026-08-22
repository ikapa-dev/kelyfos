# KelyfOS egress

**Status:** normative for v0.x. Written at task P2-5; P2-6 adds secret injection
on top of it. The threat-model discussion lives in `docs/threat-model.md` (P3-5).

## 1. The default is no network

A sandbox with no `--allow` flag has **no network interface at all**. Not a
firewalled one, not one with an empty allowlist — no NIC. There is nothing to
misconfigure, and no rule that has to hold for the guarantee to be true.

`--allow github.com,pypi.org` is what creates a NIC, and it creates one whose
only reachable destination is a proxy on the host.

## 2. Topology

```
   guest                         host
   ┌──────────────┐              ┌───────────────────────────────────┐
   │ eth0         │              │ kelyfos<id>  (TAP)                │
   │ 10.x.y.2/30  │═════════════▶│ 10.x.y.1/30                       │
   │              │   virtio-net │    │                              │
   │ HTTPS_PROXY  │              │    ├─ nftables: only :PROXY_PORT  │
   │ = 10.x.y.1   │              │    │                              │
   └──────────────┘              │    └─▶ egress proxy ──▶ internet  │
                                 │         allowlist + audit         │
                                 └───────────────────────────────────┘
```

Point-to-point /30 per sandbox. **No NAT and no IP forwarding**, and neither is
missing by accident — nothing needs them. The proxy binds directly on the host's
TAP address, so guest traffic terminates on the host. The only process that
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

The `counter` on each drop is what makes `kelyfos log` able to say a packet was
blocked rather than merely not allowed.

## 4. No DNS in the guest (decision D16)

There is no DNS responder on the TAP address, nothing in the guest's
`/etc/resolv.conf`, and UDP/53 is dropped along with everything else.

A guest configured with `HTTPS_PROXY` never resolves anything: it sends
`CONNECT github.com:443` to the proxy, and the proxy resolves as part of
deciding whether the connection is allowed. DNS in the guest is therefore not
load-bearing for any traffic KelyfOS intends to permit.

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

## 6. What the proxy enforces

- `CONNECT host:port` and absolute-URI HTTP requests are accepted only when
  `host` matches the allowlist. A bare hostname matches itself and its
  subdomains, so `--allow github.com` also permits `api.github.com`.
- Ports are restricted to 80 and 443.
- Every attempt is written to the flight recorder as an `egress.attempt` event,
  allowed or blocked, with the reason and the byte counts
  (`docs/events.md` §4).
- Allowed connections record `mode`: `tunnelled` normally, `terminated` when a
  secret is bound to the domain and the proxy is decrypting to inject it
  (decision D6). That field is how a user can prove exactly which traffic the
  proxy was able to read.

## 7. Privilege

Creating a TAP and loading nftables rules needs `CAP_NET_ADMIN`. The CLI runs
those two steps through `sudo` and fails with an explicit message if it cannot,
rather than silently starting a sandbox with no network. Running the whole VMM
under the jailer, with the network set up before privileges are dropped, is
P4-1.
