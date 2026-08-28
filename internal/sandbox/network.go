package sandbox

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// Network is one sandbox's egress plumbing: a point-to-point TAP pair and the
// nftables table that makes the proxy the only reachable destination.
//
// It exists only when the sandbox was started with an allowlist. Without one
// there is no NIC at all — not a firewalled NIC, not an empty allowlist — so
// there is no rule that has to hold for "no egress" to be true
// (docs/networking.md §1).
type Network struct {
	TAP       string
	HostIP    net.IP
	GuestIP   net.IP
	Netmask   string
	ProxyPort int
	// HostMAC is pinned rather than left to the kernel's random assignment.
	// A restored guest still holds an ARP entry mapping the host's address to
	// the MAC of the TAP that no longer exists; if the replacement comes up
	// with a different one, the guest's packets go to a MAC nobody answers to
	// and every connection hangs until that entry ages out (D22).
	HostMAC string
	table   string
}

// newNetwork derives a /30 for this sandbox and brings up the TAP.
//
// The subnet is derived from the sandbox id rather than allocated from a shared
// counter, so two concurrent `kelyfos run` invocations cannot race for the same
// range without a lock file neither of them would remember to clean up. A
// collision retries with the next index.
func newNetwork(sandboxID, user string) (*Network, error) {
	seed, err := hex.DecodeString(sandboxID)
	if err != nil || len(seed) < 2 {
		return nil, fmt.Errorf("bad sandbox id %q", sandboxID)
	}
	base := binary.BigEndian.Uint16(seed[:2]) % 16384 // 169.254.0.0/16 as /30s

	tap := "kelyfos" + sandboxID
	if len(tap) > 15 { // IFNAMSIZ - 1
		tap = tap[:15]
	}

	var lastErr error
	for attempt := 0; attempt < 32; attempt++ {
		hostIP, guestIP, ok := deriveAddrs((base + uint16(attempt)) % 16384)
		if !ok {
			// A reserved range. Advancing `attempt` is the whole remedy: the
			// next index is an ordinary /30 and costs one of the 32 tries.
			continue
		}

		n := &Network{
			TAP: tap, HostIP: hostIP, GuestIP: guestIP,
			Netmask: "255.255.255.252",
			HostMAC: hostMAC(sandboxID),
			table:   "kelyfos_" + sandboxID,
		}
		if err := n.up(user); err != nil {
			lastErr = err
			n.Down()
			continue
		}
		return n, nil
	}
	return nil, fmt.Errorf("could not bring up a TAP for sandbox %s: %w", sandboxID, lastErr)
}

// metadataIP is the cloud instance metadata address — AWS, GCP, Azure and every
// hypervisor that copied them.
var metadataIP = net.IPv4(169, 254, 169, 254)

// deriveAddrs turns one attempt index into the host and guest halves of a /30,
// and reports whether that index may be handed to a sandbox at all.
//
// Exactly one of the 16,384 indices may not: idx 10879 is 169.254.169.252/30,
// which contains the cloud metadata address, and it arrives for one sandbox id
// in 16,384 rather than never. `ip addr add` installs a connected route for the
// whole /30, so the address is claimed for the life of the sandbox and nothing
// fails at setup time to say so.
//
// The damage is not usually the host's metadata, which is the intuitive
// casualty. Stock cloud images carry a /32 route for 169.254.169.254 (AWS and
// Azure via DHCP, GCP via a gateway route); a /32 beats a /30 on longest-prefix
// match, so the host keeps its IMDS and the SANDBOX is what breaks: the proxy's
// replies to guest 169.254.169.254 leave by the physical NIC instead of the TAP,
// the guest's handshake to the proxy never completes, and egress hangs with no
// error anywhere — while stray packets addressed to the metadata IP go out on
// the wire, since the nft table filters input and forward but never output. On a
// host that reaches IMDS through a broader route (169.254.0.0/16 scope link, or
// the default route) the host's metadata is what goes instead. Either way the
// symptom is a hang, which is the hardest kind of failure to attribute.
//
// docs/networking.md §2 says of the link-local range that "nothing routes and no
// site allocates" — true of the /16 as a whole and false of this one address.
func deriveAddrs(idx uint16) (hostIP, guestIP net.IP, ok bool) {
	hostIP = net.IPv4(169, 254, byte(idx>>6), byte((idx&63)*4+1))
	guestIP = net.IPv4(169, 254, byte(idx>>6), byte((idx&63)*4+2))
	if sameSlash30(hostIP, metadataIP) {
		return nil, nil, false
	}
	return hostIP, guestIP, true
}

// sameSlash30 reports whether two addresses fall in the same /30 — the first
// three octets equal, and the fourth equal once the two host bits are masked off.
func sameSlash30(a, b net.IP) bool {
	x, y := a.To4(), b.To4()
	if x == nil || y == nil {
		return false
	}
	return x[0] == y[0] && x[1] == y[1] && x[2] == y[2] && x[3]&0xfc == y[3]&0xfc
}

// newNetworkAt re-creates a TAP using addressing a snapshot recorded, instead
// of deriving fresh addresses from the sandbox id.
//
// A restored guest has the host's proxy address and port baked into its memory
// as HTTPS_PROXY, and nothing on the host can reach in to change them. So a
// restore that invented a new /30 would come up with working plumbing and a
// guest still dialling the address the proxy used to be on — which is exactly
// the failure this exists to prevent (D22). The TAP name is still new: the old
// one is gone, and Firecracker re-pairs the interface by name on load.
func newNetworkAt(sandboxID, user, hostIP, guestIP, netmask, hostMACAddr string) (*Network, error) {
	h, g := net.ParseIP(hostIP), net.ParseIP(guestIP)
	if h == nil || g == nil {
		return nil, fmt.Errorf("snapshot recorded an unusable address pair (host %q, guest %q)", hostIP, guestIP)
	}
	tap := "kelyfos" + sandboxID
	if len(tap) > 15 { // IFNAMSIZ - 1
		tap = tap[:15]
	}
	if netmask == "" {
		netmask = "255.255.255.252"
	}
	if hostMACAddr == "" {
		hostMACAddr = hostMAC(sandboxID)
	}
	n := &Network{
		TAP: tap, HostIP: h, GuestIP: g,
		Netmask: netmask,
		HostMAC: hostMACAddr,
		table:   "kelyfos_" + sandboxID,
	}
	if err := n.up(user); err != nil {
		n.Down()
		return nil, fmt.Errorf("re-create the snapshot's network on %s: %w", hostIP, err)
	}
	return n, nil
}

// GuestAddr is GuestIP in the form egress.Proxy.Peer takes: the one address the
// proxy will serve.
//
// It returns a bare Addr rather than an (Addr, bool) pair because up() refuses
// to bring a network into existence whose guest address will not convert, so
// every *Network a caller can hold has one that does. That ordering is the
// point: a conversion failure here would silently leave Peer zero, and a zero
// Peer means "serve everyone" — the F9 hole, re-opened by the plumbing meant to
// close it. Failing the sandbox at setup is the only acceptable direction for
// that error, and it is where it is checked.
func (n *Network) GuestAddr() netip.Addr {
	addr, ok := netip.AddrFromSlice(n.GuestIP)
	if !ok {
		return netip.Addr{}
	}
	// Unmapped, so a 16-byte IPv4-in-IPv6 GuestIP and the four bytes a v4
	// connection arrives as compare equal in the proxy.
	return addr.Unmap()
}

func (n *Network) up(user string) error {
	// Before the interface exists, because a half-created network is worse than
	// none: every constructor reaches here, so this is the one door through
	// which a Network whose guest address cannot arm the proxy's peer check
	// would otherwise pass.
	if !n.GuestAddr().IsValid() {
		return fmt.Errorf("guest address %v is not usable as an address, so the egress proxy's "+
			"peer check could not be armed for this sandbox", n.GuestIP)
	}
	steps := [][]string{
		{"ip", "tuntap", "add", n.TAP, "mode", "tap", "user", user},
		{"ip", "link", "set", n.TAP, "address", n.HostMAC},
		{"ip", "addr", "add", n.HostIP.String() + "/30", "dev", n.TAP},
		{"ip", "link", "set", n.TAP, "up"},
	}
	for _, s := range steps {
		if out, err := sudo(s...); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(s, " "), err, out)
		}
	}
	return nil
}

// Restrict installs the firewall once the proxy has bound and its port is known.
// Until this runs the TAP exists but nothing is listening on it, so the guest —
// which has not booted yet — has nowhere to go either way.
func (n *Network) Restrict(proxyPort int) error {
	n.ProxyPort = proxyPort
	return n.applyFirewall()
}

// ruleset is the table this sandbox installs, as docs/networking.md §3 states
// it. Built here rather than inline in applyFirewall so a test can read what
// would be loaded without needing root.
func (n *Network) ruleset() string {
	return fmt.Sprintf(`
table inet %[1]s {
	chain input {
		type filter hook input priority filter; policy accept;
		ip daddr %[3]s iifname != "%[2]s" counter drop
		iifname "%[2]s" jump kelyfos_guest_in
	}

	chain kelyfos_guest_in {
		ip daddr %[3]s tcp dport %[4]d accept
		counter drop
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "%[2]s" counter drop
		oifname "%[2]s" counter drop
	}
}
`, n.table, n.TAP, n.HostIP, n.ProxyPort)
}

// applyFirewall installs the table from docs/networking.md §3.
//
// The base chains use policy accept and drop by iifname. A base chain on the
// input hook with a drop policy would filter every packet reaching the host,
// not just this sandbox's — which on a developer's machine means locking
// yourself out of your own box the first time you run kelyfos.
//
// The first line of the input chain is what makes the host address private, and
// it is not an optimisation of the jump below it. HostIP is a local address of
// the host, so a local process's connection to it never reaches the TAP: the
// kernel routes it over `lo`, the jump's iifname match never fires, the packet
// falls through to `policy accept`, and the proxy — with the operator's
// credentials attached — answers whoever asked (F9). Matching on the
// destination and dropping everything that did not arrive on this sandbox's own
// interface closes that, and closes the physical-NIC case with it: a packet for
// HostIP that arrived because the host answered ARP for it on the LAN has
// iifname != TAP too, and is dropped by the same line. The guest's packets do
// arrive on the TAP and reach the jump exactly as before.
func (n *Network) applyFirewall() error {
	ruleset := n.ruleset()

	cmd := exec.Command("sudo", "-n", "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %w: %s", err, out)
	}
	return nil
}

// Down removes everything this sandbox added. It is best-effort and safe to
// call twice: a half-created network still has to be cleaned up.
func (n *Network) Down() {
	if n == nil {
		return
	}
	_, _ = sudo("nft", "delete", "table", "inet", n.table)
	_, _ = sudo("ip", "link", "del", n.TAP)
}

// BlockedPackets reports how many of the GUEST's packets the drop rules
// counted, which is what lets a session say traffic was blocked rather than
// merely not allowed.
//
// The input chain is excluded, and that exclusion is the whole reason this
// decodes the JSON instead of scanning it for `"packets":` the way it used to.
// Every counter in this table used to belong to the guest — the drop at the end
// of kelyfos_guest_in and the two in forward all count packets that arrived on,
// or were headed for, this sandbox's TAP. The F9 rule does not: it counts
// packets addressed to the host's TAP address that came from somewhere else
// entirely — another process on this machine, another sandbox's guest, or the
// physical segment. Summing it in would put traffic the guest never sent into
// resource.summary's blocked_packets, which docs/events.md documents beside
// figures it calls "from the guest's point of view". A receipt that attributes
// somebody else's packets to this sandbox is the record saying something
// untrue, so the number stays the guest's and the F9 counter stays readable
// where it is, in `nft list table`.
func (n *Network) BlockedPackets() int64 {
	return n.countDrops(func(chain string) bool { return chain != "input" })
}

// ForeignPacketsDropped is the F9 rule's own counter: packets addressed to this
// sandbox's host address that did not arrive on its TAP, and were dropped.
//
// Separate from BlockedPackets because it is a fact about the host rather than
// about the guest, and nothing may add the two together. It has no caller in
// the product yet; it exists so the counter the ruleset keeps is readable from
// Go at all, and so the test that proves the drop rule is what refused a
// connection can read that rule rather than the table's total.
func (n *Network) ForeignPacketsDropped() int64 {
	return n.countDrops(func(chain string) bool { return chain == "input" })
}

// countDrops sums the counters on rules in the chains want accepts.
//
// It decodes rather than scanning the JSON for `"packets":`, which is what this
// did before F9 and what made the split above impossible: with every counter in
// the table belonging to the guest, a total was the same number either way.
func (n *Network) countDrops(want func(chain string) bool) int64 {
	// sudoJSON, not sudo: sudo folds stderr into the output, and a single nft
	// warning on the way would make this JSON unparseable and the count
	// silently zero. The textual scan this replaced coped with that by
	// accident; a decoder does not.
	out, err := sudoJSON("nft", "-j", "list", "table", "inet", n.table)
	if err != nil {
		return 0
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Chain string `json:"chain"`
				Expr  []struct {
					Counter *struct {
						Packets int64 `json:"packets"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return 0
	}
	var total int64
	for _, item := range doc.Nftables {
		if item.Rule == nil || !want(item.Rule.Chain) {
			continue
		}
		for _, e := range item.Rule.Expr {
			if e.Counter != nil {
				total += e.Counter.Packets
			}
		}
	}
	return total
}

func sudo(args ...string) (string, error) {
	out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// sudoJSON is sudo for a command whose stdout is parsed rather than shown.
// CombinedOutput is right for the others — a failure's message is the whole
// value of the output — and wrong here, where one line on stderr turns a
// document into a parse error.
func sudoJSON(args ...string) (string, error) {
	out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

// CheckPrivileges reports whether the network can be set up at all, with an
// error a user can act on rather than a permission failure three steps later.
func CheckPrivileges() error {
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("`ip` is not installed — egress needs iproute2")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("`nft` is not installed — egress needs nftables")
	}
	if out, err := sudo("true"); err != nil {
		return fmt.Errorf("egress needs CAP_NET_ADMIN via passwordless sudo (creating a TAP and "+
			"loading nftables rules): %w: %s", err, out)
	}
	return nil
}

// hostMAC derives the TAP's own address from the sandbox id, the same way the
// guest's is derived, so it is stable and reproducible rather than random.
func hostMAC(sandboxID string) string {
	b, err := hex.DecodeString(sandboxID)
	if err != nil || len(b) < 4 {
		return "02:00:00:00:00:02"
	}
	return fmt.Sprintf("02:01:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3])
}
