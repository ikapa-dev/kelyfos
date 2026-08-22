package sandbox

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
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
		idx := (base + uint16(attempt)) % 16384
		hostIP := net.IPv4(169, 254, byte(idx>>6), byte((idx&63)*4+1))
		guestIP := net.IPv4(169, 254, byte(idx>>6), byte((idx&63)*4+2))

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

func (n *Network) up(user string) error {
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

// applyFirewall installs the table from docs/networking.md §3.
//
// The base chains use policy accept and drop by iifname. A base chain on the
// input hook with a drop policy would filter every packet reaching the host,
// not just this sandbox's — which on a developer's machine means locking
// yourself out of your own box the first time you run kelyfos.
func (n *Network) applyFirewall() error {
	ruleset := fmt.Sprintf(`
table inet %[1]s {
	chain input {
		type filter hook input priority filter; policy accept;
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

// BlockedPackets reports how many packets the drop rule counted, which is what
// lets a session say traffic was blocked rather than merely not allowed.
func (n *Network) BlockedPackets() int64 {
	out, err := sudo("nft", "-j", "list", "table", "inet", n.table)
	if err != nil {
		return 0
	}
	// Cheap enough to scan rather than decode: the JSON has one counter object
	// per drop rule and we only want the total.
	var total int64
	for _, part := range strings.Split(out, `"packets":`)[1:] {
		var v int64
		if _, err := fmt.Sscanf(part, "%d", &v); err == nil {
			total += v
		}
	}
	return total
}

func sudo(args ...string) (string, error) {
	out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
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
