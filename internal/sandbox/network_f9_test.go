package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The same thing executed, which is what the finding was never given: bring up
// a real TAP, load the real ruleset, put a listener on HostIP, and dial it from
// the host the way any local process would.
//
// This is the test the review asked for by name. It needs CAP_NET_ADMIN through
// passwordless sudo — the same privilege `kelyfos run` needs — and skips
// without it rather than failing, because a developer's laptop is not the
// machine this can run on.
func TestF9_HostIPIsUnreachableFromAHostProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nftables and TAP interfaces are Linux")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	if out, err := sudo("true"); err != nil {
		t.Skipf("no passwordless sudo, which this needs for `ip` and `nft`: %v: %s", err, out)
	}

	// Named and addressed off this process so two of these running at once —
	// or one running beside a real sandbox — cannot collide. The /30 index is
	// the same space newNetwork draws from, so it is derived the same way and
	// skips the same reserved block.
	idx := uint16(os.Getpid()*4+1) % 16384
	hostIP, guestIP, ok := deriveAddrs(idx)
	if !ok {
		idx = (idx + 1) % 16384
		hostIP, guestIP, ok = deriveAddrs(idx)
		if !ok {
			t.Fatalf("two consecutive indices reserved, which cannot happen: %d", idx)
		}
	}
	n := &Network{
		// IFNAMSIZ - 1 is 15; "kelyfosf9" plus five digits is 14.
		TAP:     fmt.Sprintf("kelyfosf9%05d", os.Getpid()%100000),
		HostIP:  hostIP,
		GuestIP: guestIP,
		Netmask: "255.255.255.252",
		HostMAC: "02:01:f9:f9:f9:f9",
		table:   fmt.Sprintf("kelyfos_f9%d", os.Getpid()),
	}
	t.Cleanup(n.Down)
	if err := n.up(currentUser(t)); err != nil {
		t.Skipf("could not bring up a TAP here: %v", err)
	}

	// A stand-in for the proxy, bound exactly where the proxy binds.
	ln, err := net.Listen("tcp", n.HostIP.String()+":0")
	if err != nil {
		t.Fatalf("bind on the TAP address: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "served %s\n", c.RemoteAddr())
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	if err := n.Restrict(port); err != nil {
		t.Fatalf("load the ruleset: %v", err)
	}

	// The dial the finding is about: this process is not the guest, and it is
	// asking for the address the guest's proxy is on.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", n.HostIP, port), 3*time.Second)
	if err == nil {
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		read, _ := conn.Read(buf)
		conn.Close()
		t.Fatalf("a host process reached the proxy's port at %s:%d and was answered %q — "+
			"this is F9, and the input chain's drop line is what closes it",
			n.HostIP, port, strings.TrimSpace(string(buf[:read])))
	}
	t.Logf("refused, as it must be: %v", err)

	// A refusal is only evidence if the firewall is what produced it, and it
	// has to be *this* rule. ForeignPacketsDropped reads the input chain's
	// counter alone.
	if got := n.ForeignPacketsDropped(); got == 0 {
		t.Errorf("nothing was counted as dropped, so the refusal came from somewhere "+
			"other than the ruleset: %s", rulesetDump(t, n))
	}
	// And it must not be counted as the guest's. blocked_packets on the session
	// receipt is documented beside figures "from the guest's point of view";
	// these packets came from this test process, not from any guest.
	if got := n.BlockedPackets(); got != 0 {
		t.Errorf("the host's own dropped packets were counted as the guest's: "+
			"BlockedPackets = %d, want 0\n%s", got, rulesetDump(t, n))
	}
}

func currentUser(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Skipf("cannot read the current user: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func rulesetDump(t *testing.T, n *Network) string {
	t.Helper()
	out, _ := sudo("nft", "list", "table", "inet", n.table)
	return out
}

// GuestAddr must produce a usable address for every sandbox this product can
// derive, because egress.Proxy.Peer is armed from it and a zero Addr there
// means "serve everyone" — F9, re-opened by the plumbing meant to close it.
//
// The whole index space is enumerated for the same reason
// TestNoDerivedSandboxRangeCoversTheCloudMetadataAddress enumerates it: a
// sampled test finds a one-in-16,384 defect about as often as production does.
func TestF9_EveryDerivedGuestAddressCanArmThePeerCheck(t *testing.T) {
	for idx := 0; idx < 16384; idx++ {
		hostIP, guestIP, ok := deriveAddrs(uint16(idx))
		if !ok {
			continue
		}
		n := &Network{HostIP: hostIP, GuestIP: guestIP}
		addr := n.GuestAddr()
		if !addr.IsValid() {
			t.Fatalf("index %d derives guest %s, which GuestAddr cannot convert — the proxy's "+
				"peer check would be left unarmed for that sandbox", idx, guestIP)
		}
		if addr.String() != guestIP.String() {
			t.Fatalf("index %d: GuestAddr says %s, GuestIP says %s", idx, addr, guestIP)
		}
		if addr.Is4In6() {
			t.Fatalf("index %d: GuestAddr returned a 4-in-6 address (%s); it must be unmapped, "+
				"or it will not compare equal to the four bytes a v4 connection arrives as", idx, addr)
		}
	}
}

// The snapshot-restore path takes its addressing from recorded metadata rather
// than from deriveAddrs, so it gets its own pass — and up() is the door that
// must refuse a pair it cannot arm the check from.
func TestF9_UpRefusesANetworkWhoseGuestAddressCannotArmTheCheck(t *testing.T) {
	n := &Network{
		TAP:     "kelyfosbadaddr0",
		HostIP:  net.IPv4(169, 254, 8, 1),
		GuestIP: net.IP{1, 2, 3}, // three bytes: not an address
		table:   "kelyfos_badaddr",
	}
	err := n.up("nobody")
	if err == nil {
		t.Fatal("up() accepted a network whose guest address cannot arm the peer check; " +
			"the sandbox must refuse to come up rather than serve every local process")
	}
	if !strings.Contains(err.Error(), "peer check") {
		t.Errorf("up() refused for some other reason, so this test proves nothing: %v", err)
	}
}
