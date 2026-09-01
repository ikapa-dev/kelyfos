package sandbox

import (
	"strings"
	"testing"
)

// The audit of 2026-09-01's A7: a snapshot's meta.json is a file a same-uid
// process can write, and the addressing it records used to be installed on the
// TAP with no validation at all — sandbox.json went through State's
// derivation gate, meta.json went straight to `ip link`. A poisoned meta.json
// naming host_ip 127.0.0.1 installed loopback on the interface, bound the
// credential-carrying proxy to it, and armed a host-wide drop rule for the
// sandbox's life. Both files now go through the same gate.

func TestARecordedAddressPairMustBeADerivedSlash30(t *testing.T) {
	// What a restore actually records: a derived pair, and it passes.
	ok := "169.254.0.1"
	if err := validateSnapshotAddressing(ok, "169.254.0.2", "255.255.255.252", ""); err != nil {
		t.Fatalf("the pair a real snapshot records was refused: %v", err)
	}

	for _, tc := range []struct {
		name       string
		host, gues string
		want       string
	}{
		// The audit's own scenario: loopback on the TAP.
		{"loopback host", "127.0.0.1", "127.0.0.2", "outside the link-local range"},
		// The metadata /30, which deriveAddrs refuses at derivation time.
		{"metadata /30", "169.254.169.253", "169.254.169.254", "cloud metadata address"},
		// Not a /30 this host derives.
		{"not a /30 pair", "169.254.0.1", "169.254.0.3", "two halves of a /30"},
		{"outside link-local", "192.0.2.1", "192.0.2.2", "outside the link-local range"},
		{"guest not host+1", "169.254.0.1", "169.254.0.4", "two halves of a /30"},
	} {
		err := validateSnapshotAddressing(tc.host, tc.gues, "255.255.255.252", "")
		if err == nil {
			t.Errorf("%s: the poisoned pair was accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the refusal does not say %q:\n%v", tc.name, tc.want, err)
		}
	}
}

// A netmask that is not the /30 and a MAC outside the locally administered
// unicast class are refused too — the same checks sandbox.json has always
// survived, now applied to meta.json.
func TestARecordedNetmaskAndMACGoThroughTheGate(t *testing.T) {
	if err := validateSnapshotAddressing("169.254.0.1", "169.254.0.2", "255.255.255.0", ""); err == nil {
		t.Error("a /24 netmask was accepted; every sandbox is a /30")
	}
	if err := validateSnapshotAddressing("169.254.0.1", "169.254.0.2", "255.255.255.252", "ff:ff:ff:ff:ff:ff"); err == nil {
		t.Error("a broadcast MAC was accepted")
	} else if !strings.Contains(err.Error(), "locally administered") {
		t.Errorf("the refusal does not say what class it wants:\n%v", err)
	}
}

// newNetworkAt names meta.json in its refusal, so the reader knows which file
// to distrust. It refuses before any privileged work: no TAP exists to clean
// up on the refusal path, which is why the genuine-pair cases above are tested
// through the gate itself and not through newNetworkAt — that one would start
// creating interfaces.
func TestNewNetworkAtRefusesPoisonedMeta(t *testing.T) {
	_, err := newNetworkAt("0123abcd", "tester", "127.0.0.1", "127.0.0.2", "", "")
	if err == nil {
		t.Fatal("a poisoned meta.json was installed")
	}
	if !strings.Contains(err.Error(), "meta.json") {
		t.Errorf("the refusal does not name the file it refuses:\n%v", err)
	}
}
