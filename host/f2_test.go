package main

import (
	"strings"
	"testing"
)

// P7-17/F2, the bind half. `--addr` accepts any address, so a shim bound off
// loopback with no token is reachable from the LAN — docs/e2b-shim.md says so,
// and the code let it happen silently. A bind is the one moment the process
// knows it is about to be reachable, so that is where it is refused.
func TestF2_ANonLoopbackBindNeedsAToken(t *testing.T) {
	loopback := []string{
		"127.0.0.1:3000",
		"127.0.0.1:0",
		"[::1]:3000",
		"127.0.0.53:8080",
	}
	reachable := []string{
		"0.0.0.0:3000",
		"[::]:3000",
		"192.168.1.5:3000",
		"10.0.0.7:80",
	}

	for _, addr := range loopback {
		t.Run("loopback "+addr, func(t *testing.T) {
			if err := shimBindNeedsAToken(addr, ""); err != nil {
				t.Errorf("a loopback bind was refused with no token: %v", err)
			}
			if err := shimBindNeedsAToken(addr, "a-token"); err != nil {
				t.Errorf("a loopback bind was refused with a token: %v", err)
			}
		})
	}

	for _, addr := range reachable {
		t.Run("reachable "+addr, func(t *testing.T) {
			err := shimBindNeedsAToken(addr, "")
			if err == nil {
				t.Fatalf("%s with no token was allowed; it is reachable from the network", addr)
			}
			// The refusal has to name the address and the fix, or it is a
			// wall with no door in it.
			if !strings.Contains(err.Error(), addr) {
				t.Errorf("the refusal does not name the address: %v", err)
			}
			if !strings.Contains(err.Error(), "KELYFOS_SHIM_TOKEN") {
				t.Errorf("the refusal does not name the fix: %v", err)
			}
			if err := shimBindNeedsAToken(addr, "a-token"); err != nil {
				t.Errorf("a non-loopback bind WITH a token was still refused: %v", err)
			}
		})
	}

	// An address that will not split is refused rather than assumed safe.
	if err := shimBindNeedsAToken("nonsense", ""); err == nil {
		t.Error("an unparseable bind address was allowed with no token")
	}
}
