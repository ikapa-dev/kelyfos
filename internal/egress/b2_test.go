package egress

import (
	"net/http"
	"testing"
	"time"
)

// P7-17/B2 (D74) — the 30-second ResponseHeaderTimeout F15 added, raised to the
// bound that was already in force.
//
// F15 was right that the field was missing: neither DefaultTransport nor a zero
// value supplies one, so an origin that accepts, completes TLS and then says
// nothing held a goroutine, a socket and — on the terminated leg — the
// credential. The VALUE was never argued and never written down, and thirty
// seconds is below the time a non-streaming completion from a model API
// legitimately takes to its first byte. That leg is the credentialed model-API
// path: the failure it produced was `timeout awaiting response headers` on a
// request that was going to succeed.
//
// Both transports now carry maxTerminatedIdleTotal — the ten-minute cumulative
// idle budget F16 already enforces on the terminated leg. A connection that has
// waited that long for a first byte has spent the whole budget and notAfter
// closes it regardless, so the transport now agrees with the leg it runs on
// instead of failing earlier for a different reason.
//
// Removal was the other option and is rejected in D74 with its reason: on the
// terminated leg it would be defensible, and on the forward transport it would
// not — forwardHTTP re-issues with context.Background, so no context covers it
// and F16's machinery does not reach it.

func TestB2_TheResponseHeaderBoundIsTheIdleBudgetOnBothTransports(t *testing.T) {
	// Stated here independently rather than read off the constant, for the
	// reason TestF14_TheTableIsExactlyThis exists: a test that asserts a field
	// equals the constant it was set from cannot notice the constant moving,
	// and this is a number a person has to be able to look up.
	const want = 10 * time.Minute

	if maxTerminatedIdleTotal != want {
		t.Fatalf("maxTerminatedIdleTotal is %v, want %v — docs/networking.md and D74 both "+
			"state ten minutes, and this bound is quoted to operators", maxTerminatedIdleTotal, want)
	}

	for _, c := range []struct {
		name string
		tr   *http.Transport
	}{
		{"forward", newForwardTransport()},
		{"terminated", newTerminatedTransport()},
	} {
		got := c.tr.ResponseHeaderTimeout
		if got != want {
			t.Errorf("%s: ResponseHeaderTimeout is %v, want %v (D74).\n"+
				"  Thirty seconds — the value F15 shipped — refuses a non-streaming completion\n"+
				"  that takes longer than that to its first byte, which is ordinary traffic on\n"+
				"  the one leg that carries a credential.", c.name, got, want)
		}
		// And the specific regression, named, because "not 30s" is the half a
		// reader of this test needs to see.
		if got <= 30*time.Second {
			t.Errorf("%s: ResponseHeaderTimeout is %v, which is at or below the 30s that made a "+
				"legitimate slow completion fail with \"timeout awaiting response headers\"",
				c.name, got)
		}
	}
}

// The two legs agree. A third bound nobody can hold in their head is the shape
// this project has refused since the `jailed` bug, and D74 says the two are
// kept the same deliberately.
func TestB2_TheTwoTransportsAgreeOnIt(t *testing.T) {
	fwd := newForwardTransport().ResponseHeaderTimeout
	term := newTerminatedTransport().ResponseHeaderTimeout
	if fwd != term {
		t.Errorf("the forward leg waits %v for a response head and the terminated leg waits "+
			"%v.\n  D74 keeps them equal: whichever value is chosen, one number is the point.",
			fwd, term)
	}
}
