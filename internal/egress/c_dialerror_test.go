package egress

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// P7-17/C — the 502 handed the guest the address an allowlisted name resolved
// to.
//
// F14 closed exactly this on the 403: "a guest that is told which address an
// allowlisted name resolves to has been handed the result of a DNS lookup it
// has no resolver of its own to perform — one name at a time, that is a map of
// the host's network." The 403 was fixed and the 502 two lines below it was
// not, and it is the easier one to reach: the guest does not need the name to
// resolve anywhere unusual, only somewhere that does not answer.
//
// Go's dial errors carry the address by construction —
// `dial tcp 93.184.216.34:443: connect: connection refused` — so writing
// err.Error() into the body was the whole of it.

// A stand-in for what dialContextSafe returns on an ordinary failed dial:
// net.OpError with the resolved address in a structured field, which is what
// the standard library actually produces.
func dialErr(addr string) error {
	ip, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		panic(err)
	}
	return &net.OpError{Op: "dial", Net: "tcp", Addr: ip,
		Err: errors.New("connect: connection refused")}
}

func TestC_TheDialFailureBodyNamesNoAddress(t *testing.T) {
	const resolved = "93.184.216.34:443"
	var got []Attempt
	p := &Proxy{OnEvent: func(a Attempt) { got = append(got, a) }}

	var w strings.Builder
	p.reportDialFailure(&w, "example.com", 443, dialErr(resolved))

	body := w.String()
	if strings.Contains(body, "93.184.216.34") {
		t.Errorf("the 502 handed the guest the address the name resolved to:\n%s", body)
	}
	// It has to still say what happened, or the guest is left guessing at a
	// blank wall — the same balance the 403 strikes.
	if !strings.Contains(body, "example.com") {
		t.Errorf("the 502 does not name the host the guest asked for:\n%s", body)
	}
	if !strings.Contains(body, "502") {
		t.Errorf("the answer is not a 502:\n%s", body)
	}

	// And the operator keeps it. The address goes to the recorder, in the field
	// F14 added for exactly this, not into the answer.
	if len(got) != 1 {
		t.Fatalf("the failure produced %d recorder events, want 1", len(got))
	}
	if got[0].ResolvedAddr != resolved {
		t.Errorf("the chain lost the address: ResolvedAddr = %q, want %q",
			got[0].ResolvedAddr, resolved)
	}
	if got[0].Reason != ReasonDialFailed {
		t.Errorf("reason = %q, want %q", got[0].Reason, ReasonDialFailed)
	}
}

// The resolved-address refusal above it is untouched: it already withheld the
// address and it still does, and its reason is its own.
func TestC_TheResolvedAddressRefusalIsUnchanged(t *testing.T) {
	var got []Attempt
	p := &Proxy{OnEvent: func(a Attempt) { got = append(got, a) }}

	var w strings.Builder
	p.reportDialFailure(&w, "example.com", 443,
		&errUnsafeResolvedAddr{host: "example.com", addr: "169.254.169.254"})

	if strings.Contains(w.String(), "169.254.169.254") {
		t.Errorf("the 403 named the address:\n%s", w.String())
	}
	if len(got) != 1 || got[0].ResolvedAddr != "169.254.169.254" {
		t.Errorf("the chain did not keep the address: %+v", got)
	}
	if len(got) == 1 && got[0].Reason != ReasonUnsafeResolvedAddr {
		t.Errorf("reason = %q, want %q", got[0].Reason, ReasonUnsafeResolvedAddr)
	}
}

// An error that is not a dial against an address leaves the field empty rather
// than inventing one, and still says nothing to the guest.
func TestC_ADialFailureWithNoAddressRecordsNone(t *testing.T) {
	var got []Attempt
	p := &Proxy{OnEvent: func(a Attempt) { got = append(got, a) }}

	var w strings.Builder
	p.reportDialFailure(&w, "example.com", 443, errors.New("no such host"))

	if len(got) != 1 {
		t.Fatalf("the failure produced %d recorder events, want 1", len(got))
	}
	if got[0].ResolvedAddr != "" {
		t.Errorf("ResolvedAddr = %q for an error carrying no address", got[0].ResolvedAddr)
	}
	if strings.Contains(w.String(), "no such host") {
		t.Errorf("the error string reached the guest:\n%s", w.String())
	}
}
