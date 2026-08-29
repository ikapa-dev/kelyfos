package egress

import (
	"errors"
	"net"
	"strings"
	"testing"
	"unicode/utf8"
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
	// And it must not promise the guest a diagnostic that is not there. The
	// first version said "the reason is in the flight recorder" when the
	// recorder held one reason code — upstream_unreachable — for a refused
	// connection, a timeout, a name that resolved to nothing, a TLS failure and
	// a response-header timeout alike (P7-17/C, review round).
	if strings.Contains(body, "The reason is in the flight recorder") {
		t.Error("the 502 promises a diagnostic; check the record actually carries one")
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
	// The reason the message points at. ReasonDialFailed is a category, and
	// without this the operator has the category and nobody has the reason —
	// which is what withholding err.Error() from the guest cost until the
	// review found it (P7-17/C, review round).
	if !strings.Contains(got[0].Detail, "connection refused") {
		t.Errorf("the chain carries no detail for a refused dial: Detail = %q", got[0].Detail)
	}
}

// Detail is bounded, because it reaches the flight recorder, which pays for
// every byte forever — and it is cut on a rune boundary, so a record never
// carries half of one.
func TestC_TheDialFailureDetailIsBounded(t *testing.T) {
	long := errors.New(strings.Repeat("é", 400))
	got := detailOf(long)
	if len(got) > maxAttemptDetail+4 {
		t.Errorf("detail is %d bytes, over the %d-byte bound", len(got), maxAttemptDetail)
	}
	if !utf8.ValidString(got) {
		t.Errorf("detail was cut mid-rune: %q", got)
	}
	if detailOf(nil) != "" {
		t.Errorf("a nil error produced a detail: %q", detailOf(nil))
	}
	// A short one is untouched.
	if got := detailOf(errors.New("connection refused")); got != "connection refused" {
		t.Errorf("an ordinary error was altered: %q", got)
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
