package digest

import (
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/egress"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-17/C — a foreign-peer refusal is a fact about the host, and it was being
// counted against the guest.
//
// F9 records an egress.attempt with reason=foreign_peer when something on the
// machine that is not the guest connects to the proxy's port. It carries no
// host and no port, because no request was ever parsed. The Domains table
// excluded it for free — there is no host to key on — and the counters did not,
// so a session in which the guest made no egress attempt at all could report
// "egress 0 ok / 3 blocked" because a local process knocked three times. That
// is another party's traffic in this sandbox's receipt, and it is the same
// distinction internal/sandbox already draws for BlockedPackets: the F9 rule's
// own nftables counter is deliberately not part of the guest's figure either.

func attempt(reason string, host string, allowed bool) recorder.Event {
	return recorder.Event{
		Type: recorder.TypeEgressAttempt, Reason: reason, Host: host, Allowed: &allowed,
	}
}

func TestC_AForeignPeerRefusalIsNotTheGuestsBlockedEgress(t *testing.T) {
	events := []recorder.Event{attempt("not_in_allowlist", "example.com", false)}
	// One real refusal the guest drove, and three knocks from elsewhere on the
	// machine.
	for i := 0; i < 3; i++ {
		events = append(events, attempt(egress.ReasonForeignPeer, "", false))
	}
	d := Walk(events)

	if got := d.Session.EgressBlocked; got != 1 {
		t.Errorf("egress blocked = %d, want 1: the guest was refused once and three local "+
			"processes knocked on the proxy's port, which is not this sandbox's traffic", got)
	}
	if got := d.Session.EgressOK; got != 0 {
		t.Errorf("egress ok = %d, want 0", got)
	}
	// Counted on their own line, though. Excluding them from EgressBlocked and
	// counting them nowhere left the timeline and the summary disagreeing about
	// the same events — three rows reading BLOCKED above "egress blocked: 0",
	// which is the mirror image of the number the exclusion removed
	// (P7-17/C, review round).
	if got := d.ForeignKnocks; got != 3 {
		t.Errorf("foreign knocks = %d, want 3: the refusals render as BLOCKED rows and a "+
			"summary that counts none of them leaves a reader nothing to reconcile them with",
			got)
	}
	// And an ordinary allowed attempt still counts, so the exclusion is a
	// clause and not a switch.
	d = Walk(append(events, attempt("", "example.com", true)))
	if got := d.Session.EgressOK; got != 1 {
		t.Errorf("egress ok = %d after one allowed attempt, want 1", got)
	}
}

// The Domains table never had it, and this pins why rather than leaving it to
// the absence of a host: a foreign-peer event that somehow carried one must
// still not enter the table as a domain the guest tried to reach.
func TestC_AForeignPeerRefusalIsNotADomainTheGuestNamed(t *testing.T) {
	d := Walk([]recorder.Event{attempt(egress.ReasonForeignPeer, "", false)})
	if len(d.Domains) != 0 {
		t.Errorf("a foreign-peer refusal put %d entries in the domain table: %+v",
			len(d.Domains), d.Domains)
	}
}

// internal/digest imports internal/recorder and nothing else, so the reason
// string is spelled here rather than imported into the production file. This is
// the pin that makes the duplication safe — a test may import both packages
// where the fold may not.
func TestC_TheForeignPeerReasonMatchesTheProxy(t *testing.T) {
	if reasonForeignPeer != egress.ReasonForeignPeer {
		t.Fatalf("internal/digest spells the reason %q and internal/egress writes %q; the "+
			"exclusion above would silently stop matching", reasonForeignPeer, egress.ReasonForeignPeer)
	}
}
