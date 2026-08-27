// Telling a person about a refusal that happened inside the guest (E5-4).
//
// A refusal reaches whoever was refused, which for egress is a program inside
// the sandbox — and for CONNECT that program is usually told a great deal less
// than the proxy said. curl reports "Received HTTP code 403 from proxy after
// CONNECT" and discards the body: the fix line is written, sent, and thrown
// away by the client before anybody reads it. Plain HTTP and a
// secret-terminated connection both carry it through, because there the
// refusal is the response.
//
// The person watching the run is the other reader, and the one who can act:
// they are the one with the policy file open. So the first time a domain is
// refused, the refusal is printed on the host with its fix line — once per host
// and reason, because a retry loop refused forty times is one thing to fix, not
// forty.
package main

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/notify"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// maxBlockedEntries bounds how many distinct denial lines blockedOnce will
// ever remember. seen is keyed on rendered denial text that embeds the
// guest-chosen host, so a guest that tries thousands of distinct disallowed
// hostnames would otherwise grow this map, and the lines printed for it,
// without limit. An ordinary run refusing a handful of hosts never comes
// close; past the cap a genuinely new denial is neither recorded nor printed,
// which is the right failure mode — "no more new denial lines," not unbounded
// host memory (S5a).
const maxBlockedEntries = 4096

// blockedOnce prints a policy refusal the first time each one happens.
type blockedOnce struct {
	mu   sync.Mutex
	seen map[string]bool
	w    io.Writer
	// notify, when set, sends the same refusal to the desktop (E5-7). It shares
	// this type's deduplication rather than having its own: a run that printed
	// one line and raised forty notifications would be worse than either.
	notify *notify.Notifier
}

func newBlockedOnce(w io.Writer) *blockedOnce {
	return &blockedOnce{seen: map[string]bool{}, w: w}
}

// markSeen reports whether text has not been printed yet and should be now,
// recording it as seen when the answer is yes. Bounded by maxBlockedEntries:
// past the cap, an unseen text is reported as already-seen so it is silently
// dropped rather than remembered forever.
func (b *blockedOnce) markSeen(text string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen[text] {
		return false
	}
	if len(b.seen) >= maxBlockedEntries {
		return false
	}
	b.seen[text] = true
	return true
}

// say prints the refusal behind a blocked attempt, or nothing at all when the
// attempt was allowed, when it failed rather than being refused, or when this
// host and reason have already been reported.
//
// A dial that did not connect is not in the catalog and gets nothing: it has no
// fix, and a line here would train the reader to skim past the ones that do.
func (b *blockedOnce) say(a egress.Attempt) {
	if a.Allowed {
		return
	}
	var text string
	switch a.Reason {
	case egress.ReasonNotAllowed:
		text = denial.EgressHost.Render(denial.V{"host": a.Host})
	case egress.ReasonBadPort:
		text = denial.EgressPort.Render(denial.V{
			"host": a.Host, "port": strconv.Itoa(a.Port)})
	default:
		return
	}
	// Deduplicated on the advice, not on the attempt. Two refusals that would
	// print the same two lines are one thing to fix: a host refused on 80 and
	// again on 443 needs the same entry added once, and saying so twice is
	// noise dressed as detail.
	if !b.markSeen(text) {
		return
	}
	fmt.Fprintf(b.w, "kelyfos: %s\n", text)
	b.notify.Send("kelyfos: blocked", firstLine(text))
}

// sayText prints an already-rendered refusal, once. It is the same rule for the
// same reason: the advice is the key, so a forward refused on every connection
// is one thing to fix rather than one line per attempt.
func (b *blockedOnce) sayText(text string) {
	if !b.markSeen(text) {
		return
	}
	fmt.Fprintf(b.w, "kelyfos: %s\n", text)
	b.notify.Send("kelyfos: blocked", firstLine(text))
}

// finishedBody is what a "run finished" notification says (E5-7).
//
// The two facts somebody who walked away wants are the same two the shell would
// have given them: whether it worked, and how long it took. The reason is only
// worth saying when it is not the ordinary one — "stopped after 4m" reads
// better than "shutdown after 4m", and "timed out after 30m" has to be said.
func finishedBody(reason string, code *int, took time.Duration) string {
	d := took.Round(time.Second)
	if took < time.Second {
		d = took.Round(time.Millisecond)
	}
	switch {
	case code != nil && *code == 0:
		return fmt.Sprintf("finished cleanly after %s", d)
	case code != nil:
		return fmt.Sprintf("exited %d after %s", *code, d)
	case reason == "timeout":
		return fmt.Sprintf("timed out after %s", d)
	case reason == "vm_exited":
		return fmt.Sprintf("the sandbox died unexpectedly after %s", d)
	case reason == "interrupted":
		return fmt.Sprintf("stopped after %s", d)
	default:
		return fmt.Sprintf("%s after %s", reason, d)
	}
}

// wireProxyAudit connects a proxy to a session's recorder: every attempt to
// leave, allowed or blocked, and every credential attached — by name and
// destination, never by value (docs/events.md §4).
//
// One function because there are five proxies in this product and this wiring
// was written out at four of them. The fifth, `kelyfos snapshot restore`, was
// simply missed: it opens a recorder, writes session.start, session.ready and
// session.end, and wired neither hook — so a restored machine produced a chain
// that looked complete and said nothing whatsoever about egress. A blocked
// attempt left no trace; a credential spent left no trace. Meanwhile the README
// says "every attempt to leave the sandbox is recorded, allowed or not", and
// the threat model lists guest→network as active.
//
// That is the P5-1 `jailed` shape exactly — a record field set at some of the
// places that open a chain and not the others — and it was found by doing P6-4's
// enumeration before writing any of P6-4's feature code, which is the argument
// for the enumeration.
//
// blocked may be nil, for a door with no terminal of the user's to print to.
func wireProxyAudit(proxy *egress.Proxy, rec *recorder.Recorder, agent string, blocked *blockedOnce) {
	if proxy == nil || rec == nil {
		return
	}
	proxy.OnSecret = func(name, host string) {
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSecretUse, Agent: agent, Name: name, Host: host,
		})
	}
	proxy.OnWithheld = func(name, host, reason string) {
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSecretWithheld, Agent: agent,
			Name: name, Host: host, Reason: reason,
		})
	}
	proxy.OnScrubbed = func(name, host string) {
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeSecretScrubbed, Agent: agent, Name: name, Host: host,
		})
	}
	proxy.OnEvent = func(a egress.Attempt) {
		if blocked != nil {
			// The person watching the run is the one with the policy file open,
			// and for a refused CONNECT they are often the only reader who gets
			// the fix line at all (E5-4).
			blocked.say(a)
		}
		allowed := a.Allowed
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeEgressAttempt, Agent: agent,
			Host: a.Host, Port: a.Port, Allowed: &allowed,
			Reason: a.Reason, Mode: a.Mode,
			BytesIn: a.BytesIn, BytesOut: a.BytesOut,
		})
	}
}
