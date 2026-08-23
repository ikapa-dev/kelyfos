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

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
)

// blockedOnce prints a policy refusal the first time each one happens.
type blockedOnce struct {
	mu   sync.Mutex
	seen map[string]bool
	w    io.Writer
}

func newBlockedOnce(w io.Writer) *blockedOnce {
	return &blockedOnce{seen: map[string]bool{}, w: w}
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
	key := text
	b.mu.Lock()
	if b.seen[key] {
		b.mu.Unlock()
		return
	}
	b.seen[key] = true
	b.mu.Unlock()
	fmt.Fprintf(b.w, "kelyfos: %s\n", text)
}

// sayText prints an already-rendered refusal, once. It is the same rule for the
// same reason: the advice is the key, so a forward refused on every connection
// is one thing to fix rather than one line per attempt.
func (b *blockedOnce) sayText(text string) {
	b.mu.Lock()
	if b.seen[text] {
		b.mu.Unlock()
		return
	}
	b.seen[text] = true
	b.mu.Unlock()
	fmt.Fprintf(b.w, "kelyfos: %s\n", text)
}
