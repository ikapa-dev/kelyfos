package egress

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/hostile"
)

// The hostile corpus for the egress proxy's CONNECT parsing (S1, door A).
//
// splitTarget and plausibleHost validated a CONNECT target's characters but
// never its length. A guest able to reach the proxy at all — which is every
// sandbox with any --allow rule, since the proxy is the only route out
// (docs/networking.md) — could send `CONNECT <9 MiB of 'a'>:443 HTTP/1.1`.
// http.ReadRequest does not bound the request line's length, the oversized
// string became `host`, was refused for not being on the allowlist, and
// host/denials.go's wireProxyAudit appended it whole into an egress.attempt
// event with no size check of its own — a line past every reader's
// recorder.MaxLine, which is durable, guest-triggered destruction of the
// flight recorder from that line on.
func TestHostileOversizedConnectHostIsRejected(t *testing.T) {
	huge := strings.Repeat("a", 9<<20)
	raw := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\n\r\n", huge)

	// Built over a plain strings.Reader rather than through handle()'s own
	// headerLimitReader (S5a added that afterward, bounding the whole request
	// at maxRequestHeaderBytes before it ever reaches here) — this isolates
	// splitTarget's own 253-byte host bound, the fix this fixture exists to
	// hold, from handle()'s separate, broader header-size defense in depth.
	// A live 9 MiB CONNECT host is refused by handle() before it ever gets
	// this far today; this fixture pins the deeper check that still has to
	// hold if it didn't.
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("building the fixture request: %v", err)
	}

	problem := ""
	host, _, splitErr := splitTarget(req)
	if splitErr == nil {
		shown := host
		if len(shown) > 64 {
			shown = shown[:64] + "…"
		}
		problem = fmt.Sprintf("splitTarget accepted a %d-byte host instead of refusing it: %q", len(host), shown)
	}
	hostile.Holds(t, "egress/oversized-connect-host", problem)
}
