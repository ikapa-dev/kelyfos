package egress

import "testing"

// The audit of 2026-09-01's A13: the upstream transports were package-global,
// so their connection pools were shared by every proxy in the process. A
// connection dialled — and resolved-address-vetted — under one sandbox's
// policy could then serve another sandbox's request, skipping the per-dial
// resolved-address re-check the reuse makes unnecessary from the transport's
// point of view and mandatory from this one's. The transports are per proxy
// now, and this is the property that makes cross-proxy pool reuse impossible:
// two proxies hold two transports, and one proxy holds one.
func TestA13_EachProxyOwnsItsTransports(t *testing.T) {
	p1 := &Proxy{}
	p2 := &Proxy{}

	if p1.plainUpstream() == p2.plainUpstream() {
		t.Error("two proxies share the plain transport; their connection pools are shared too")
	}
	if p1.upstream() == p2.upstream() {
		t.Error("two proxies share the terminated transport; their connection pools are shared too")
	}
	// And the pool per proxy is still one pool: lazily built once, so
	// keep-alive works inside a sandbox the way it always did.
	if p1.plainUpstream() != p1.plainUpstream() {
		t.Error("one proxy rebuilt its plain transport between calls; its own keep-alive pool is gone")
	}
	if p1.upstream() != p1.upstream() {
		t.Error("one proxy rebuilt its terminated transport between calls; its own keep-alive pool is gone")
	}
}
