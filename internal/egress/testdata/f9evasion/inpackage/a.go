package egress

// A factory inside the package itself: the type is an identifier, not a
// selector, so a selector-only match never saw it.
func newProxy() *Proxy { return &Proxy{Policy: Policy{}} }
