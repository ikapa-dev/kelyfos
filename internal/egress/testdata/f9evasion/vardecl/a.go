package vardecl

import "github.com/ikapa-dev/kelyfos/internal/egress"

// The zero value, whose Peer is unset.
func build() *egress.Proxy {
	var p egress.Proxy
	p.Policy = egress.Policy{}
	return &p
}
