package vardecl

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// The zero value, whose Peer is unset.
func build() *egress.Proxy {
	var p egress.Proxy
	p.Policy = egress.Policy{}
	return &p
}
