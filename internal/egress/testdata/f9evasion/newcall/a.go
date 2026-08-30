package newcall

import "github.com/ikapa-dev/kelyfos/internal/egress"

// new() has no composite literal for the field to live in.
func build() *egress.Proxy { return new(egress.Proxy) }
