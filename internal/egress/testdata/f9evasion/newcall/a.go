package newcall

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// new() has no composite literal for the field to live in.
func build() *egress.Proxy { return new(egress.Proxy) }
