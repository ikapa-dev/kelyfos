package namedtype

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// A local name for the same type, constructed under that name.
type P = egress.Proxy

func build() *P { return &P{Policy: egress.Policy{}} }
