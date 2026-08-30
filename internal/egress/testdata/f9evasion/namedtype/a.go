package namedtype

import "github.com/ikapa-dev/kelyfos/internal/egress"

// A local name for the same type, constructed under that name.
type P = egress.Proxy

func build() *P { return &P{Policy: egress.Policy{}} }
