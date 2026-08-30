package aliasimport

import eg "github.com/ikapa-dev/kelyfos/internal/egress"

// The audit used to match the literal identifier "egress".
func build() *eg.Proxy { return &eg.Proxy{Policy: eg.Policy{}} }
