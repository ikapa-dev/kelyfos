package dotimport

import . "github.com/ikapa-dev/kelyfos/internal/egress"

// No qualifier at all: the type is a bare identifier here.
func build() *Proxy { return &Proxy{Policy: Policy{}} }
