package dotimport

import . "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// No qualifier at all: the type is a bare identifier here.
func build() *Proxy { return &Proxy{Policy: Policy{}} }
