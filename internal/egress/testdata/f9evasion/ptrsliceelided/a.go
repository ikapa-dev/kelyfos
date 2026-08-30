package ptrsliceelided

import "github.com/ikapa-dev/kelyfos/internal/egress"

// The one that matters: ordinary Go, and exactly what a refactor from one
// proxy to several would produce without anybody noticing.
var pool = []*egress.Proxy{{Policy: egress.Policy{}}}
