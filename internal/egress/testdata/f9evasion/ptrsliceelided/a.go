package ptrsliceelided

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// The one that matters: ordinary Go, and exactly what a refactor from one
// proxy to several would produce without anybody noticing.
var pool = []*egress.Proxy{{Policy: egress.Policy{}}}
