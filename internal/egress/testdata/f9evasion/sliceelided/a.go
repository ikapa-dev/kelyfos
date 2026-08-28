package sliceelided

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// The element type is elided, so the inner literal's own Type is nil.
var pool = []egress.Proxy{{Policy: egress.Policy{}}}
