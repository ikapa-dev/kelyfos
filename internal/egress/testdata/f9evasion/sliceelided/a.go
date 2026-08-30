package sliceelided

import "github.com/ikapa-dev/kelyfos/internal/egress"

// The element type is elided, so the inner literal's own Type is nil.
var pool = []egress.Proxy{{Policy: egress.Policy{}}}
