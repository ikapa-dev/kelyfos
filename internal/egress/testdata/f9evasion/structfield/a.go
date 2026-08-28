package structfield

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

type holder struct {
	p egress.Proxy
}

// The field's type is elided, so the inner literal's own Type is nil.
var h = holder{p: {Policy: egress.Policy{}}}
