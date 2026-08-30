package structfield

import "github.com/ikapa-dev/kelyfos/internal/egress"

type holder struct {
	p egress.Proxy
}

// The field's type is elided, so the inner literal's own Type is nil.
var h = holder{p: {Policy: egress.Policy{}}}
