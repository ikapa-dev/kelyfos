package embedded

import "github.com/p4r4n0rm4l/KelyfOS/internal/egress"

// The literal below names w, not Proxy, so nothing in the construction says
// whether Peer was set.
type w struct {
	egress.Proxy
	name string
}

func build() *w { return &w{name: "one"} }
