package prearmed

import (
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// The live one. recorder.Event has a Peer field, so a per-file audit saw
// "X.Peer" in this file and excused the unarmed proxy below it — which is how
// an unarmed &egress.Proxy{} added to host/log.go passed.
func record(e recorder.Event) string { return e.Peer }

func build() *egress.Proxy { return &egress.Proxy{Policy: egress.Policy{}} }
