package main

import (
	"os"
	"strings"
)

// applyEgressEnv reads the proxy address the host put on the kernel command line
// and makes it the environment every command in this sandbox inherits.
//
// The address arrives via /proc/cmdline rather than a vsock RPC because the
// kernel has already used the same command line to configure eth0
// (CONFIG_IP_PNP), so the network and the proxy that fronts it are described in
// exactly one place, by the side that decided both (docs/networking.md §5).
//
// No value here is a secret. The proxy is what holds credentials; the guest is
// told only where to send its traffic (decision D6).
func applyEgressEnv() (proxy string) {
	blob, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, field := range strings.Fields(string(blob)) {
		value, ok := strings.CutPrefix(field, "kelyfos.proxy=")
		if !ok || value == "" {
			continue
		}
		url := "http://" + value
		// Both cases, because the convention is split down the middle: curl and
		// most C programs read the lowercase form, Go and much of the JVM world
		// read the uppercase one. Setting one and not the other produces a
		// sandbox where half the tools have egress and half do not.
		defaultEnv = append(defaultEnv,
			"HTTP_PROXY="+url, "HTTPS_PROXY="+url,
			"http_proxy="+url, "https_proxy="+url,
			"NO_PROXY=localhost,127.0.0.1", "no_proxy=localhost,127.0.0.1",
		)
		return value
	}
	return ""
}
