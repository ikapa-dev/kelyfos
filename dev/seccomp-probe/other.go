//go:build !linux

// Reading another process's installed seccomp filter is a Linux operation
// through and through — ptrace, PTRACE_SECCOMP_GET_FILTER, /proc. This stub
// exists so the package still builds on a macOS workstation, where `go vet
// ./...` runs before anything is pushed.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr,
		"seccomp-probe: reads a Linux process's installed filter; this is %s.\n"+
			"    Run it where the VMM runs: limactl shell kelyfos-dev -- sudo ./bin/seccomp-probe -pid <pid>\n",
		runtime.GOOS)
	os.Exit(2)
}
