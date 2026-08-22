package main

import (
	gocontext "context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"github.com/p4r4n0rm4l/KelyfOS/shim"
)

func shimCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos shim", flag.ExitOnError)
	var (
		addr   = fs.String("addr", "127.0.0.1:3000", "address to serve on")
		arch   = fs.String("arch", sandbox.HostArch(), "guest architecture")
		flavor = fs.String("image", "dev", "image flavor for sandboxes the shim creates")
		allow  = fs.String("allow", "", "egress allowlist for sandboxes the shim creates")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos shim [flags]

Serves an E2B-compatible REST subset so code written against the E2B SDK can
point at a self-hosted KelyfOS box. Point the SDK at it with:

    export E2B_API_KEY=e2b_kelyfos
    export E2B_API_URL=http://127.0.0.1:3000
    export E2B_SANDBOX_URL=http://127.0.0.1:3000

This is a best-effort subset: sandbox lifecycle and file transfer are supported,
command execution is not — the E2B SDK runs commands over Connect RPC with
protobuf streaming, which is a different protocol stack. Use kelyfos mcp for
commands. See docs/e2b-shim.md.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	srv := shim.New(*arch, *flavor, splitAllow(*allow))
	defer srv.Close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	http := &http.Server{Handler: srv.Handler()}

	fmt.Printf("kelyfos E2B shim listening on http://%s\n", ln.Addr())
	fmt.Printf("  sandboxes: image %s, arch %s", *flavor, *arch)
	if list := splitAllow(*allow); len(list) > 0 {
		fmt.Printf(", egress %s", strings.Join(list, ", "))
	} else {
		fmt.Print(", no egress")
	}
	fmt.Println("\n\nCtrl-C to stop; every sandbox the shim created is stopped with it.")

	go func() { _ = http.Serve(ln) }()

	ctx, stop := signal.NotifyContext(gocontext.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("\nstopping...")

	shutdownCtx, cancel := gocontext.WithTimeout(gocontext.Background(), 5*time.Second)
	defer cancel()
	_ = http.Shutdown(shutdownCtx)
	return nil
}
