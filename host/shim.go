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

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
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
	typed := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { typed[f.Name] = true })

	// The project's policy applies here exactly as it applies to `kelyfos run`.
	// An entry path that skips the file is a hole in the wall, and a shim
	// sandbox that quietly ran uncapped was one (F-D33).
	pol := shim.Policy{
		Arch: *arch, Flavor: *flavor, Allow: splitAllow(*allow),
		Vcpus: 2, MemMiB: 512,
		Argv: append([]string{"kelyfos", "shim"}, argv...), Version: Version,
	}
	cfg, err := loadPolicy()
	if err != nil {
		return err
	}
	if cfg != nil {
		pol.PolicyPath = cfg.Path
		if cfg.Image != "" && !typed["image"] {
			pol.Flavor = cfg.Image
		}
		if cfg.Arch != "" && !typed["arch"] {
			pol.Arch = cfg.Arch
		}
		if len(cfg.Allow) > 0 && !typed["allow"] {
			pol.Allow = cfg.Allow
		}
		// The caps have no flags on this command at all, so there is no request
		// to check against a ceiling: the declared value is the value, which is
		// what docs/resources.md says of every flagless limit. An SDK client
		// cannot ask for a bigger machine, and that is the point.
		if cfg.ResCPUs > 0 {
			pol.Vcpus = cfg.ResCPUs
		} else if cfg.Vcpus > 0 {
			pol.Vcpus = cfg.Vcpus
		}
		if cfg.ResMemMiB > 0 {
			pol.MemMiB = cfg.ResMemMiB
		} else if cfg.MemMiB > 0 {
			pol.MemMiB = cfg.MemMiB
		}
		pol.CPUQuota = cfg.ResCPUQuota
		pol.ScratchBytes = cfg.ResScratchByte
		pol.IO = sandbox.IOLimits{
			NetMbpsRx: cfg.ResNetMbpsRx, NetMbpsTx: cfg.ResNetMbpsTx,
			DiskIOPS: cfg.ResDiskIOPS, DiskMbps: cfg.ResDiskMbps,
		}
		if len(cfg.Secrets) > 0 {
			for _, spec := range cfg.Secrets {
				sec, err := egress.ParseSecret(spec)
				if err != nil {
					return err
				}
				if !containsDomain(pol.Allow, sec.Domain) {
					return denial.SecretUnallowed.Err(denial.V{"spec": spec, "domain": sec.Domain})
				}
				pol.Secrets = append(pol.Secrets, sec)
			}
		}
		if pol.ScratchBytes > 0 && pol.ScratchBytes > int64(pol.MemMiB)<<20 {
			line, _ := cfg.Ceiling("scratch")
			return fmt.Errorf("scratch = %d bytes at %s:%d is larger than the %d MiB the machine has",
				pol.ScratchBytes, cfg.Path, line, pol.MemMiB)
		}
	}

	srv := shim.New(pol)
	defer srv.Close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	// After the listen rather than before it, so the check reads the address
	// the kernel actually gave — `--addr :0` and `--addr localhost:3000` are
	// both a different string by now — and the socket is closed again before
	// anything can reach it.
	if err := shimBindNeedsAToken(ln.Addr().String(), os.Getenv(shim.TokenEnv)); err != nil {
		ln.Close()
		return err
	}
	// The Host header is checked against this on every route (P7-17/F2), and
	// it is the listener's own address rather than the flag: the two differ
	// for every form of --addr that names a port of zero or a name.
	srv.Policy.Addr = ln.Addr().String()

	http := &http.Server{Handler: srv.Handler()}

	fmt.Printf("kelyfos E2B shim listening on http://%s\n", ln.Addr())
	if pol.PolicyPath != "" {
		fmt.Printf("policy: %s\n", pol.PolicyPath)
	}
	fmt.Printf("  sandboxes: image %s, arch %s, %d vcpu, %d MiB", pol.Flavor, pol.Arch, pol.Vcpus, pol.MemMiB)
	if pol.CPUQuota > 0 {
		fmt.Printf(", cpu %d%%", pol.CPUQuota)
	}
	if len(pol.Allow) > 0 {
		fmt.Printf(", egress %s", strings.Join(pol.Allow, ", "))
	} else {
		fmt.Print(", no egress")
	}
	fmt.Println()
	fmt.Println("  every sandbox it creates gets its own flight recorder; kelyfos log --list shows them")
	fmt.Println("\nCtrl-C to stop; every sandbox the shim created is stopped with it.")

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

// shimBindNeedsAToken refuses a bind that is reachable from the network unless
// a credential is set (P7-17/F2).
//
// `--addr` accepts any address, and docs/e2b-shim.md already says a shim off
// loopback is reachable from the LAN — but the code let it happen silently, on
// a surface whose routes boot microVMs and write files into a live sandbox. A
// bind is the one moment the process knows it is about to be reachable, so this
// is where it is answered, and it is answered by refusing rather than warning:
// a warning on a port that is already open is a warning nobody acts on in time.
//
// addr is the LISTENER's own address, not the string the operator typed, so
// `--addr :3000` and `--addr localhost:3000` are both resolved before they get
// here. An address that will not split is refused rather than assumed safe.
func shimBindNeedsAToken(addr, token string) error {
	if token != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("cannot tell whether %q is reachable from the network: %w.\n"+
			"Set %s to a shared secret, or bind an address this can read", addr, err, shim.TokenEnv)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s is reachable from the network and this shim has no credential.\n"+
		"Any machine that can route to it could boot sandboxes, kill them, and read and\n"+
		"write files inside them. Set %s to a shared secret — every route then requires\n"+
		"Authorization: Bearer <token> — or bind loopback (--addr 127.0.0.1:3000).",
		addr, shim.TokenEnv)
}
