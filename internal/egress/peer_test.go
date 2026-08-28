package egress

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// peerRig starts a proxy that serves exactly one peer, in front of a TLS
// upstream that a credential is bound to. Everything a foreign caller could
// gain is on the table: the CONNECT is to a domain the policy allows, on a port
// it allows, with a secret bound to it — so a proxy that answers at all answers
// with the operator's token attached.
//
// Two loopback addresses stand in for the two ends of the TAP: 127.0.0.2 is the
// host's address, which the proxy binds, and 127.0.0.3 is the guest. The
// substitution is faithful in the way that matters here — both are local
// addresses, so both are reachable by any process on the machine over `lo`,
// which is the whole of F9 — and it is the only way to run this without root.
func peerRig(t *testing.T, peer netip.Addr) (proxyAddr, upstreamTarget string,
	sawAuth func() string, roots *x509.CertPool, attempts func() []Attempt) {
	t.Helper()

	var mu sync.Mutex
	var auth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}

	var amu sync.Mutex
	var got []Attempt
	p := &Proxy{
		Policy: Policy{
			Allow:   []string{host},
			Ports:   []int{upstreamPort(t, upstream)},
			Secrets: []*Secret{secret},
		},
		Peer:     peer,
		CA:       ca,
		Upstream: upstream.Client().Transport,
		OnEvent: func(a Attempt) {
			amu.Lock()
			defer amu.Unlock()
			got = append(got, a)
		},
	}
	port, err := p.Listen("127.0.0.2:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	return fmt.Sprintf("127.0.0.2:%d", port),
		strings.TrimPrefix(upstream.URL, "https://"),
		func() string { mu.Lock(); defer mu.Unlock(); return auth },
		roots,
		func() []Attempt { amu.Lock(); defer amu.Unlock(); return append([]Attempt(nil), got...) }
}

// dialFrom opens a connection to the proxy with a chosen source address, which
// is what a different local process on the same machine has.
func dialFrom(t *testing.T, src, proxyAddr string) (net.Conn, error) {
	t.Helper()
	d := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)},
		Timeout:   5 * time.Second,
	}
	return d.Dial("tcp", proxyAddr)
}

// TestF9_ProxyRefusesAForeignLocalPeer is the finding, and the whole of it: a
// process that is not the sandbox reaches the proxy's port — it can, and no
// firewall rule stops it, because the packet goes over `lo` and never touches
// the TAP the input chain matches on — and gets nothing.
//
// Before the fix this connection was served: the CONNECT succeeded, the proxy
// terminated TLS with its own CA and put the operator's GITHUB_TOKEN on the
// request. The token never left the host, which is what secret.go defends; it
// was simply spent by someone who could not read it.
func TestF9_ProxyRefusesAForeignLocalPeer(t *testing.T) {
	guest := netip.MustParseAddr("127.0.0.3")
	proxyAddr, target, sawAuth, _, attempts := peerRig(t, guest)

	// 127.0.0.1 is a local address that is not the guest — the stand-in for
	// another user's shell, a CI job, a compromised build script.
	raw, err := dialFrom(t, "127.0.0.1", proxyAddr)
	if err != nil {
		t.Fatalf("the foreign peer could not connect at all, so this test proves nothing: %v", err)
	}
	defer raw.Close()

	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	// A refusal here is a closed connection and nothing else. Not a 403: a
	// caller that is not the sandbox gets no status line, and no confirmation
	// that anything is behind this port.
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(raw).ReadString('\n')
	if err == nil {
		t.Fatalf("the proxy answered a foreign peer with %q; it must close and say nothing",
			strings.TrimSpace(line))
	}
	if sawAuth() != "" {
		t.Fatalf("the upstream saw Authorization %q for a peer that is not the guest", sawAuth())
	}

	// The operator has to be able to see it happened. A foreign connection to
	// the port that carries the credentials is not a policy question, it is an
	// event.
	var refusal *Attempt
	for _, a := range waitForAttempt(t, attempts, func(a Attempt) bool {
		return a.Reason == ReasonForeignPeer
	}) {
		if a.Reason == ReasonForeignPeer {
			cp := a
			refusal = &cp
		}
	}
	if refusal == nil {
		t.Fatal("the refusal was not recorded")
	}
	if refusal.Allowed {
		t.Errorf("the refusal is recorded as allowed: %+v", refusal)
	}
	if refusal.Mode != "" {
		t.Errorf("a refused connection has no mode, got %q", refusal.Mode)
	}
	if refusal.Peer != "127.0.0.1" {
		t.Errorf("the record says the connection came from %q, want 127.0.0.1", refusal.Peer)
	}
	// Host is a destination everywhere it is read — the digest enters it in the
	// Domains table and counts it Blocked, the report titles the row
	// "BLOCKED "+Host, and log, view and watch print it as somewhere the
	// sandbox tried to reach. A source address in it makes all five say the
	// guest named a host it never named.
	if refusal.Host != "" || refusal.Port != 0 {
		t.Errorf("a foreign-peer refusal named a destination: host=%q port=%d — no request was "+
			"ever parsed, so there is none to name", refusal.Host, refusal.Port)
	}
}

// The other half, and the one that fails if the check is written too tightly:
// the guest itself must still be served, credential and all.
func TestF9_ProxyStillServesTheGuest(t *testing.T) {
	guest := netip.MustParseAddr("127.0.0.3")
	proxyAddr, target, sawAuth, roots, _ := peerRig(t, guest)

	raw, err := dialFrom(t, "127.0.0.3", proxyAddr)
	if err != nil {
		t.Fatalf("the guest could not connect: %v", err)
	}
	defer raw.Close()

	host, _, _ := net.SplitHostPort(target)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("the guest's CONNECT was not answered: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("the guest's CONNECT was refused: %s", strings.TrimSpace(line))
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("drain headers: %v", err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	inner := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots})
	if err := inner.Handshake(); err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	resp.Body.Close()
	if got, want := sawAuth(), "Bearer "+testToken; got != want {
		t.Errorf("the guest's request carried Authorization %q, want %q", got, want)
	}
}

// An unset Peer restricts nothing, and that is a contract rather than an
// oversight: every other test in this package relies on it, and no sandbox may.
//
// It is asserted rather than left implicit so that the day somebody reads the
// Peer field and assumes the proxy defends itself, this says otherwise in one
// line — and so that changing the default is a decision somebody has to come
// here and make, with this test in front of them. What keeps that default from
// being a hole is not this test but the one below it,
// TestF9_EveryProxyConstructionArmsThePeerCheck: no proxy this product builds
// is allowed to leave Peer unset.
func TestF9_AnUnsetPeerRestrictsNothing(t *testing.T) {
	var got []Attempt
	var mu sync.Mutex
	p := &Proxy{OnEvent: func(a Attempt) { mu.Lock(); got = append(got, a); mu.Unlock() }}
	port, err := p.Listen("127.0.0.2:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	defer p.Close()

	raw, err := dialFrom(t, "127.0.0.1", fmt.Sprintf("127.0.0.2:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	// A request the policy refuses, so there is something to read back: the
	// point is that the connection is served at all, not that it succeeds.
	fmt.Fprint(raw, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(raw).ReadString('\n')
	if err != nil {
		t.Fatalf("a proxy with no Peer closed the connection unread; the default changed "+
			"and every caller that does not set Peer now refuses its own sandbox: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Errorf("the request was served but answered %q, want a 403 from the allowlist",
			strings.TrimSpace(line))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range got {
		if a.Reason == ReasonForeignPeer {
			t.Errorf("a proxy with no Peer refused a peer: %+v", a)
		}
	}
}

// A refused foreign connection must not count as the sandbox doing something.
// LastActive drives the idle timeout (E1-6); if a refusal advanced it, any
// local process could keep an idle sandbox alive forever by knocking — a
// smaller door than F9's, opened by the fix for it.
func TestF9_AForeignPeerDoesNotKeepTheSandboxAlive(t *testing.T) {
	p := &Proxy{Peer: netip.MustParseAddr("127.0.0.3")}
	port, err := p.Listen("127.0.0.2:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	defer p.Close()

	if !p.LastActive().IsZero() {
		t.Fatalf("a proxy that has served nothing reports activity at %v", p.LastActive())
	}
	raw, err := dialFrom(t, "127.0.0.1", fmt.Sprintf("127.0.0.2:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	// Wait for the close rather than for a clock: the refusal is synchronous
	// with it.
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("the proxy did not close the foreign connection")
	}
	if !p.LastActive().IsZero() {
		t.Errorf("a refused foreign connection advanced the idle clock to %v", p.LastActive())
	}
}

// peerAudit reports every place under root that builds an egress Proxy without
// arming its peer check, and how many construction sites it recognised at all.
//
// Both numbers are returned because the first version of the fixture test
// asserted only "exactly one finding" — and this function's own "found nothing
// at all" sentinel was itself a finding, so a fixture that stopped being caught
// produced exactly one finding, the sentinel, and passed. A reviewer deleted
// the dot-import and in-package detection outright and all six fixtures stayed
// green. The count is what makes that impossible to repeat: a shape that stops
// being recognised drops sites to zero, and no arrangement of findings can hide
// it. A check that cannot fail is not a check, which is the same lesson as the
// Listen comment this whole task exists to correct.
//
// Per construction, not per file. An earlier version excused a whole file if
// any `X.Peer` selector appeared anywhere in it — and recorder.Event has a Peer
// field, so host/log.go, host/view.go, host/teamgraph.go and host/forward.go
// were all pre-armed for free. It was cited as following
// host/audit_wiring_test.go, and that test's justification does not transfer:
// it is per-file because restoreNetwork builds a proxy its *caller* must wire,
// and must wire before sandbox.Restore, so the call cannot sit in the literal.
// Peer is a struct field with no such timing, every site sets it inline, and
// per-construction costs nothing. That test also matches a named function
// rather than a bare field selector, so it never had this weakness.
func peerAudit(t *testing.T, root string) (findings []string, sites int) {
	t.Helper()

	type parsedFile struct {
		path string
		fset *token.FileSet
		file *ast.File
		dir  string
	}
	var files []parsedFile

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			// testdata holds this test's own fixtures and is invisible to the
			// go tool; the rest hold build output or trees this product does
			// not compile.
			case ".git", ".claude", "bin", "out", "image", "docs", "vendor", "node_modules", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// Not fatal: a .go file that does not parse does not compile, so it
			// cannot be a construction site this product ships. Logged rather
			// than swallowed so it cannot become a quiet blind spot.
			t.Logf("skipping unparseable %s: %v", path, perr)
			return nil
		}
		files = append(files, parsedFile{path, fset, f, filepath.Dir(path)})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// What this file calls the package. Resolved from the import spec rather
	// than assumed to be "egress": `import eg ".../internal/egress"` slipped
	// past a literal-identifier match.
	naming := func(f *ast.File) (local string, dot bool) {
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil || !strings.HasSuffix(p, "/internal/egress") {
				continue
			}
			switch {
			case imp.Name == nil:
				local = "egress"
			case imp.Name.Name == ".":
				dot = true
			case imp.Name.Name == "_":
				// imported for effect only; it cannot name the type
			default:
				local = imp.Name.Name
			}
		}
		return local, dot
	}

	deparen := func(e ast.Expr) ast.Expr {
		for {
			p, ok := e.(*ast.ParenExpr)
			if !ok {
				return e
			}
			e = p.X
		}
	}

	// Local type names that ARE this Proxy, and local structs that embed it,
	// collected per directory: a type may be declared in one file of a package
	// and constructed in another.
	aliases := map[string]map[string]bool{}                 // dir -> type name
	fieldsOf := map[string]map[string]map[string]ast.Expr{} // dir -> type -> field -> type expr

	// isProxy for a type expression, in the context of one file.
	isProxy := func(pf parsedFile, e ast.Expr) bool {
		if e == nil {
			return false
		}
		local, dot := naming(pf.file)
		inPackage := pf.file.Name.Name == "egress"
		switch v := deparen(e).(type) {
		case *ast.SelectorExpr:
			id, ok := v.X.(*ast.Ident)
			return ok && local != "" && id.Name == local && v.Sel.Name == "Proxy"
		case *ast.Ident:
			if (inPackage || dot) && v.Name == "Proxy" {
				return true
			}
			return aliases[pf.dir][v.Name]
		}
		return false
	}
	// The same, for a type reached by eliding an element type: `[]*egress.Proxy{{…}}`
	// gives the inner literal the type `*egress.Proxy`, and the value it builds
	// is a Proxy. Not used for `var p *egress.Proxy`, which is a nil pointer and
	// builds nothing — host/run.go declares exactly that.
	isProxyElem := func(pf parsedFile, e ast.Expr) bool {
		if s, ok := deparen(e).(*ast.StarExpr); ok {
			e = s.X
		}
		return isProxy(pf, e)
	}

	// Pass one: type declarations. Two rounds so `type X = egress.Proxy` in one
	// file is known to another file of the same package.
	for round := 0; round < 2; round++ {
		for _, pf := range files {
			ast.Inspect(pf.file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				if isProxy(pf, ts.Type) || isProxyElem(pf, ts.Type) {
					if aliases[pf.dir] == nil {
						aliases[pf.dir] = map[string]bool{}
					}
					aliases[pf.dir][ts.Name.Name] = true
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					return true
				}
				for _, fld := range st.Fields.List {
					if len(fld.Names) == 0 {
						continue // embedded; handled in pass two, where it is a finding
					}
					if fieldsOf[pf.dir] == nil {
						fieldsOf[pf.dir] = map[string]map[string]ast.Expr{}
					}
					if fieldsOf[pf.dir][ts.Name.Name] == nil {
						fieldsOf[pf.dir][ts.Name.Name] = map[string]ast.Expr{}
					}
					for _, nm := range fld.Names {
						fieldsOf[pf.dir][ts.Name.Name][nm.Name] = fld.Type
					}
				}
				return true
			})
		}
	}

	hasPeer := func(cl *ast.CompositeLit) bool {
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Peer" {
				return true
			}
		}
		return false
	}
	// &T{…} and T{…} both reach a literal.
	litOf := func(e ast.Expr) *ast.CompositeLit {
		if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
			e = u.X
		}
		cl, _ := e.(*ast.CompositeLit)
		return cl
	}

	// Pass two: constructions.
	for _, pf := range files {
		at := func(pos token.Pos) string { return pf.fset.Position(pos).String() }
		// The type an elided child literal takes, filled in by its parent.
		// ast.Inspect visits a parent before its children, so a chain of
		// elisions resolves in one walk.
		elided := map[*ast.CompositeLit]ast.Expr{}

		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.TypeSpec:
				st, ok := v.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					return true
				}
				for _, fld := range st.Fields.List {
					if len(fld.Names) != 0 || !isProxyElem(pf, fld.Type) {
						continue
					}
					// Embedding hides the construction: a literal of the outer
					// type names the outer type, so nothing here can tell
					// whether Peer was set.
					sites++
					findings = append(findings, fmt.Sprintf(
						"%s: type %s embeds Proxy, which hides its construction from this audit — "+
							"a literal of %s names %s, not Proxy. Hold it in a named field instead — F9.",
						at(v.Pos()), v.Name.Name, v.Name.Name, v.Name.Name))
				}
			case *ast.CompositeLit:
				typ := v.Type
				if typ == nil {
					typ = elided[v]
				}
				if isProxyElem(pf, typ) {
					sites++
					if !hasPeer(v) {
						findings = append(findings, fmt.Sprintf(
							"%s: builds a Proxy without setting Peer, so it serves any process on the "+
								"host that can route to the address it binds — F9. Set Peer: <net>.GuestAddr().",
							at(v.Pos())))
					}
				}
				// Hand every child literal the type it inherits. This is what
				// `[]*egress.Proxy{{Policy: pol}}` needs — ordinary Go that a
				// refactor to more than one proxy would produce without anyone
				// noticing, and invisible to a match on the literal's own Type,
				// which is nil.
				var elem, key ast.Expr
				var fields map[string]ast.Expr
				switch tv := deparen(typ).(type) {
				case *ast.ArrayType:
					elem = tv.Elt
				case *ast.MapType:
					elem, key = tv.Value, tv.Key
				case *ast.Ident:
					fields = fieldsOf[pf.dir][tv.Name]
				case *ast.SelectorExpr:
					fields = fieldsOf[pf.dir][tv.Sel.Name]
				}
				for _, elt := range v.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						want := elem
						if fields != nil {
							if id, ok := kv.Key.(*ast.Ident); ok {
								want = fields[id.Name]
							}
						}
						if cl := litOf(kv.Value); cl != nil && cl.Type == nil && want != nil {
							elided[cl] = want
						}
						if cl := litOf(kv.Key); cl != nil && cl.Type == nil && key != nil {
							elided[cl] = key
						}
						continue
					}
					if cl := litOf(elt); cl != nil && cl.Type == nil && elem != nil {
						elided[cl] = elem
					}
				}
			case *ast.CallExpr:
				// new(Proxy) has no literal to carry the field.
				if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "new" && len(v.Args) == 1 && isProxy(pf, v.Args[0]) {
					sites++
					findings = append(findings, fmt.Sprintf(
						"%s: builds a Proxy with new(), which cannot set Peer. Use a composite "+
							"literal that sets it — F9.", at(v.Pos())))
				}
			case *ast.ValueSpec:
				// var p Proxy — the zero value. Not `var p *egress.Proxy`,
				// which is a nil pointer that builds nothing.
				if v.Type != nil && isProxy(pf, v.Type) && len(v.Values) == 0 {
					sites++
					findings = append(findings, fmt.Sprintf(
						"%s: declares a zero Proxy, whose Peer is unset. Construct it with a "+
							"composite literal that sets Peer — F9.", at(v.Pos())))
				}
			}
			return true
		})
	}
	return findings, sites
}

// Every proxy this product builds must arm its peer check. Read the source; do
// not trust a list.
//
// The repository, not one package: host/audit_wiring_test.go's equivalent scans
// `host` alone and would never have seen shim/shim.go, which builds a sixth
// proxy of its own.
func TestF9_EveryProxyConstructionArmsThePeerCheck(t *testing.T) {
	findings, sites := peerAudit(t, filepath.Join("..", ".."))
	for _, f := range findings {
		t.Error(f)
	}
	// Five production sites build one today. A walker that suddenly recognises
	// fewer has stopped looking somewhere, and would otherwise report a clean
	// bill for the wrong reason.
	if sites < 5 {
		t.Fatalf("recognised only %d Proxy construction sites in the repository; there are at "+
			"least five, so the walker has stopped seeing some of them", sites)
	}
	t.Logf("%d Proxy construction sites, all armed", sites)
}

// The audit has to actually catch things. Each fixture is one construction the
// walker must both recognise and refuse; `.go` files under testdata are
// invisible to the go tool, so they compile nothing and are only read as text.
//
// Both halves are asserted. Checking the finding count alone is what made the
// first version of this test inert: the "found nothing at all" sentinel was
// itself one finding, so a shape that stopped being recognised still produced
// exactly one and passed.
func TestF9_ThePeerAuditCatchesEveryEvasionShape(t *testing.T) {
	shapes := []struct{ dir, why string }{
		{"aliasimport", "an aliased import: &eg.Proxy{} where eg is this package"},
		{"dotimport", "a dot import: &Proxy{} with no qualifier at all"},
		{"newcall", "new(egress.Proxy), which has no literal to carry the field"},
		{"vardecl", "var p egress.Proxy, the zero value"},
		{"inpackage", "a factory inside package egress returning &Proxy{}"},
		{"prearmed", "an unarmed literal in a file that mentions X.Peer for an unrelated type"},
		{"sliceelided", "[]egress.Proxy{{…}} — the element type is elided, so the literal's own Type is nil"},
		{"ptrsliceelided", "[]*egress.Proxy{{…}} — the shape an ordinary refactor to several proxies produces"},
		{"mapelided", "map[string]*egress.Proxy{\"a\": {…}}"},
		{"arrayelided", "[1]egress.Proxy{{…}}"},
		{"embedded", "type w struct{ egress.Proxy } — the literal names w, not Proxy"},
		{"structfield", "holder{p: {…}} — a Proxy-typed field with the type elided"},
		{"namedtype", "type P = egress.Proxy, constructed under its local name"},
	}
	for _, s := range shapes {
		t.Run(s.dir, func(t *testing.T) {
			findings, sites := peerAudit(t, filepath.Join("testdata", "f9evasion", s.dir))
			if sites != 1 {
				t.Fatalf("%s — the walker recognised %d construction sites, want 1: it no longer "+
					"sees this shape at all, which is the failure a finding count cannot show",
					s.why, sites)
			}
			if len(findings) != 1 {
				t.Fatalf("%s — want exactly one finding, got %d: %v", s.why, len(findings), findings)
			}
			t.Logf("caught %s\n    %s", s.why, findings[0])
		})
	}
}

// The refusal has to be bounded, because it is the one refusal on this proxy
// that an unprivileged local process can drive in a tight loop for the cost of
// a TCP handshake — every other one makes the guest assemble and send a
// request first. Unbounded, it is a cheap write into the flight recorder, and
// through the digest's own MaxDistinctKeys it would evict the blocked-domain
// records the operator actually wants.
func TestF9_AForeignPeerIsRecordedOncePerAddressNotOncePerConnection(t *testing.T) {
	var mu sync.Mutex
	var got []Attempt
	p := &Proxy{
		Peer:    netip.MustParseAddr("127.0.0.3"),
		OnEvent: func(a Attempt) { mu.Lock(); got = append(got, a); mu.Unlock() },
	}
	port, err := p.Listen("127.0.0.2:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	defer p.Close()

	const knocks = 40
	for i := 0; i < knocks; i++ {
		raw, err := dialFrom(t, "127.0.0.1", fmt.Sprintf("127.0.0.2:%d", port))
		if err != nil {
			t.Fatalf("knock %d: %v", i, err)
		}
		_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := raw.Read(make([]byte, 1)); err == nil {
			t.Fatalf("knock %d was served", i)
		}
		raw.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d knocks from one address wrote %d events; a retry loop refused forty times "+
			"is one thing to look at, not forty", knocks, len(got))
	}
	if got[0].Peer != "127.0.0.1" || got[0].Reason != ReasonForeignPeer {
		t.Errorf("the one event is %+v", got[0])
	}
}

// The bound must not swallow a genuinely new address, up to its cap.
func TestF9_ADifferentForeignAddressIsItsOwnEvent(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	p := &Proxy{
		Peer:    netip.MustParseAddr("127.0.0.3"),
		OnEvent: func(a Attempt) { mu.Lock(); seen[a.Peer]++; mu.Unlock() },
	}
	port, err := p.Listen("127.0.0.2:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	defer p.Close()

	for _, src := range []string{"127.0.0.1", "127.0.0.4", "127.0.0.5", "127.0.0.1"} {
		raw, err := dialFrom(t, src, fmt.Sprintf("127.0.0.2:%d", port))
		if err != nil {
			t.Fatalf("dial from %s: %v", src, err)
		}
		_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = raw.Read(make([]byte, 1))
		raw.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("three distinct addresses knocked (one of them twice) and %d were recorded: %v",
			len(seen), seen)
	}
	for addr, n := range seen {
		if n != 1 {
			t.Errorf("%s was recorded %d times, want 1", addr, n)
		}
	}
}
