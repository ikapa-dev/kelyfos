package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/egress"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// TestUnscrubbableModeIsABoundedSet drives the real wireProxyAudit hook and
// confirms that whatever Content-Encoding an origin chose, the Mode recorded on
// secret.unscrubbable is one of a fixed set — gzip, deflate, br, compress, zstd
// or other. That is what lets internal/recorder's eraseExempt keep Mode exempt
// (review L8): if origin-chosen text could reach the field, an erasure would
// leave guest-adjacent bytes behind. On main, OnUnscrubbable recorded the raw
// encoding, so "GZIP", " gzip " and "gzip, br" all reached the record verbatim
// and this test fails.
func TestUnscrubbableModeIsABoundedSet(t *testing.T) {
	root := t.TempDir()
	id := "unscrub"
	rec, err := recorder.Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()

	proxy := &egress.Proxy{}
	wireProxyAudit(proxy, rec, "", nil)
	if proxy.OnUnscrubbable == nil {
		t.Fatal("wireProxyAudit did not install an OnUnscrubbable hook")
	}

	cases := []struct {
		encoding string
		want     string
	}{
		{"gzip", "gzip"},
		{"GZIP", "gzip"},
		{" gzip ", "gzip"},
		{"x-gzip", "gzip"},
		{"deflate", "deflate"},
		{"DEFLATE", "deflate"},
		{"br", "br"},
		{"compress", "compress"},
		{"x-compress", "compress"},
		{"zstd", "zstd"},
		{"gzip, br", "other"},
		{"identity", "other"},
		{"exi", "other"},
		{"", "other"},
	}
	allowed := map[string]bool{
		"gzip": true, "deflate": true, "br": true, "compress": true, "zstd": true, "other": true,
	}

	for _, c := range cases {
		proxy.OnUnscrubbable("example.com", c.encoding)
	}

	blob, err := os.ReadFile(recorder.Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		if e.Type == recorder.TypeSecretUnscrubbable {
			got = append(got, e.Mode)
		}
	}
	if len(got) != len(cases) {
		t.Fatalf("recorded %d secret.unscrubbable events, want %d", len(got), len(cases))
	}
	for i, c := range cases {
		if !allowed[got[i]] {
			t.Errorf("encoding %q recorded Mode %q, which is outside the bounded set", c.encoding, got[i])
		}
		if got[i] != c.want {
			t.Errorf("encoding %q normalised to %q, want %q", c.encoding, got[i], c.want)
		}
	}
}
