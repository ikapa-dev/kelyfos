package main

import (
	"net"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// The channel credential, guest side (audit 2026-09-01, A2/A3): what the host
// hands over on the control channel is validated before it is stored, and what
// this process dials outbound presents it first.

const (
	// A well-formed credential: 32 bytes of entropy, hex-encoded.
	goodCredential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// What a peer that does not have the credential would send, or an
	// attacker guessing: any string that is not the credential.
	badCredential = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func TestSetChannelCredentialTakesOnlyACredential(t *testing.T) {
	t.Cleanup(func() { _ = setChannelCredential("") })
	if err := setChannelCredential(goodCredential); err != nil {
		t.Fatalf("a well-formed credential was refused: %v", err)
	}
	if got := currentChannelCredential(); got != goodCredential {
		t.Errorf("the credential did not stick: %q", got)
	}
	for _, bad := range []string{
		"",                                    // nothing
		"abc",                                 // too short
		goodCredential + "0",                  // too long
		strings.Repeat("g", credentialHexLen), // not hex
	} {
		if err := setChannelCredential(bad); err == nil {
			t.Errorf("a malformed credential (%d bytes) was stored", len(bad))
		}
	}
	// A refusal stored nothing: the good credential is still the one held.
	if got := currentChannelCredential(); got != goodCredential {
		t.Errorf("a refused credential replaced the stored one: %q", got)
	}
	// And a later, legitimate re-hand (the restore path's fresh value)
	// replaces rather than merges.
	if err := setChannelCredential(badCredential[:len(badCredential)-1] + "e"); err != nil {
		t.Fatalf("a second well-formed credential was refused: %v", err)
	}
	if got := currentChannelCredential(); got != badCredential[:len(badCredential)-1]+"e" {
		t.Errorf("a re-handed credential did not replace the first: %q", got)
	}
}

// The presentation is the first frame on the connection: one JSON line, the
// credential in it, nothing before it — the host reads it with the
// first-frame deadline and refuses the connection if it is not there.
func TestPresentCredentialWritesTheHelloFirst(t *testing.T) {
	t.Cleanup(func() { _ = setChannelCredential("") })
	if err := setChannelCredential(goodCredential); err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() { _ = presentCredential(client) }()
	var hello credentialHello
	if err := proto.NewReader(server).Read(&hello); err != nil {
		t.Fatalf("the hello did not arrive: %v", err)
	}
	if hello.Auth != goodCredential {
		t.Errorf("the hello carried %q, want the credential", hello.Auth)
	}
}
