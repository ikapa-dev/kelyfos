package main

import (
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/shim"
)

// P7-17/F2, the flipped default (owner's ruling of 2026-08-29).
//
// Unauthenticated was the shim's documented default for three phases. The
// argument for it — "a tool for a machine you already trust" — answered the
// wrong question: while the browser checks close the cross-site hole
// structurally, every other process on the machine could still boot microVMs
// and write files into a live sandbox for the price of knowing the port. So a
// token is minted per process, printed once, and running without one takes a
// flag, because an opt-out is a choice the operator can see and an opt-in is a
// step nobody takes. host/view.go is the model and newLocalToken is literally
// its function.

func TestF2_AShimWithNoConfiguredTokenMintsOne(t *testing.T) {
	t.Setenv(shim.TokenEnv, "")

	tok, err := shimToken(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Errorf("minted token is %d characters, want 64 (256 bits, hex)", len(tok))
	}
	if strings.Trim(tok, "0123456789abcdef") != "" {
		t.Errorf("minted token is not hex: %q", tok)
	}
	// Per process, not per product: two shims on one machine do not share a
	// credential.
	other, err := shimToken(false)
	if err != nil {
		t.Fatal(err)
	}
	if other == tok {
		t.Error("two calls minted the same token")
	}
}

func TestF2_AConfiguredTokenIsUsedAsGiven(t *testing.T) {
	t.Setenv(shim.TokenEnv, "an-operator-chose-this")
	tok, err := shimToken(false)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "an-operator-chose-this" {
		t.Errorf("token = %q, want the environment's", tok)
	}
}

func TestF2_RunningWithNoTokenTakesTheFlag(t *testing.T) {
	t.Setenv(shim.TokenEnv, "")
	tok, err := shimToken(true)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Errorf("--insecure-no-token still produced a token: %q", tok)
	}
}

// The flag and the variable ask for opposite things, so asking for both is a
// mistake rather than a precedence puzzle.
func TestF2_TheFlagAndTheVariableTogetherAreRefused(t *testing.T) {
	t.Setenv(shim.TokenEnv, "an-operator-chose-this")
	if _, err := shimToken(true); err == nil {
		t.Fatal("--insecure-no-token with the variable set was accepted")
	} else if !strings.Contains(err.Error(), shim.TokenEnv) {
		t.Errorf("the refusal does not name the variable: %v", err)
	}
}

// Printed once, and the operator has to be able to act on it: the export line
// for a second terminal or a restart, and the header form because that is the
// only form a request may carry.
func TestF2_TheMintedTokenIsPrintedWithBothWaysToUseIt(t *testing.T) {
	var b strings.Builder
	printShimToken(&b, "deadbeef", "127.0.0.1:3000", false)
	got := b.String()
	for _, want := range []string{
		"deadbeef",
		"export " + shim.TokenEnv + "=deadbeef",
		"Authorization: Bearer deadbeef",
		"127.0.0.1:3000",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the start-up block does not carry %q:\n%s", want, got)
		}
	}

	// A token the operator supplied is not echoed back at them: it is already
	// in their environment, and reprinting a credential they chose puts it in
	// one more scrollback for no gain.
	b.Reset()
	printShimToken(&b, "an-operator-chose-this", "127.0.0.1:3000", true)
	if strings.Contains(b.String(), "an-operator-chose-this") {
		t.Errorf("a token from the environment was echoed:\n%s", b.String())
	}
	if !strings.Contains(b.String(), shim.TokenEnv) {
		t.Errorf("the block does not say where the token came from:\n%s", b.String())
	}

	// And running without one says what that means, in the words the threat
	// model uses.
	b.Reset()
	printShimToken(&b, "", "127.0.0.1:3000", false)
	if !strings.Contains(b.String(), "insecure-no-token") {
		t.Errorf("the no-token block does not name the flag that caused it:\n%s", b.String())
	}
}
