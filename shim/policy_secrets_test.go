package shim

import (
	"fmt"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
)

// Policy.Secrets holds *egress.Secret, matching every other container that
// carries secrets in this codebase, so that a stray %v or %+v on the slice —
// or on Policy as a whole — goes through Secret's pointer-receiver String()
// rather than reflecting over a value copy and printing the credential
// (finding F10). This pins that a Policy value formats safely end to end,
// the same way TestSecretValueNeverFormats pins it for a bare Secret.
func TestPolicySecretsNeverFormatTheirValue(t *testing.T) {
	const testToken = "super-secret-token-value"
	t.Setenv("GITHUB_TOKEN", testToken)

	sec, err := egress.ParseSecret("GITHUB_TOKEN@example.com")
	if err != nil {
		t.Fatal(err)
	}

	pol := Policy{Allow: []string{"example.com"}, Secrets: []*egress.Secret{sec}}

	for _, rendered := range []string{
		fmt.Sprintf("%v", pol),
		fmt.Sprintf("%+v", pol),
		fmt.Sprintf("%v", pol.Secrets),
		fmt.Sprintf("%+v", pol.Secrets),
		fmt.Sprintf("%v", pol.Secrets[0]),
		fmt.Sprintf("%+v", pol.Secrets[0]),
	} {
		if strings.Contains(rendered, testToken) {
			t.Errorf("Policy rendered a secret's value: %s", rendered)
		}
	}
}
