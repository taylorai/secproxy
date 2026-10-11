package policy

import (
	"strings"
	"testing"

	"github.com/taylorai/secproxy/internal/config"
)

const (
	testPlaceholder = "sp_token_abcdefghijklmnopqrstuvwxyz"
	testSecret      = "real-secret-value"
)

func compileTestPolicy(t *testing.T, unmatched string, egress []string, bindings []config.Binding) *Policy {
	t.Helper()
	cfg := &config.Config{
		UnmatchedHost: unmatched,
		Egress:        egress,
		Secrets: map[string]config.Secret{
			"token": {Placeholder: testPlaceholder},
		},
		Bindings: bindings,
	}
	p, err := Compile(cfg, map[string]string{"token": testSecret})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecide(t *testing.T) {
	t.Parallel()
	binding := config.Binding{
		Secret: "token", Hosts: []string{"api.example.com"},
		Slot: config.Slot{Header: &config.HeaderSlot{Name: "Authorization", Format: "Bearer {secret}"}},
	}
	p := compileTestPolicy(t, "deny", []string{"public.example.com", "api.example.com"}, []config.Binding{binding})
	if got := p.Decide("api.example.com"); got != Inspect {
		t.Fatalf("binding and egress decision = %s, want inspect", got)
	}
	if got := p.Decide("public.example.com"); got != Passthrough {
		t.Fatalf("egress decision = %s, want passthrough", got)
	}
	if got := p.Decide("other.example.com"); got != Deny {
		t.Fatalf("unmatched decision = %s, want deny", got)
	}

	p = compileTestPolicy(t, "passthrough", nil, []config.Binding{binding})
	if got := p.Decide("other.example.com"); got != Passthrough {
		t.Fatalf("passthrough default decision = %s", got)
	}
}

func TestReplacementsIncludesBasicAndDeduplicates(t *testing.T) {
	t.Parallel()
	basic := &config.BasicSlot{Username: "x-access-token", Password: "{secret}"}
	p := compileTestPolicy(t, "deny", nil, []config.Binding{
		{Secret: "token", Hosts: []string{"api.example.com"}, Slot: config.Slot{Basic: basic}},
		{Secret: "token", Hosts: []string{"api.example.com"}, Slot: config.Slot{Header: &config.HeaderSlot{Name: "X-Token", Format: "{secret}"}}},
	})
	got := p.Replacements("api.example.com")
	if len(got) != 2 {
		t.Fatalf("Replacements() has %d entries, want value and basic token: %#v", len(got), got)
	}
	want := map[[2]string]bool{
		{testSecret, testPlaceholder}:                                       true,
		{basicToken(basic, testSecret), basicToken(basic, testPlaceholder)}: true,
	}
	for _, pair := range got {
		if !want[pair] {
			t.Errorf("unexpected replacement %#v", pair)
		}
	}
}

func TestSummaryOmitsSecretValues(t *testing.T) {
	t.Parallel()
	p := compileTestPolicy(t, "deny", nil, []config.Binding{{
		Secret: "token", Hosts: []string{"api.example.com"},
		Slot: config.Slot{Header: &config.HeaderSlot{Name: "Authorization", Format: "Bearer {secret}"}},
	}})
	summary := p.Summary()
	if strings.Contains(summary, testSecret) || strings.Contains(summary, testPlaceholder) {
		t.Fatalf("Summary exposed a credential: %q", summary)
	}
}
