package config

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const validPlaceholder = "sp_test_abcdefghijklmnopqrstuvwxyz"

func TestParseExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/secproxy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("Parse(example) failed: %v", err)
	}
}

func TestParseRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown top-level key", baseYAML("mystery: true\n", ""), "field mystery not found"},
		{"egress and binding overlap", baseYAML("egress: [api.example.com]\n", bindingYAML("api.example.com", "slot: {header: Authorization}\n")), "overlaps egress host"},
		{"two slots", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization, query: {param: token}}\n")), "exactly one"},
		{"header format missing marker", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization, format: Bearer}\n")), "must contain {secret}"},
		{"TRACE method", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    methods: [TRACE]\n")), "TRACE is never allowed"},
		{"path with semicolon", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    paths: ['/ok;x/**']\n")), "must not contain %"},
		{"path with empty segment", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    paths: ['/ok//read']\n")), "empty segments"},
		{"path with dots-only segment", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    paths: ['/ok/.../x']\n")), ". or .. segments"},
		{"bare wildcard", baseYAML("egress: ['*']\n", ""), "bare wildcard"},
		{"public suffix wildcard", baseYAML("egress: ['*.com']\n", ""), "at least two labels"},
		{"IP literal", baseYAML("egress: [192.0.2.1]\n", ""), "IP literals"},
		{"short placeholder", strings.Replace(baseYAML("egress: [example.com]\n", ""), validPlaceholder, "short", 1), "at least 16"},
		{"duplicate placeholder", `version: 1
listen: {connect: ':8080'}
egress: [example.com]
secrets:
  one: {from_env: ONE, placeholder: ` + validPlaceholder + `}
  two: {from_env: TWO, placeholder: ` + validPlaceholder + `}
`, "share a placeholder"},
		{"both secret sources", strings.Replace(baseYAML("egress: [example.com]\n", ""), "from_env: TEST_SECRET", "from_env: TEST_SECRET, from_file: /tmp/secret", 1), "exactly one"},
		{"neither secret source", strings.Replace(baseYAML("egress: [example.com]\n", ""), "from_env: TEST_SECRET, ", "", 1), "exactly one"},
		{"bad inject value", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    inject: sometimes\n")), "inject must be"},
		{"persist_dir with key_env", baseYAML("ca: {persist_dir: /tmp/x, key_env: K, cert_env: C}\negress: [example.com]\n", ""), "persist_dir and key_env"},
		{"two always bindings on one slot", baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    inject: always\n")+`  - secret: token
    hosts: [api.example.com]
    slot: {basic: {username: u, password: "{secret}"}}
    inject: always
`), "already claimed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %v, want substring %q\nconfig:\n%s", err, tt.want, tt.yaml)
			}
		})
	}
}

func TestHeaderSlotShortAndNestedFormsMatch(t *testing.T) {
	t.Parallel()
	short, err := Parse([]byte(baseYAML("", bindingYAML("api.example.com", `slot: {header: Authorization, format: "Bearer {secret}"}`+"\n"))))
	if err != nil {
		t.Fatal(err)
	}
	nested, err := Parse([]byte(baseYAML("", bindingYAML("api.example.com", `slot: {header: {name: Authorization, format: "Bearer {secret}"}}`+"\n"))))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(short.Bindings[0].Slot.Header, nested.Bindings[0].Slot.Header) {
		t.Fatalf("short = %#v, nested = %#v", short.Bindings[0].Slot.Header, nested.Bindings[0].Slot.Header)
	}
}

func TestFillPlaceholders(t *testing.T) {
	t.Parallel()
	c := Config{Secrets: map[string]Secret{
		"set":   {Placeholder: validPlaceholder},
		"unset": {},
	}}
	c.FillPlaceholders()
	if got := c.Secrets["set"].Placeholder; got != validPlaceholder {
		t.Fatalf("existing placeholder changed to %q", got)
	}
	if got := c.Secrets["unset"].Placeholder; got == "" || checkPlaceholder(got) != nil {
		t.Fatalf("generated placeholder %q is invalid", got)
	}
}

func TestSecretValuesReportsEveryMissingSecret(t *testing.T) {
	t.Setenv("SECPROXY_MISSING_ONE", "")
	t.Setenv("SECPROXY_MISSING_TWO", "")
	c := Config{Secrets: map[string]Secret{
		"one": {FromEnv: "SECPROXY_MISSING_ONE"},
		"two": {FromEnv: "SECPROXY_MISSING_TWO"},
	}}
	_, err := c.SecretValues()
	if err == nil {
		t.Fatal("SecretValues() returned no error")
	}
	for _, name := range []string{`"one"`, `"two"`} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}
}

func TestNewPlaceholderShape(t *testing.T) {
	t.Parallel()
	pattern := regexp.MustCompile(`^sp_[a-z0-9_]+_[a-z2-7]{26}$`)
	for i := 0; i < 10; i++ {
		if got := NewPlaceholder("GitHub Token"); !pattern.MatchString(got) {
			t.Fatalf("NewPlaceholder() = %q", got)
		}
	}
}

func baseYAML(extra, bindings string) string {
	return `version: 1
listen: {connect: ':8080'}
secrets:
  token: {from_env: TEST_SECRET, placeholder: ` + validPlaceholder + `}
` + extra + bindings
}

func bindingYAML(host, slotAndRules string) string {
	return `bindings:
  - secret: token
    hosts: [` + host + `]
    ` + slotAndRules
}

func TestInjectDefaultsToPlaceholder(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Bindings[0].Inject; got != InjectPlaceholder {
		t.Fatalf("Inject = %q, want %q", got, InjectPlaceholder)
	}
	cfg, err = Parse([]byte(baseYAML("", bindingYAML("api.example.com", "slot: {header: Authorization}\n    inject: always\n"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Bindings[0].Inject; got != InjectAlways {
		t.Fatalf("Inject = %q, want %q", got, InjectAlways)
	}
}

func TestPersistDirExpandsHome(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML("ca: {persist_dir: ~/.config/secproxy/ca}\negress: [example.com]\n", "")))
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if cfg.CA.PersistDir != home+"/.config/secproxy/ca" {
		t.Fatalf("PersistDir = %q", cfg.CA.PersistDir)
	}
}

func TestSlotRejectsUnknownKeysDespiteCustomUnmarshaller(t *testing.T) {
	t.Parallel()
	// methods indented under slot must be an error, not a silently wider binding
	_, err := Parse([]byte(baseYAML("", bindingYAML("api.example.com", "slot:\n      header: Authorization\n      methods: [GET]\n"))))
	if err == nil || !strings.Contains(err.Error(), "field methods not found in slot") {
		t.Fatalf("Parse() error = %v", err)
	}
	_, err = Parse([]byte(baseYAML("", bindingYAML("api.example.com", "slot: {basic: {username: u, password: \"{secret}\", paths: [/x]}}\n"))))
	if err == nil || !strings.Contains(err.Error(), "field paths not found in slot.basic") {
		t.Fatalf("Parse() error = %v", err)
	}
	_, err = Parse([]byte(baseYAML("", bindingYAML("api.example.com", "slot: {header: {name: Authorization, fmt: x}}\n"))))
	if err == nil || !strings.Contains(err.Error(), "field fmt not found in slot.header") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestWildcardOverlapBetweenEgressAndBindingIsRejected(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte(baseYAML("egress: ['*.example.com']\n", bindingYAML("api.example.com", "slot: {header: Authorization}\n"))))
	if err == nil || !strings.Contains(err.Error(), "overlaps egress host") {
		t.Fatalf("wildcard egress over exact binding: %v", err)
	}
	_, err = Parse([]byte(baseYAML("egress: [api.example.com]\n", bindingYAML("'*.example.com'", "slot: {header: Authorization}\n"))))
	if err == nil || !strings.Contains(err.Error(), "overlaps egress host") {
		t.Fatalf("wildcard binding over exact egress: %v", err)
	}
	if _, err := Parse([]byte(baseYAML("egress: ['*.example.com']\n", bindingYAML("example.com", "slot: {header: Authorization}\n")))); err != nil {
		t.Fatalf("apex beside wildcard should be fine: %v", err)
	}
}
