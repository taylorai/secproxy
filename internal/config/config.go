// Package config defines the secproxy configuration file and validates it.
//
// The config file never contains secret values. It says where each secret
// comes from (an environment variable or a file), what placeholder the
// sandboxed program holds instead, and the exact places that placeholder may
// be exchanged for the real value.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level document.
type Config struct {
	Version int    `yaml:"version"`
	RunID   string `yaml:"run_id"`

	Listen Listen   `yaml:"listen"`
	CA     CAConfig `yaml:"ca"`

	// UnmatchedHost says what to do with a destination that is neither an
	// egress host nor a binding host: "deny" (default) or "passthrough".
	// Unmatched hosts are never inspected.
	UnmatchedHost string `yaml:"unmatched_host"`

	// Egress hosts are forwarded as raw TLS bytes. No decryption, no secrets.
	Egress []string `yaml:"egress"`

	// Secrets is keyed by a short name used in bindings (e.g. "github").
	Secrets map[string]Secret `yaml:"secrets"`

	// Bindings say where a secret's placeholder may be exchanged.
	Bindings []Binding `yaml:"bindings"`
}

// Listen configures the two front doors. Either may be empty.
type Listen struct {
	// Transparent accepts raw TLS connections and reads the destination from
	// SNI. This is what a network-level relay (a sidecar that receives all
	// port-443 traffic) talks to. Example: ":443".
	Transparent string `yaml:"transparent"`

	// Connect is a normal HTTP proxy endpoint for HTTPS_PROXY-aware clients.
	// Handles CONNECT and absolute-form http:// requests. Example: ":8080".
	Connect string `yaml:"connect"`
}

// CAConfig controls the certificate authority used to decrypt inspected hosts.
type CAConfig struct {
	// CertOut is where the public CA certificate is written at startup so
	// the orchestrator can hand it to the sandbox. The private key is not
	// written here, whichever way the CA was obtained.
	CertOut string `yaml:"cert_out"`

	// The root comes from one of three places, checked in this order:
	//
	// PersistDir is a directory holding ca.pem and ca.key. If they exist
	// they are loaded; if not, a CA valid for a year is minted and written
	// there. For a proxy on a laptop, where the user trusts the certificate
	// once and expects it to stay valid across restarts. A leading "~/" is
	// expanded.
	PersistDir string `yaml:"persist_dir"`

	// KeyEnv names an env var holding a PEM CA private key, with CertEnv
	// holding the matching certificate. For an orchestrator that wants to
	// hand the certificate to the sandbox before the proxy starts.
	KeyEnv  string `yaml:"key_env"`
	CertEnv string `yaml:"cert_env"`

	// When neither is set, an ephemeral CA is generated in memory at startup
	// and dies with the process. This is the right default for a sidecar.
}

// Secret says where a real value comes from and what stands in for it.
type Secret struct {
	FromEnv  string `yaml:"from_env"`
	FromFile string `yaml:"from_file"`

	// Placeholder is the fake value the sandbox holds. Random per run.
	// Generated at load time if empty (see Config.FillPlaceholders).
	Placeholder string `yaml:"placeholder"`

	// Env is the environment variable name the sandbox expects, e.g.
	// GITHUB_TOKEN. Used by `secproxy env` and `secproxy run`. Optional.
	Env string `yaml:"env"`
}

// Binding permits one secret to be substituted into one slot for a set of
// hosts, optionally restricted by method and path.
type Binding struct {
	Secret  string   `yaml:"secret"`
	Hosts   []string `yaml:"hosts"`
	Slot    Slot     `yaml:"slot"`
	Methods []string `yaml:"methods"` // empty = any
	Paths   []string `yaml:"paths"`   // empty = any; glob: * = one segment, ** = any

	// Inject says when the secret goes into the slot:
	//
	//   placeholder  (default) only when the slot holds exactly the
	//                placeholder. A request without it goes upstream as-is.
	//   always       on every request to the host. The slot may be empty or
	//                hold the placeholder; either way the real value goes in.
	//                A slot holding anything else is refused, so a different
	//                credential is never silently replaced. Methods and paths
	//                then gate the request itself, not just secret use.
	//
	// "always" is for programs that cannot be handed the placeholder (they
	// read credentials from their own config, or validate the token's shape
	// before sending). With it, the sandbox need not hold the placeholder
	// at all.
	Inject string `yaml:"inject"`
}

// Inject values.
const (
	InjectPlaceholder = "placeholder"
	InjectAlways      = "always"
)

// Slot is exactly one of Header, Basic, Query.
type Slot struct {
	Header *HeaderSlot `yaml:"header"`
	Basic  *BasicSlot  `yaml:"basic"`
	Query  *QuerySlot  `yaml:"query"`
}

// HeaderSlot substitutes a whole header value. Format defaults to "{secret}";
// a typical value is "Bearer {secret}". The header value sent by the sandbox
// must equal Format with {secret} replaced by the placeholder, exactly.
type HeaderSlot struct {
	Name   string `yaml:"name"`
	Format string `yaml:"format"`
}

// BasicSlot substitutes inside an HTTP Basic Authorization header. Username
// and Password are templates; at least one must contain {secret}. Git sends
// credentials this way.
type BasicSlot struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// QuerySlot substitutes the value of one query parameter, which must equal
// the placeholder exactly.
type QuerySlot struct {
	Param string `yaml:"param"`
}

// UnmarshalYAML lets a header slot be written in the short form
//
//	slot: { header: Authorization, format: "Bearer {secret}" }
//
// as well as the nested form
//
//	slot: { header: { name: Authorization, format: "Bearer {secret}" } }
//
// A custom unmarshaller bypasses the decoder's KnownFields setting, so the
// keys are checked by hand here. Without that, "methods:" indented one level
// too far would vanish into the slot and silently widen the binding.
func (s *Slot) UnmarshalYAML(n *yaml.Node) error {
	if err := knownKeys(n, "slot", "header", "format", "basic", "query"); err != nil {
		return err
	}
	type raw struct {
		Header yaml.Node `yaml:"header"`
		Format string    `yaml:"format"`
		Basic  yaml.Node `yaml:"basic"`
		Query  yaml.Node `yaml:"query"`
	}
	var r raw
	if err := n.Decode(&r); err != nil {
		return err
	}
	if r.Basic.Kind != 0 {
		if err := knownKeys(&r.Basic, "slot.basic", "username", "password"); err != nil {
			return err
		}
		s.Basic = &BasicSlot{}
		if err := r.Basic.Decode(s.Basic); err != nil {
			return err
		}
	}
	if r.Query.Kind != 0 {
		if err := knownKeys(&r.Query, "slot.query", "param"); err != nil {
			return err
		}
		s.Query = &QuerySlot{}
		if err := r.Query.Decode(s.Query); err != nil {
			return err
		}
	}
	switch r.Header.Kind {
	case 0:
		// no header slot
	case yaml.ScalarNode:
		s.Header = &HeaderSlot{Name: r.Header.Value, Format: r.Format}
	case yaml.MappingNode:
		if err := knownKeys(&r.Header, "slot.header", "name", "format"); err != nil {
			return err
		}
		s.Header = &HeaderSlot{}
		if err := r.Header.Decode(s.Header); err != nil {
			return err
		}
	default:
		return errors.New("slot.header must be a string or a mapping")
	}
	return nil
}

// knownKeys rejects a mapping node with any key outside allowed, matching
// what yaml's KnownFields(true) does for ordinary structs.
func knownKeys(n *yaml.Node, where string, allowed ...string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a mapping", where)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		ok := false
		for _, a := range allowed {
			if key == a {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("line %d: field %s not found in %s", n.Content[i].Line, key, where)
		}
	}
	return nil
}

// Load reads, parses and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses and validates config bytes.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo must not silently widen or narrow policy
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.UnmatchedHost == "" {
		c.UnmatchedHost = "deny"
	}
	for i := range c.Bindings {
		if h := c.Bindings[i].Slot.Header; h != nil && h.Format == "" {
			h.Format = "{secret}"
		}
		if c.Bindings[i].Inject == "" {
			c.Bindings[i].Inject = InjectPlaceholder
		}
	}
	c.CA.PersistDir = expandHome(c.CA.PersistDir)
	c.CA.CertOut = expandHome(c.CA.CertOut)
}

// expandHome replaces a leading "~/" with the user's home directory, which
// YAML does not do for us. Anything else is returned unchanged.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return home + path[1:]
}

// Validate checks everything that can be checked without touching the
// network or the secret values. All failures are hard errors: the proxy
// must not start with a config it only partly understands.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Version != 1 {
		fail("version must be 1")
	}
	if c.Listen.Transparent == "" && c.Listen.Connect == "" {
		fail("listen: at least one of transparent or connect is required")
	}
	if c.UnmatchedHost != "deny" && c.UnmatchedHost != "passthrough" {
		fail("unmatched_host must be deny or passthrough, got %q", c.UnmatchedHost)
	}
	if (c.CA.KeyEnv == "") != (c.CA.CertEnv == "") {
		fail("ca: key_env and cert_env must be set together")
	}
	if c.CA.PersistDir != "" && c.CA.KeyEnv != "" {
		fail("ca: persist_dir and key_env/cert_env both say where the CA comes from; use one")
	}

	hostOwner := map[string]string{} // canonical host pattern -> "egress" or binding secret
	var egress []string
	for _, h := range c.Egress {
		p, err := CanonicalHostPattern(h)
		if err != nil {
			fail("egress %q: %v", h, err)
			continue
		}
		if _, dup := hostOwner[p]; dup {
			fail("egress %q listed twice", p)
		}
		hostOwner[p] = "egress"
		egress = append(egress, p)
	}

	placeholders := map[string]string{}
	for name, s := range c.Secrets {
		if name == "" || strings.ContainsAny(name, " \t/") {
			fail("secret name %q is not a simple identifier", name)
		}
		if (s.FromEnv == "") == (s.FromFile == "") {
			fail("secret %q: exactly one of from_env or from_file is required", name)
		}
		if s.Placeholder != "" {
			if err := checkPlaceholder(s.Placeholder); err != nil {
				fail("secret %q: %v", name, err)
			}
			if other, dup := placeholders[s.Placeholder]; dup {
				fail("secret %q and %q share a placeholder", name, other)
			}
			placeholders[s.Placeholder] = name
		}
	}

	if len(c.Bindings) == 0 && len(c.Egress) == 0 && c.UnmatchedHost == "deny" {
		fail("config permits no traffic at all (no egress, no bindings, unmatched_host: deny)")
	}
	alwaysSlots := map[string]string{} // host pattern + slot -> binding, for inject: always
	for i, b := range c.Bindings {
		where := fmt.Sprintf("bindings[%d]", i)
		if _, ok := c.Secrets[b.Secret]; !ok {
			fail("%s: unknown secret %q", where, b.Secret)
		}
		if len(b.Hosts) == 0 {
			fail("%s: hosts is required", where)
		}
		if b.Inject != InjectPlaceholder && b.Inject != InjectAlways {
			fail("%s: inject must be %s or %s, got %q", where, InjectPlaceholder, InjectAlways, b.Inject)
		}
		for _, h := range b.Hosts {
			p, err := CanonicalHostPattern(h)
			if err != nil {
				fail("%s: host %q: %v", where, h, err)
				continue
			}
			for _, e := range egress {
				if PatternMatches(e, p) || PatternMatches(p, e) {
					fail("%s: host %q overlaps egress host %q; a host is either passed through or inspected, not both", where, p, e)
				}
			}
			hostOwner[p] = b.Secret
			if b.Inject == InjectAlways {
				// Two bindings that both want to fill the same slot on every
				// request to the same host cannot both win.
				key := p + " " + b.Slot.key()
				if other, dup := alwaysSlots[key]; dup {
					fail("%s: inject: always for %s on %s is already claimed by %s", where, b.Slot.key(), p, other)
				}
				alwaysSlots[key] = where
			}
		}
		if err := b.Slot.validate(); err != nil {
			fail("%s: slot: %v", where, err)
		}
		for _, m := range b.Methods {
			if m != strings.ToUpper(m) || m == "" {
				fail("%s: method %q must be upper case", where, m)
			}
			if m == "TRACE" || m == "TRACK" || m == "CONNECT" {
				fail("%s: method %s is never allowed", where, m)
			}
		}
		for _, p := range b.Paths {
			if err := checkPathPattern(p); err != nil {
				fail("%s: path %q: %v", where, p, err)
			}
		}
	}
	return errors.Join(errs...)
}

// key names the place a slot writes to, so two bindings aiming at the same
// place can be detected. Basic auth lives in the Authorization header.
func (s *Slot) key() string {
	switch {
	case s.Header != nil:
		return "header " + strings.ToLower(s.Header.Name)
	case s.Basic != nil:
		return "header authorization"
	case s.Query != nil:
		return "query " + s.Query.Param
	}
	return "?"
}

func (s *Slot) validate() error {
	n := 0
	if s.Header != nil {
		n++
		if s.Header.Name == "" {
			return errors.New("header name is required")
		}
		if strings.ContainsAny(s.Header.Name, " :\r\n") {
			return fmt.Errorf("header name %q is not a valid header name", s.Header.Name)
		}
		if strings.EqualFold(s.Header.Name, "Host") || strings.HasPrefix(strings.ToLower(s.Header.Name), "proxy-") {
			return fmt.Errorf("header %q may not carry a secret", s.Header.Name)
		}
		if strings.Count(s.Header.Format, "{secret}") != 1 {
			return errors.New("header format must contain {secret} exactly once")
		}
		if strings.ContainsAny(s.Header.Format, "\r\n") {
			return errors.New("header format may not contain newlines")
		}
	}
	if s.Basic != nil {
		n++
		if !strings.Contains(s.Basic.Username, "{secret}") && !strings.Contains(s.Basic.Password, "{secret}") {
			return errors.New("basic: username or password must contain {secret}")
		}
		if strings.Contains(s.Basic.Username, ":") {
			return errors.New("basic: username may not contain ':'")
		}
	}
	if s.Query != nil {
		n++
		if s.Query.Param == "" {
			return errors.New("query param is required")
		}
	}
	if n != 1 {
		return errors.New("exactly one of header, basic, query is required")
	}
	return nil
}

// checkPlaceholder enforces that a placeholder is distinctive enough that a
// substring match can't fire by accident, and safe to put in a header.
func checkPlaceholder(p string) error {
	if len(p) < 16 {
		return errors.New("placeholder must be at least 16 characters")
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("placeholder contains %q; only [A-Za-z0-9_.-] are allowed", r)
		}
	}
	return nil
}

// checkPathPattern rejects path patterns that could be normalised by the
// upstream into something we did not intend to allow.
func checkPathPattern(p string) error {
	if !strings.HasPrefix(p, "/") {
		return errors.New("must start with /")
	}
	if strings.Contains(p, "?") || strings.Contains(p, "#") {
		return errors.New("must not contain a query or fragment")
	}
	if strings.ContainsAny(p, "%\\;") {
		return errors.New("must not contain %, \\ or ;")
	}
	// Requests with empty or dot-only segments are refused (see
	// policy.safePath), so a pattern containing one could never match.
	trimmed := strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/")
	if trimmed == "" {
		return nil
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" {
			return errors.New("must not contain empty segments (//)")
		}
		if strings.Trim(seg, ".") == "" {
			return errors.New("must not contain . or .. segments")
		}
	}
	return nil
}

// CanonicalHostPattern lower-cases a host pattern, strips a trailing dot and
// checks its shape. Patterns are an exact DNS name or "*.example.com",
// where the wildcard matches exactly one label. IP literals are rejected:
// a secret should only ever be bound to a name.
func CanonicalHostPattern(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", errors.New("empty host")
	}
	if strings.ContainsAny(h, ":/ ") {
		return "", errors.New("host must be a bare name without port or path")
	}
	if h == "*" || strings.HasSuffix(h, ".*") {
		return "", errors.New("bare wildcard is not allowed")
	}
	rest := h
	if strings.HasPrefix(h, "*.") {
		rest = h[2:]
		if !strings.Contains(rest, ".") {
			return "", errors.New("wildcard must cover at least two labels (e.g. *.example.com)")
		}
	}
	if strings.Contains(rest, "*") {
		return "", errors.New("wildcard is only allowed as the leading label")
	}
	for _, label := range strings.Split(rest, ".") {
		if label == "" {
			return "", errors.New("empty label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("invalid character %q", r)
			}
		}
	}
	if isAllDigitsAndDots(rest) {
		return "", errors.New("IP literals are not allowed as hosts")
	}
	return h, nil
}

// PatternMatches compares a canonical pattern against a canonical host.
// "*.example.com" matches "a.example.com" but not "example.com" or
// "a.b.example.com". A pattern also matches itself, so two identical
// patterns compare as overlapping.
func PatternMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		if pattern == host {
			return true
		}
		suffix := pattern[1:] // ".example.com"
		if !strings.HasSuffix(host, suffix) {
			return false
		}
		label := strings.TrimSuffix(host, suffix)
		return label != "" && !strings.Contains(label, ".")
	}
	return pattern == host
}

func isAllDigitsAndDots(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r == '.') {
			return false
		}
	}
	return true
}

// SecretValues resolves every secret's real value. It fails if any is
// missing or empty: a proxy that starts without a secret it was told about
// would silently forward placeholders upstream.
func (c *Config) SecretValues() (map[string]string, error) {
	out := make(map[string]string, len(c.Secrets))
	var errs []error
	for name, s := range c.Secrets {
		var v string
		switch {
		case s.FromEnv != "":
			v = os.Getenv(s.FromEnv)
			if v == "" {
				errs = append(errs, fmt.Errorf("secret %q: env var %s is empty or unset", name, s.FromEnv))
				continue
			}
		case s.FromFile != "":
			b, err := os.ReadFile(s.FromFile)
			if err != nil {
				errs = append(errs, fmt.Errorf("secret %q: %w", name, err))
				continue
			}
			v = strings.TrimRight(string(b), "\r\n")
			if v == "" {
				errs = append(errs, fmt.Errorf("secret %q: file %s is empty", name, s.FromFile))
				continue
			}
		}
		out[name] = v
	}
	return out, errors.Join(errs...)
}
