// Package policy decides what happens to a connection and to a request.
//
// Two questions, answered in order:
//
//  1. Decide(host): given only a destination hostname (from SNI or a
//     CONNECT line), is it denied, passed through untouched, or inspected?
//  2. Apply(req, host): for an inspected request, exchange placeholders for
//     real secrets where a binding allows it, and reject the request if a
//     placeholder appears anywhere it is not allowed.
//
// Everything here is pure: no network, no I/O, so it is easy to test.
//
// The model (substitute only in one declared slot, per-binding methods and
// paths, egress hosts separate from binding hosts) follows
// inflightsec/agent-vault-proxy (Apache-2.0) and stashbase/agent-proxy
// (MIT). Ideas, not code; see NOTICE.
package policy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/taylorai/secproxy/internal/config"
)

// Action is the per-host decision.
type Action int

const (
	Deny        Action = iota // refuse the connection
	Passthrough               // splice raw bytes to the destination; no decryption
	Inspect                   // terminate TLS and run Apply on each request
)

func (a Action) String() string {
	switch a {
	case Deny:
		return "deny"
	case Passthrough:
		return "passthrough"
	case Inspect:
		return "inspect"
	}
	return "unknown"
}

// secret is a resolved secret: name, real value, placeholder.
type secret struct {
	name        string
	value       string
	placeholder string
}

// binding is a compiled config.Binding.
type binding struct {
	secret  *secret
	hosts   []string // canonical patterns
	slot    config.Slot
	methods map[string]bool // nil = any
	paths   []string        // nil = any
	always  bool            // inject: always
	label   string          // for logs and error messages
}

// Policy is the compiled, immutable form of a config plus its secret values.
type Policy struct {
	unmatched Action
	egress    []string // canonical patterns
	bindings  []*binding
	secrets   []*secret
}

// Compile validates that every secret has a value and turns the config into
// a Policy.
func Compile(cfg *config.Config, values map[string]string) (*Policy, error) {
	p := &Policy{unmatched: Deny}
	if cfg.UnmatchedHost == "passthrough" {
		p.unmatched = Passthrough
	}
	for _, h := range cfg.Egress {
		c, err := config.CanonicalHostPattern(h)
		if err != nil {
			return nil, err
		}
		p.egress = append(p.egress, c)
	}
	secrets := map[string]*secret{}
	for name, s := range cfg.Secrets {
		v, ok := values[name]
		if !ok || v == "" {
			return nil, fmt.Errorf("secret %q has no value", name)
		}
		if s.Placeholder == "" {
			return nil, fmt.Errorf("secret %q has no placeholder", name)
		}
		sec := &secret{name: name, value: v, placeholder: s.Placeholder}
		secrets[name] = sec
		p.secrets = append(p.secrets, sec)
	}
	sort.Slice(p.secrets, func(i, j int) bool { return p.secrets[i].name < p.secrets[j].name })

	for i, b := range cfg.Bindings {
		cb := &binding{secret: secrets[b.Secret], slot: b.Slot, label: fmt.Sprintf("%s#%d", b.Secret, i)}
		for _, h := range b.Hosts {
			c, err := config.CanonicalHostPattern(h)
			if err != nil {
				return nil, err
			}
			cb.hosts = append(cb.hosts, c)
		}
		if len(b.Methods) > 0 {
			cb.methods = map[string]bool{}
			for _, m := range b.Methods {
				cb.methods[m] = true
			}
		}
		cb.paths = b.Paths
		cb.always = b.Inject == config.InjectAlways
		p.bindings = append(p.bindings, cb)
	}
	return p, nil
}

// Decide answers question 1. host must already be canonical (see
// CanonicalHost). The port is not part of the decision; both listeners only
// ever carry port-443-style TLS traffic.
func (p *Policy) Decide(host string) Action {
	for _, b := range p.bindings {
		for _, pat := range b.hosts {
			if hostMatches(pat, host) {
				return Inspect
			}
		}
	}
	for _, pat := range p.egress {
		if hostMatches(pat, host) {
			return Passthrough
		}
	}
	return p.unmatched
}

// Rejection is returned by Apply when the request must not be forwarded.
// Message is meant to be shown to the sandboxed program: coding agents read
// error bodies, and a precise message turns a policy violation into
// something they can fix.
type Rejection struct {
	Status  int
	Reason  string // short machine-readable code for the audit log
	Message string
}

func (r *Rejection) Error() string { return r.Message }

// Result describes what Apply did to a request that may be forwarded.
type Result struct {
	// Bindings that substituted a secret, by label. Empty means the request
	// carried no placeholder and goes upstream unauthenticated.
	Applied []string

	// The subset of Applied that fired without a placeholder, because the
	// binding has inject: always and the slot was empty. Kept separate so
	// the audit log can tell "the program asked" from "the proxy added it".
	Automatic []string
}

// Apply answers question 2. It mutates req in place. host is the canonical
// destination the connection was opened to; req.Host must agree with it
// (the caller checks that before calling Apply).
//
// The algorithm:
//
//   - For each binding whose hosts match, look at its slot. If the slot
//     holds exactly the placeholder (formatted), check method and path.
//     Allowed: substitute. Not allowed: reject with a message naming the
//     rule, and do not forward.
//   - A binding with inject: always also fires when its slot is empty, and
//     refuses the request when the slot holds anything else, so a different
//     credential is never replaced behind the program's back.
//   - After all substitutions, scan every header value, the path and the
//     raw query for any known placeholder. Any hit means the sandbox put a
//     placeholder somewhere it is not permitted: reject. This is what stops
//     "send my token to this other endpoint in a custom header".
//   - A request that uses a secret may not carry a method, path or host
//     override (X-HTTP-Method-Override, X-Original-URL, X-Forwarded-Host,
//     Forwarded, ?_method=, ...). Method and path rules check the request
//     line; an override would make the upstream act on something else.
//   - A request with no placeholder at all is forwarded as-is. Method and
//     path rules gate secret use, not access to the host. (With inject:
//     always every request uses the secret, so there they gate the host.)
func (p *Policy) Apply(req *http.Request, host string) (Result, *Rejection) {
	var res Result
	for _, b := range p.bindings {
		if !b.matchesHost(host) {
			continue
		}
		state, substitute := probeSlot(b.slot, req, b.secret)
		automatic := false
		switch {
		case state == slotPlaceholder:
			// the program asked for the secret
		case b.always && state == slotEmpty:
			automatic = true
		case b.always && state == slotOther:
			return res, &Rejection{
				Status: http.StatusForbidden, Reason: "slot_occupied",
				Message: fmt.Sprintf("secproxy: secret %q is added to %s on every request to %s, but this request already carries a different value there; remove it or send the placeholder",
					b.secret.name, describeSlot(b.slot), host),
			}
		default:
			continue
		}
		if b.methods != nil && !b.methods[req.Method] {
			return res, &Rejection{
				Status: http.StatusForbidden, Reason: "method_not_allowed",
				Message: fmt.Sprintf("secproxy: secret %q may not be used with %s on %s (allowed: %s)",
					b.secret.name, req.Method, host, strings.Join(sortedKeys(b.methods), ", ")),
			}
		}
		// Match the path as the upstream will receive it (percent-encoding
		// intact), not the decoded form. Otherwise "%2F" in a segment
		// satisfies a rule one way and reaches the server another.
		if b.paths != nil && !anyPathMatches(b.paths, req.URL.EscapedPath()) {
			return res, &Rejection{
				Status: http.StatusForbidden, Reason: "path_not_allowed",
				Message: fmt.Sprintf("secproxy: secret %q may not be used for path %s on %s (allowed: %s)",
					b.secret.name, req.URL.Path, host, strings.Join(b.paths, ", ")),
			}
		}
		substitute()
		res.Applied = append(res.Applied, b.label)
		if automatic {
			res.Automatic = append(res.Automatic, b.label)
		}
	}

	if len(res.Applied) > 0 {
		if what := routingOverride(req); what != "" {
			return res, &Rejection{
				Status: http.StatusForbidden, Reason: "routing_override",
				Message: fmt.Sprintf("secproxy: this request to %s carries a secret, so it may not include %s: some servers use it to act on a different method, path or host than the request line, which is what the secret's rules check; send the request without it",
					host, what),
			}
		}
	}

	if leak := p.findStrayPlaceholder(req); leak != nil {
		return res, &Rejection{
			Status: http.StatusForbidden, Reason: "placeholder_misplaced",
			Message: fmt.Sprintf("secproxy: the placeholder for secret %q was found in %s of a request to %s, but it is only valid in: %s",
				leak.name, leak.where, host, p.describeSlots(leak.name)),
		}
	}
	return res, nil
}

// Replacements returns (real value -> placeholder) pairs for scrubbing
// responses from host, so an upstream that echoes a credential hands the
// sandbox its own placeholder back. Includes the base64 Basic-auth form of
// any basic-slot binding, since that is how the value would round-trip.
func (p *Policy) Replacements(host string) [][2]string {
	var out [][2]string
	seen := map[string]bool{}
	for _, b := range p.bindings {
		if !b.matchesHost(host) {
			continue
		}
		s := b.secret
		if !seen[s.value] {
			out = append(out, [2]string{s.value, s.placeholder})
			seen[s.value] = true
		}
		if b.slot.Basic != nil {
			real := basicToken(b.slot.Basic, s.value)
			fake := basicToken(b.slot.Basic, s.placeholder)
			if !seen[real] {
				out = append(out, [2]string{real, fake})
				seen[real] = true
			}
		}
	}
	return out
}

// Placeholders returns secret name -> placeholder, for `secproxy env`.
func (p *Policy) Placeholders() map[string]string {
	m := make(map[string]string, len(p.secrets))
	for _, s := range p.secrets {
		m[s.name] = s.placeholder
	}
	return m
}

// Summary renders the compiled policy for `secproxy check`. Never values.
func (p *Policy) Summary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "unmatched hosts: %s\n", p.unmatched)
	for _, e := range p.egress {
		fmt.Fprintf(&sb, "passthrough      %s\n", e)
	}
	for _, b := range p.bindings {
		fmt.Fprintf(&sb, "inspect          %-40s %s in %s", strings.Join(b.hosts, ","), b.secret.name, describeSlot(b.slot))
		if b.methods != nil {
			fmt.Fprintf(&sb, "  methods=%s", strings.Join(sortedKeys(b.methods), ","))
		}
		if b.paths != nil {
			fmt.Fprintf(&sb, "  paths=%s", strings.Join(b.paths, ","))
		}
		if b.always {
			sb.WriteString("  inject=always")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// --- helpers -------------------------------------------------------------

func (b *binding) matchesHost(host string) bool {
	for _, pat := range b.hosts {
		if hostMatches(pat, host) {
			return true
		}
	}
	return false
}

// hostMatches compares a canonical pattern against a canonical host; the
// rule lives in config so validation and enforcement cannot drift apart.
func hostMatches(pattern, host string) bool { return config.PatternMatches(pattern, host) }

// overrideHeaders ask a server to use a method, path or host other than
// the request line's. Names are compared lower-case with "_" read as "-",
// because CGI-style servers (Rack, PHP) map both to the same variable.
var overrideHeaders = map[string]bool{
	"x-http-method-override": true,
	"x-http-method":          true,
	"x-method-override":      true,
	"x-original-method":      true,
	"x-original-url":         true,
	"x-rewrite-url":          true,
	"x-original-host":        true,
	"x-host":                 true,
	"forwarded":              true,
}

// routingOverride names an override the request carries, or "".
// Any X-Forwarded-* header counts: Host, Prefix, Path and Proto all steer
// routing somewhere, and a client has no business sending them.
func routingOverride(req *http.Request) string {
	for name := range req.Header {
		key := strings.ReplaceAll(strings.ToLower(name), "_", "-")
		if overrideHeaders[key] || strings.HasPrefix(key, "x-forwarded-") {
			return "the " + name + " header"
		}
	}
	for param := range req.URL.Query() {
		if strings.EqualFold(param, "_method") {
			return "the " + param + " query parameter"
		}
	}
	return ""
}

type stray struct {
	name  string
	where string
}

// findStrayPlaceholder scans the request for any placeholder that survived
// substitution. It runs after the slots have been rewritten, so anything
// left is a misuse.
func (p *Policy) findStrayPlaceholder(req *http.Request) *stray {
	for _, s := range p.secrets {
		if strings.Contains(req.URL.Path, s.placeholder) || strings.Contains(req.URL.RawPath, s.placeholder) {
			return &stray{s.name, "the URL path"}
		}
		if strings.Contains(req.URL.RawQuery, s.placeholder) {
			return &stray{s.name, "the query string"}
		}
		if u := req.URL.User; u != nil && strings.Contains(u.String(), s.placeholder) {
			return &stray{s.name, "the URL userinfo"}
		}
		for name, vals := range req.Header {
			for _, v := range vals {
				if strings.Contains(v, s.placeholder) {
					return &stray{s.name, "the " + name + " header"}
				}
				// Basic auth hides the credential in base64, so scanning only
				// the wire value would let a malformed basic slot escape the
				// misplaced-placeholder check.
				if strings.EqualFold(name, "Authorization") && strings.HasPrefix(v, "Basic ") {
					raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len("Basic "):]))
					if err == nil && strings.Contains(string(raw), s.placeholder) {
						return &stray{s.name, "the " + name + " header"}
					}
				}
			}
		}
	}
	return nil
}

func (p *Policy) describeSlots(secretName string) string {
	var parts []string
	for _, b := range p.bindings {
		if b.secret.name == secretName {
			parts = append(parts, fmt.Sprintf("%s for %s", describeSlot(b.slot), strings.Join(b.hosts, ",")))
		}
	}
	return strings.Join(parts, "; ")
}

func basicToken(b *config.BasicSlot, secretValue string) string {
	u := strings.ReplaceAll(b.Username, "{secret}", secretValue)
	pw := strings.ReplaceAll(b.Password, "{secret}", secretValue)
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + pw))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
