// Package childenv builds the environment a sandboxed program needs in order
// to (a) hold placeholders instead of secrets, (b) send its HTTPS traffic to
// the proxy when it is proxy-aware, and (c) trust the proxy's certificate.
//
// Setting these variables is a courtesy to well-behaved programs, not a
// security boundary. The boundary is the network: the sandbox must have no
// route to the internet except through the proxy. How that is enforced is
// the orchestrator's job (a firewall, a network namespace, a cloud sandbox
// egress rule, a transparent relay) and is deliberately outside this tool.
package childenv

import (
	"sort"

	"github.com/taylorai/secproxy/internal/config"
)

// Options controls what is emitted.
type Options struct {
	// ProxyURL is the address of the connect listener, e.g.
	// "http://secproxy:8080" or "http://127.0.0.1:8080". Empty when the
	// sandbox is behind a transparent relay and needs no proxy variables.
	ProxyURL string

	// CAPath is where the sandbox will find the CA certificate.
	CAPath string
}

// Vars returns the variables to set. Placeholders are emitted under each
// secret's configured Env name; secrets without one are skipped.
func Vars(cfg *config.Config, opts Options) map[string]string {
	env := map[string]string{}

	for _, s := range cfg.Secrets {
		if s.Env != "" && s.Placeholder != "" {
			env[s.Env] = s.Placeholder
		}
	}

	if opts.ProxyURL != "" {
		// Both cases: curl only reads the lower-case forms, most other
		// tools read upper case. NO_PROXY is emptied so a stale value
		// cannot carve out a bypass.
		for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
			env[k] = opts.ProxyURL
		}
		env["NO_PROXY"] = ""
		env["no_proxy"] = ""
		env["NODE_USE_ENV_PROXY"] = "1" // Node's fetch ignores HTTPS_PROXY unless told
	}

	if opts.CAPath != "" {
		for _, k := range CAVars {
			env[k] = opts.CAPath
		}
	}
	return env
}

// CAVars are the variables. The list matches the one Infisical CLI sets for
// its child processes (packages/cmd/agent_proxy.go, MIT); see NOTICE.
//
// These are the variables that point each common TLS stack at an extra
// trusted certificate. Programs that read none of these (some Java, some
// static binaries with baked-in roots) need the certificate installed in
// the system store as well; that is the orchestrator's job.
var CAVars = []string{
	"SSL_CERT_FILE",       // OpenSSL, Go, Python ssl, Rust rustls-native-certs, uv
	"REQUESTS_CA_BUNDLE",  // Python requests
	"CURL_CA_BUNDLE",      // curl
	"GIT_SSL_CAINFO",      // git
	"NODE_EXTRA_CA_CERTS", // Node, and Claude Code
	"DENO_CERT",           // Deno
}

// SortedKeys is a small helper for deterministic output.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
