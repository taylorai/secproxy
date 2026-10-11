package policy

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// CanonicalHost turns whatever a client called the destination (SNI, a
// CONNECT authority, a Host header) into the single form used for matching,
// dialing, certificate names, and the audit log: lower case, no port, no
// trailing dot, no brackets. Every place that looks at a hostname must go
// through here so the proxy cannot be split-brained about where a request is
// going.
func CanonicalHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", errors.New("empty host")
	}
	if strings.ContainsAny(h, "/?#@\\ ") {
		return "", errors.New("host contains characters that are not part of a hostname")
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return "", errors.New("empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		// IP literals never match any policy (config rejects them), so the
		// only possible outcome is deny or passthrough of an unmatched host.
		// Return the normalised text form.
		return ip.String(), nil
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return "", errors.New("empty label in host")
		}
	}
	// Anything that is not an IP must look like a DNS name. This keeps out
	// "%" (an IPv6 zone such as "::1%lo" is not something net.ParseIP
	// accepts, but netguard's parser is), "*", ":" and other bytes that
	// some later parser might read differently.
	for _, c := range h {
		if !isHostChar(c) {
			return "", errors.New("host contains characters that are not part of a hostname")
		}
	}
	return h, nil
}

// isHostChar allows letters, digits, "-" and ".", plus "_", which is not
// legal in hostnames but turns up in real ones.
func isHostChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
}

// HostAgrees reports whether a request's own idea of its destination
// (req.Host, or the authority in an absolute-form URL) matches the host the
// connection was opened to. A mismatch means a client is trying to make the
// proxy inject a credential for host A into a request it will deliver to
// host B's virtual host, and must be refused.
func HostAgrees(req *http.Request, connHost string) bool {
	for _, candidate := range []string{req.Host, req.URL.Host} {
		if candidate == "" {
			continue
		}
		c, err := CanonicalHost(candidate)
		if err != nil || c != connHost {
			return false
		}
	}
	return true
}

// anyPathMatches reports whether the request path matches one of the
// patterns. Patterns use "*" for exactly one path segment and "**" for any
// number of segments (including zero). Matching is on the raw path split by
// "/", after rejecting anything that could normalise differently upstream.
func anyPathMatches(patterns []string, path string) bool {
	if !safePath(path) {
		return false
	}
	for _, p := range patterns {
		if globMatch(strings.Split(strings.Trim(p, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/")) {
			return true
		}
	}
	return false
}

// safePath refuses paths that one server could read differently from
// another. Ordinary API paths ("/repos/acme/tool/issues", "/v1/messages")
// pass; these do not:
//
//   - percent-encoding and backslashes, which decode or normalise to
//     different segments ("%2F", "%2e%2e", "\\");
//   - ";", because Java servers drop ";params" from a segment before
//     resolving dots, so "/ok/..;/admin" matches "/ok/**" here and means
//     "/admin" there;
//   - empty segments ("/ok//read"), which nginx and others merge away;
//   - segments made only of dots (".", "..", "...").
//
// One leading and one trailing "/" are allowed; they do not make segments.
func safePath(path string) bool {
	if strings.ContainsAny(path, "%\\;") {
		return false
	}
	trimmed := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/")
	if trimmed == "" {
		return true
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if strings.Trim(seg, ".") == "" {
			return false
		}
	}
	return true
}

func globMatch(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	switch pattern[0] {
	case "**":
		for i := 0; i <= len(segs); i++ {
			if globMatch(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	case "*":
		return len(segs) > 0 && globMatch(pattern[1:], segs[1:])
	default:
		return len(segs) > 0 && segs[0] == pattern[0] && globMatch(pattern[1:], segs[1:])
	}
}
