package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/policy"
)

// handleConnectRequest is the HTTP handler for the connect listener. Two
// request shapes are accepted:
//
//	CONNECT api.github.com:443 HTTP/1.1     -> hijack, "200 Connection Established", then handleTLSConn
//	GET http://pypi.org/simple/ HTTP/1.1    -> plain HTTP, allowed only for passthrough hosts
//
// Anything else is refused. In particular "GET https://..." in absolute
// form is refused rather than upgraded: a client that asks the proxy to
// speak TLS on its behalf would be trusting us with plaintext it never
// intended to expose.
func (s *Server) handleConnectRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	if r.URL.Scheme == "http" && r.URL.Host != "" {
		s.handlePlainHTTP(w, r)
		return
	}
	http.Error(w, "secproxy: this is an HTTP proxy; use CONNECT for https:// or absolute-form URLs for http://", http.StatusBadRequest)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPart, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		hostPart, port = r.Host, "443"
	}
	host, err := policy.CanonicalHost(hostPart)
	if err != nil {
		http.Error(w, "secproxy: bad CONNECT target", http.StatusBadRequest)
		return
	}
	if port != "443" {
		// Only TLS on 443 is brokered. Non-443 CONNECT is refused outright:
		// we cannot tell what protocol it is and would not be able to
		// inspect it.
		s.log(audit.Event{Decision: "deny", Host: host, Reason: "port_not_443", Listener: "connect"})
		http.Error(w, "secproxy: only port 443 may be tunnelled", http.StatusForbidden)
		return
	}
	if s.Policy.Decide(host) == policy.Deny {
		// Decide early so a denied host gets a readable 403 instead of a
		// tunnel that dies on first byte.
		s.log(audit.Event{Decision: "deny", Host: host, Reason: "unmatched_host", Listener: "connect"})
		http.Error(w, "secproxy: destination "+s.safeClientText(host, host)+" is not permitted by policy", http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "secproxy: hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	var tunnel net.Conn = conn
	if buf.Reader.Buffered() > 0 {
		tunnel = &replayConn{Conn: conn, reader: io.MultiReader(buf.Reader, conn)}
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = conn.Close()
		return
	}

	// The CONNECT line said where the tunnel goes; the TLS ClientHello
	// inside it says where the client thinks it is talking to. They must
	// agree. Otherwise a client could CONNECT to an allowed host that shares
	// an address with a denied one (any CDN) and put the denied name in
	// SNI, and the passthrough would carry it there untouched.
	sni, replay, err := peekClientHello(tunnel)
	if err != nil {
		s.log(audit.Event{Decision: "deny", Host: host, Reason: "no_sni", Listener: "connect"})
		_ = conn.Close()
		return
	}
	if canonical, err := policy.CanonicalHost(sni); err != nil || canonical != host {
		s.log(audit.Event{Decision: "deny", Host: host, Reason: "sni_mismatch", Listener: "connect"})
		_ = conn.Close()
		return
	}
	s.handleTLSConn(r.Context(), replay, host, port, "connect")
}

// handlePlainHTTP forwards an absolute-form http:// request for a
// passthrough host. No secrets are ever involved on plain HTTP; a binding
// host requested over http:// is refused so a credential can never travel
// in clear.
//
// The absolute URL is authoritative. Only Passthrough destinations are
// forwarded; inspected destinations must use TLS so credentials never cross
// the network in cleartext.
func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host, err := policy.CanonicalHost(r.URL.Host)
	if err != nil {
		http.Error(w, "secproxy: bad HTTP destination", http.StatusBadRequest)
		return
	}
	ev := audit.Event{Host: host, Method: r.Method, Path: s.safeClientText(host, r.URL.Path), Listener: "connect"}
	switch s.Policy.Decide(host) {
	case policy.Inspect:
		ev.Decision, ev.Reason = "deny", "plain_http_secret_host"
		s.log(ev)
		http.Error(w, "secproxy: this destination carries a secret; use https", http.StatusForbidden)
		return
	case policy.Deny:
		ev.Decision, ev.Reason = "deny", "unmatched_host"
		s.log(ev)
		http.Error(w, "secproxy: destination is not permitted by policy", http.StatusForbidden)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = outboundHeaders(r.Header)
	resp, err := s.upstream.RoundTrip(out)
	if err != nil {
		ev.Decision, ev.Reason = "error", "upstream"
		ev.Status = http.StatusBadGateway
		s.log(ev)
		http.Error(w, "secproxy: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header, nil)
	w.WriteHeader(resp.StatusCode)
	cw := &flushingCountWriter{w: w}
	_, _ = io.CopyBuffer(cw, resp.Body, make([]byte, 32<<10))
	ev.Decision = "passthrough"
	ev.Status = resp.StatusCode
	ev.BytesOut = cw.n
	ev.Millis = time.Since(start).Milliseconds()
	s.log(ev)
}

// isHopByHop lists headers that belong to one connection, not the request,
// and must not be forwarded. Upgrade is handled specially in forward.go.
func isHopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
