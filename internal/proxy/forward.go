package proxy

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/policy"
)

// handleInspectedRequest is the heart of the proxy: one decrypted request
// in, one policy decision, one upstream request out, one scrubbed response
// back. The order of operations matters and is spelled out here so the
// implementation cannot drift:
//
//  1. Build the audit event now, from the request as the client sent it.
//     Nothing after this point may add header values or the query string.
//  2. Refuse TRACE/TRACK (they echo request headers back).
//  3. Refuse if req.Host or an absolute URL disagrees with the connection's
//     host (policy.HostAgrees). This is the "inject for A, deliver to B"
//     check.
//  4. policy.Apply. On Rejection: write Status + Message as text/plain and
//     audit decision "deny" with Reason. Do not contact upstream.
//  5. Build the upstream request: scheme https, host = connection host,
//     same method/path/query/body; drop hop-by-hop and Proxy-* headers;
//     drop Range and If-Range if a secret was injected (and later refuse
//     a partial response to such a request);
//     drop Accept-Encoding so the response is plaintext and scrubbable;
//     set Host explicitly. Preserve Upgrade/Connection: upgrade for
//     WebSocket handshakes (see below).
//  6. s.upstream.RoundTrip. Errors => 502 with a generic message (never the
//     Go error text, which can contain URLs) and audit "error".
//  7. Copy the response: status, headers minus hop-by-hop, then body
//     through a scrubbing writer built from s.Policy.Replacements(host),
//     flushing after every write so streamed responses (SSE) arrive as they
//     are produced. Response headers are scrubbed too (Location, WWW-Authenticate).
//  8. Audit decision "inject" if Result.Applied is non-empty, else
//     "forward", with status, bytes and elapsed time.
//
// The step order and the TRACE/Host checks follow Infisical CLI
// packages/agentproxy (MIT); the WebSocket handling follows Infisical Agent
// Vault internal/mitm/websocket.go (MIT). Both Copyright Infisical Inc.;
// see NOTICE.
//
// WebSocket: if the request has Upgrade: websocket, the handshake goes
// through steps 1-6 like any request (so a placeholder in the handshake's
// Authorization header is substituted), then on a 101 response the two
// connections are spliced raw for the life of the socket. Frames are not
// inspected or scrubbed. Use httputil-free hijack on both sides; Agent
// Vault internal/mitm/websocket.go is the reference for the handshake
// header handling.
func (s *Server) handleInspectedRequest(w http.ResponseWriter, r *http.Request, host, port, listener string) {
	start := time.Now()
	ev := audit.Event{Host: host, Method: r.Method, Path: s.safeClientText(host, r.URL.Path), Listener: listener}

	if r.Method == "TRACE" || r.Method == "TRACK" {
		ev.Decision, ev.Reason = "deny", "method_reflects"
		s.log(ev)
		http.Error(w, "secproxy: "+r.Method+" is not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !policy.HostAgrees(r, host) {
		ev.Decision, ev.Reason = "deny", "host_mismatch"
		s.log(ev)
		http.Error(w, "secproxy: request Host does not match the connection's destination "+host, http.StatusBadRequest)
		return
	}

	res, rej := s.Policy.Apply(r, host)
	if rej != nil {
		ev.Decision, ev.Reason = "deny", rej.Reason
		s.log(ev)
		http.Error(w, s.safeClientText(host, rej.Message), rej.Status)
		return
	}
	ev.Bindings = res.Applied
	ev.Automatic = res.Automatic
	if len(res.Applied) > 0 {
		ev.Decision = "inject"
	} else {
		ev.Decision = "forward"
	}

	upgrade := isWebSocketUpgrade(r)
	out := upstreamRequest(r, host, upgrade)
	injected := len(res.Applied) > 0
	if injected {
		// The scrubber only sees a secret that arrives whole in one
		// response. Two Range requests could fetch an echoed secret in
		// halves, so a request that carries one gets the full body.
		// Requests without a secret keep Range: they have nothing to echo.
		out.Header.Del("Range")
		out.Header.Del("If-Range")
	}
	if upgrade {
		s.forwardWebSocket(w, out, host, port, start, &ev)
		return
	}

	resp, err := s.upstream.RoundTrip(out)
	if err != nil {
		ev.Decision, ev.Reason = "error", "upstream"
		ev.Status = http.StatusBadGateway
		s.log(ev)
		http.Error(w, "secproxy: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if injected && (resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != "") {
		ev.Decision, ev.Reason = "error", "partial_content"
		ev.Status = http.StatusBadGateway
		s.log(ev)
		http.Error(w, "secproxy: upstream sent a partial response to a request carrying a secret; partial responses cannot be scrubbed", http.StatusBadGateway)
		return
	}
	s.copyInspectedResponse(w, resp, host, start, &ev)
}

func upstreamRequest(r *http.Request, host string, upgrade bool) *http.Request {
	out := r.Clone(r.Context())
	out.URL = &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	out.RequestURI = ""
	out.Host = host
	out.Header = outboundHeaders(r.Header)
	if upgrade {
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", r.Header.Get("Upgrade"))
		// No permessage-deflate: server frames are scrubbed as a byte
		// stream, which only works if they are not compressed.
		out.Header.Del("Sec-WebSocket-Extensions")
	}
	return out
}

func (s *Server) copyInspectedResponse(w http.ResponseWriter, resp *http.Response, host string, start time.Time, ev *audit.Event) {
	replacements := s.Policy.Replacements(host)

	// We asked for an unencoded body (Accept-Encoding is dropped), but a
	// server may compress anyway, and the scrubber cannot see through
	// compression. Gzip is undone here; anything else is refused rather
	// than forwarded unscrubbed.
	body := io.Reader(resp.Body)
	enc, ok := contentEncoding(resp.Header)
	if enc != "" || !ok {
		// HEAD, 204, 304 and similar carry the encoding header with no body
		// to decode. Look for a first byte before deciding.
		peek := bufio.NewReader(resp.Body)
		if _, err := peek.Peek(1); err == io.EOF {
			enc, ok = "", true
		}
		body = peek
	}
	if !ok {
		// The upstream's value is not echoed: it is upstream-controlled
		// text that has not been through the scrubber.
		ev.Decision, ev.Reason = "error", "content_encoding"
		ev.Status = http.StatusBadGateway
		s.log(*ev)
		http.Error(w, "secproxy: upstream sent a Content-Encoding that cannot be scrubbed; only identity and a single gzip are accepted", http.StatusBadGateway)
		return
	}
	if enc == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			ev.Decision, ev.Reason = "error", "bad_gzip"
			ev.Status = http.StatusBadGateway
			s.log(*ev)
			http.Error(w, "secproxy: upstream sent an unreadable gzip body", http.StatusBadGateway)
			return
		}
		defer gz.Close()
		body = gz
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}

	copyResponseHeaders(w.Header(), resp.Header, replacements)
	// A replacement can change the body's byte length, so Go must choose
	// fresh framing rather than forwarding an upstream Content-Length.
	if len(replacements) > 0 {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)

	cw := &flushingCountWriter{w: w}
	scrubber := newScrubWriter(cw, replacements)
	_, _ = io.CopyBuffer(scrubber, body, make([]byte, 32<<10))
	_ = scrubber.Close()
	ev.Status = resp.StatusCode
	ev.BytesOut = cw.n
	ev.Millis = time.Since(start).Milliseconds()
	s.log(*ev)
}

// contentEncoding reads every Content-Encoding line, not just the first: a
// server can send several, and each may list several codings. It returns
// "" for an unencoded body, "gzip" for exactly one gzip layer, and ok=false
// for anything else, including gzip twice, which would hand the client an
// inner layer the scrubber never saw.
func contentEncoding(h http.Header) (enc string, ok bool) {
	var codings []string
	for _, line := range h.Values("Content-Encoding") {
		for _, token := range strings.Split(line, ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if token != "" && token != "identity" {
				codings = append(codings, token)
			}
		}
	}
	switch {
	case len(codings) == 0:
		return "", true
	case len(codings) == 1 && (codings[0] == "gzip" || codings[0] == "x-gzip"):
		return "gzip", true
	}
	return "", false
}

func copyResponseHeaders(dst, src http.Header, replacements [][2]string) {
	clean := src.Clone()
	scrubHeaders(clean, replacements)
	removeConnectionHeaders(clean)
	for name, values := range clean {
		if isHopByHop(name) || strings.HasPrefix(strings.ToLower(name), "proxy-") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func removeConnectionHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(token))
		}
	}
}

// safeClientText keeps values held by the proxy out of both audit paths and
// denial text, even when a client deliberately places one in its URL.
func (s *Server) safeClientText(host, text string) string {
	for _, replacement := range s.Policy.Replacements(host) {
		text = strings.ReplaceAll(text, replacement[0], "[redacted]")
		text = strings.ReplaceAll(text, replacement[1], "[redacted]")
	}
	for _, placeholder := range s.Policy.Placeholders() {
		text = strings.ReplaceAll(text, placeholder, "[redacted]")
	}
	return text
}

type flushingCountWriter struct {
	w http.ResponseWriter
	n int64
}

func (w *flushingCountWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func (w *flushingCountWriter) Flush() {
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func (s *Server) forwardWebSocket(w http.ResponseWriter, out *http.Request, host, port string, start time.Time, ev *audit.Event) {
	upstream, reader, resp, err := s.dialWebSocketUpstream(out.Context(), out, host, port)
	if err != nil {
		ev.Decision, ev.Reason = "error", "upstream"
		ev.Status = http.StatusBadGateway
		s.log(*ev)
		http.Error(w, "secproxy: upstream request failed", http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer upstream.Close()
		defer resp.Body.Close()
		s.copyInspectedResponse(w, resp, host, start, ev)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		ev.Decision, ev.Reason = "error", "hijack"
		ev.Status = http.StatusInternalServerError
		s.log(*ev)
		http.Error(w, "secproxy: websocket unavailable", http.StatusInternalServerError)
		return
	}
	client, clientBuf, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		ev.Decision, ev.Reason = "error", "hijack"
		ev.Status = http.StatusInternalServerError
		s.log(*ev)
		return
	}

	if err := writeSwitchingResponse(clientBuf.Writer, resp, s.Policy.Replacements(host)); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		ev.Decision, ev.Reason = "error", "upstream"
		ev.Status = http.StatusBadGateway
		s.log(*ev)
		return
	}
	if err := clientBuf.Flush(); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		ev.Decision, ev.Reason = "error", "upstream"
		ev.Status = http.StatusBadGateway
		s.log(*ev)
		return
	}

	clientReader := &replayConn{Conn: client, reader: clientBuf.Reader}
	upstreamReader := &replayConn{Conn: upstream, reader: reader}
	bytesIn, bytesOut := s.spliceWebSocket(clientReader, upstreamReader, sameLengthReplacements(s.Policy.Replacements(host)))
	ev.Status = http.StatusSwitchingProtocols
	ev.BytesIn = bytesIn
	ev.BytesOut = bytesOut
	ev.Millis = time.Since(start).Milliseconds()
	s.log(*ev)
}

func (s *Server) dialWebSocketUpstream(ctx context.Context, req *http.Request, host, port string) (net.Conn, *bufio.Reader, *http.Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, upstreamTLSTimeout)
	raw, err := s.dial(dialCtx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		return nil, nil, nil, err
	}

	tlsConfig := s.upstream.TLSClientConfig.Clone()
	tlsConfig.ServerName = host
	tlsConfig.NextProtos = []string{"http/1.1"}
	conn := tls.Client(raw, tlsConfig)
	_ = conn.SetDeadline(time.Now().Add(upstreamTLSTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(responseHeaderWait))
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reader, resp, nil
}

func writeSwitchingResponse(w *bufio.Writer, resp *http.Response, replacements [][2]string) error {
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	headers := resp.Header.Clone()
	scrubHeaders(headers, replacements)
	removeConnectionHeaders(headers)
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "proxy-") {
			headers.Del(name)
		}
	}
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	if err := headers.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// spliceWebSocket copies frames both ways after the 101. Client frames go
// through untouched. Server frames are relayed one at a time by
// relayServerFrames (wsframe.go), which scrubs each payload with the
// length-preserving replacements. The scrubber here is a safety net for
// careless upstreams, not a defence against a hostile one; see the README.
func (s *Server) spliceWebSocket(client, upstream net.Conn, replacements [][2]string) (bytesIn, bytesOut int64) {
	untrackClient := s.track(client)
	defer untrackClient()
	untrackUpstream := s.track(upstream)
	defer untrackUpstream()
	clientIdle := &activityConn{Conn: client, idle: tunnelIdle}
	upstreamIdle := &activityConn{Conn: upstream, idle: tunnelIdle}
	type result struct {
		in bool
		n  int64
	}
	done := make(chan result, 2)
	go func() {
		n, _ := io.CopyBuffer(upstreamIdle, clientIdle, make([]byte, 32<<10))
		done <- result{in: true, n: n}
	}()
	go func() {
		n, _ := relayServerFrames(clientIdle, upstreamIdle, replacements)
		done <- result{in: false, n: n}
	}()
	first := <-done
	_ = client.Close()
	_ = upstream.Close()
	second := <-done
	for _, result := range []result{first, second} {
		if result.in {
			bytesIn = result.n
		} else {
			bytesOut = result.n
		}
	}
	return bytesIn, bytesOut
}

// sameLengthReplacements reshapes each replacement so it has exactly the
// byte length of the value it replaces: the placeholder truncated, or padded
// with '*'. Inside a WebSocket stream we cannot re-frame, so the bytes must
// stay put; the sandbox still gets something recognisably not the secret.
func sameLengthReplacements(in [][2]string) [][2]string {
	out := make([][2]string, 0, len(in))
	for _, r := range orderedReplacements(in) {
		real, fake := r[0], r[1]
		switch {
		case len(fake) > len(real):
			fake = fake[:len(real)]
		case len(fake) < len(real):
			fake += strings.Repeat("*", len(real)-len(fake))
		}
		out = append(out, [2]string{real, fake})
	}
	return out
}

// outboundHeaders copies request headers for upstream, dropping the ones
// that must not cross a proxy and the ones we manage ourselves.
func outboundHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	connectionHeaders := map[string]bool{}
	for _, value := range in.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			connectionHeaders[http.CanonicalHeaderKey(strings.TrimSpace(token))] = true
		}
	}
	for k, vs := range in {
		if isHopByHop(k) || connectionHeaders[http.CanonicalHeaderKey(k)] || strings.HasPrefix(strings.ToLower(k), "proxy-") {
			continue
		}
		switch http.CanonicalHeaderKey(k) {
		case "Accept-Encoding": // plaintext responses so scrubbing can see them
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}
