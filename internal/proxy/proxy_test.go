package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/ca"
	"github.com/taylorai/secproxy/internal/config"
	"github.com/taylorai/secproxy/internal/netguard"
	"github.com/taylorai/secproxy/internal/policy"
)

const (
	testReal        = "REAL_VALUE_DO_NOT_LEAK"
	testPlaceholder = "sp_tok_testplaceholder0000"
)

func TestConnectInspectPolicyScrubbingAndStreaming(t *testing.T) {
	h := newProxyHarness(t)
	client := h.inspectedClient()

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.test/ok/x", nil)
	req.Header.Set("Authorization", "Bearer "+testPlaceholder)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Bearer "+testPlaceholder) || strings.Contains(body, testReal) {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}

	tests := []struct {
		name, method, path, header, want string
		status                           int
	}{
		{name: "method", method: http.MethodDelete, path: "/ok/x", header: "Authorization", status: 403, want: "DELETE"},
		{name: "path", method: http.MethodGet, path: "/nope", header: "Authorization", status: 403, want: "/nope"},
		{name: "other header", method: http.MethodGet, path: "/ok/x", header: "X-Other", status: 403, want: "X-Other"},
		{name: "trace", method: http.MethodTrace, path: "/ok/x", status: 405, want: "TRACE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, "https://api.example.test"+test.path, nil)
			if test.header != "" {
				req.Header.Set(test.header, "Bearer "+testPlaceholder)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body := readBody(t, resp)
			if resp.StatusCode != test.status || !strings.Contains(body, test.want) {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
		})
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.example.test/ok/x", nil)
	req.Host = "other.example.test"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); resp.StatusCode != 400 || !strings.Contains(body, "does not match") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.example.test/ok/sse", nil)
	req.Header.Set("Authorization", "Bearer "+testPlaceholder)
	started := time.Now()
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(resp.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	first := time.Since(started)
	_, _ = io.Copy(io.Discard, reader)
	_ = resp.Body.Close()
	last := time.Since(started)
	if first >= 90*time.Millisecond || last < 90*time.Millisecond {
		t.Fatalf("SSE was not incremental: first=%s last=%s", first, last)
	}

	h.assertAuditSafe(t)
}

func TestConnectDeniesUnmatchedBeforeTunnel(t *testing.T) {
	h := newProxyHarness(t)
	conn, err := net.Dial("tcp", h.connectAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT denied.example.test:443 HTTP/1.1\r\nHost: denied.example.test:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	h.assertAuditSafe(t)
}

func TestConnectWebSocketInjectionAndSplice(t *testing.T) {
	h := newProxyHarness(t)
	raw, err := net.Dial("tcp", h.connectAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, _ = io.WriteString(raw, "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n")
	reader := bufio.NewReader(raw)
	connectResp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", connectResp.StatusCode)
	}

	tlsConn := tls.Client(raw, &tls.Config{ServerName: "api.example.test", RootCAs: h.proxyRoots, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	// The example Sec-WebSocket-Key nonce from RFC 6455 section 1.3. Not a secret.
	const wsNonce = "dGhlIHNhbXBsZSBub25jZQ=="
	_, _ = io.WriteString(tlsConn, "GET /ok/ws HTTP/1.1\r\nHost: api.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+wsNonce+"\r\nAuthorization: Bearer "+testPlaceholder+"\r\n\r\n")
	wsReader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(wsReader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != websocketAccept(wsNonce) {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Header)
	}

	writeMaskedFrame(t, tlsConn, []byte("hello"))
	if got := readServerFrame(t, wsReader); string(got) != "hello" {
		t.Fatalf("echo=%q", got)
	}
	writeMaskedFrame(t, tlsConn, []byte("leak"))
	// Same-length scrubbing: the placeholder is cut to the secret's length so
	// the frame header stays truthful.
	if got := readServerFrame(t, wsReader); string(got) != "token=Bearer "+testPlaceholder[:len(testReal)] {
		t.Fatalf("server frame was not scrubbed: %q", got)
	}
	writeMaskedFrame(t, tlsConn, []byte("after"))
	if got := readServerFrame(t, wsReader); string(got) != "after" {
		t.Fatalf("framing lost after scrub: %q", got)
	}
	_ = tlsConn.Close()
}

func TestConnectRefusesSNIThatDisagreesWithTunnel(t *testing.T) {
	h := newProxyHarness(t)
	raw, err := net.Dial("tcp", h.connectAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, _ = io.WriteString(raw, "CONNECT plain.example.test:443 HTTP/1.1\r\nHost: plain.example.test:443\r\n\r\n")
	reader := bufio.NewReader(raw)
	connectResp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", connectResp.StatusCode)
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: "denied.example.test", InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("handshake with a foreign SNI through an allowed tunnel succeeded")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(h.audit.String(), "sni_mismatch") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(h.audit.String(), "sni_mismatch") {
		t.Fatalf("audit log lacks sni_mismatch: %s", h.audit.String())
	}
}

func TestInspectedResponseEncodings(t *testing.T) {
	h := newProxyHarness(t)
	client := h.inspectedClient()

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.test/ok/gz", nil)
	req.Header.Set("Authorization", "Bearer "+testPlaceholder)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" || strings.Contains(body, testReal) || !strings.Contains(body, testPlaceholder) {
		t.Fatalf("gzip response not decoded and scrubbed: status=%d enc=%q body=%q", resp.StatusCode, resp.Header.Get("Content-Encoding"), body)
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.example.test/ok/br", nil)
	req.Header.Set("Authorization", "Bearer "+testPlaceholder)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "Content-Encoding") {
		t.Fatalf("unscrubbable encoding was forwarded: status=%d body=%q", resp.StatusCode, body)
	}

	// Every Content-Encoding line counts, not only the first.
	for _, tt := range []struct {
		path     string
		wantCode int
	}{
		{"/ok/gz-mixed", http.StatusOK},
		{"/ok/gz-twice", http.StatusBadGateway},
		{"/ok/deflate-second", http.StatusBadGateway},
		// The refusal must not echo the upstream's header value, which
		// here is the injected credential.
		{"/ok/enc-echo", http.StatusBadGateway},
	} {
		req, _ := http.NewRequest(http.MethodGet, "https://api.example.test"+tt.path, nil)
		req.Header.Set("Authorization", "Bearer "+testPlaceholder)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := readBody(t, resp)
		if resp.StatusCode != tt.wantCode || strings.Contains(strings.ToLower(body), strings.ToLower(testReal)) {
			t.Errorf("%s: status=%d enc=%q body=%q, want %d with no credential", tt.path, resp.StatusCode, resp.Header.Values("Content-Encoding"), body, tt.wantCode)
		}
		if tt.wantCode == http.StatusOK && (!strings.Contains(body, testPlaceholder) || resp.Header.Get("Content-Encoding") != "") {
			t.Errorf("%s: gzip not decoded and scrubbed: enc=%q body=%q", tt.path, resp.Header.Values("Content-Encoding"), body)
		}
	}
	h.assertAuditSafe(t)
}

// Two Range requests could each fetch half of an echoed secret, and neither
// half is long enough for the scrubber to recognise.
func TestRangeIsDroppedWhenASecretIsInjected(t *testing.T) {
	h := newProxyHarness(t)
	client := h.inspectedClient()
	get := func(path, auth, rangeHeader string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "https://api.example.test"+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		req.Header.Set("Range", rangeHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp, readBody(t, resp)
	}

	resp, body := get("/ok/range", "Bearer "+testPlaceholder, "bytes=0-20")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, testPlaceholder) || strings.Contains(body, testReal[:10]) {
		t.Fatalf("ranged request with a secret: status=%d body=%q, want the full scrubbed body", resp.StatusCode, body)
	}

	resp, body = get("/ok/range", "Bearer unrelated", "bytes=0-4")
	if resp.StatusCode != http.StatusPartialContent || body != `{"aut` {
		t.Fatalf("ranged request without a secret: status=%d body=%q, want 206 with the first 5 bytes", resp.StatusCode, body)
	}

	resp, body = get("/ok/partial", "Bearer "+testPlaceholder, "")
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, testReal[:10]) {
		t.Fatalf("unrequested partial response: status=%d body=%q, want 502", resp.StatusCode, body)
	}
	if !strings.Contains(h.audit.String(), "partial_content") {
		t.Fatalf("audit log lacks partial_content: %s", h.audit.String())
	}
	h.assertAuditSafe(t)
}

func TestPlainHTTPPolicy(t *testing.T) {
	h := newProxyHarness(t)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: h.connectAddr})}}
	resp, err := client.Get("http://plain.example.test/ok/x")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"path":"/ok/x"`) {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	resp, err = client.Get("http://api.example.test/ok/x")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "use https") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestConnectAndTransparentPassthroughKeepUpstreamCertificate(t *testing.T) {
	h := newProxyHarness(t)
	for _, test := range []struct {
		name string
		dial func() (net.Conn, error)
	}{
		{name: "connect", dial: func() (net.Conn, error) {
			transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: h.connectAddr}), TLSClientConfig: &tls.Config{RootCAs: h.upstreamRoots}}
			client := &http.Client{Transport: transport}
			resp, err := client.Get("https://plain.example.test/ok/x")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].Issuer.CommonName != "secproxy ephemeral CA" {
				return nil, fmt.Errorf("unexpected upstream certificate")
			}
			return nil, nil
		}},
		{name: "transparent", dial: func() (net.Conn, error) {
			raw, err := net.Dial("tcp", h.transparentAddr)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, &tls.Config{ServerName: "plain.example.test", RootCAs: h.upstreamRoots})
			if err := conn.Handshake(); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := test.dial()
			if err != nil {
				t.Fatal(err)
			}
			if conn != nil {
				_ = conn.Close()
			}
		})
	}
}

func TestTransparentInspect(t *testing.T) {
	h := newProxyHarness(t)
	raw, err := net.Dial("tcp", h.transparentAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: "api.example.test", RootCAs: h.proxyRoots})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET /ok/x HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer "+testPlaceholder+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, testPlaceholder) || strings.Contains(body, testReal) {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	h.assertAuditSafe(t)
}

type proxyHarness struct {
	connectAddr, transparentAddr string
	proxyRoots, upstreamRoots    *x509.CertPool
	audit                        lockedBuffer
}

func newProxyHarness(t *testing.T) *proxyHarness {
	t.Helper()
	upstreamCA, err := ca.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok/ws" {
			if r.Header.Get("Authorization") != "Bearer "+testReal {
				http.Error(w, "missing injected credential", http.StatusForbidden)
				return
			}
			serveTestWebSocket(w, r)
			return
		}
		if r.URL.Path == "/ok/gz" {
			// ignores the missing Accept-Encoding and compresses anyway
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			fmt.Fprintf(gz, `{"echo":%q}`, r.Header.Get("Authorization"))
			_ = gz.Close()
			return
		}
		if r.URL.Path == "/ok/gz-mixed" {
			// one gzip layer, spelled oddly and next to identity lines
			w.Header().Add("Content-Encoding", "identity")
			w.Header().Add("Content-Encoding", " GZIP ")
			gz := gzip.NewWriter(w)
			fmt.Fprintf(gz, `{"echo":%q}`, r.Header.Get("Authorization"))
			_ = gz.Close()
			return
		}
		if r.URL.Path == "/ok/gz-twice" {
			// the double-compression middleware bug: two gzip layers
			w.Header().Add("Content-Encoding", "gzip")
			w.Header().Add("Content-Encoding", "gzip")
			var inner bytes.Buffer
			gz := gzip.NewWriter(&inner)
			fmt.Fprintf(gz, `{"echo":%q}`, r.Header.Get("Authorization"))
			_ = gz.Close()
			outer := gzip.NewWriter(w)
			_, _ = outer.Write(inner.Bytes())
			_ = outer.Close()
			return
		}
		if r.URL.Path == "/ok/deflate-second" {
			// only the first line looks harmless
			w.Header().Add("Content-Encoding", "identity")
			w.Header().Add("Content-Encoding", "deflate")
			fmt.Fprint(w, "pretend this is deflate")
			return
		}
		if r.URL.Path == "/ok/enc-echo" {
			w.Header().Set("Content-Encoding", "x-"+r.Header.Get("Authorization"))
			fmt.Fprint(w, "body")
			return
		}
		if r.URL.Path == "/ok/br" {
			w.Header().Set("Content-Encoding", "br")
			fmt.Fprint(w, "pretend this is brotli")
			return
		}
		if r.URL.Path == "/ok/range" {
			// an echo that honours Range, like any static or caching server
			body := fmt.Sprintf(`{"auth":%q}`, r.Header.Get("Authorization"))
			http.ServeContent(w, r, "", time.Time{}, strings.NewReader(body))
			return
		}
		if r.URL.Path == "/ok/partial" {
			// a partial response nobody asked for
			w.Header().Set("Content-Range", "bytes 0-9/100")
			w.WriteHeader(http.StatusPartialContent)
			fmt.Fprint(w, r.Header.Get("Authorization")[:10])
			return
		}
		if r.URL.Path == "/ok/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "data: %d\n\n", i)
				w.(http.Flusher).Flush()
				time.Sleep(50 * time.Millisecond)
			}
			return
		}
		fmt.Fprintf(w, `{"auth":%q,"path":%q}`, r.Header.Get("Authorization"), r.URL.Path)
	})
	apiUpstream := newNamedTLSServer(t, upstreamCA, "api.example.test", handler)
	plainUpstream := newNamedTLSServer(t, upstreamCA, "plain.example.test", handler)
	plainHTTPUpstream := httptest.NewServer(handler)

	cfg := &config.Config{
		UnmatchedHost: "deny",
		Egress:        []string{"plain.example.test"},
		Secrets: map[string]config.Secret{
			"tok": {Placeholder: testPlaceholder},
		},
		Bindings: []config.Binding{{
			Secret: "tok", Hosts: []string{"api.example.test"},
			Slot:    config.Slot{Header: &config.HeaderSlot{Name: "Authorization", Format: "Bearer {secret}"}},
			Methods: []string{http.MethodGet, http.MethodPost}, Paths: []string{"/ok/**"},
		}},
	}
	pol, err := policy.Compile(cfg, map[string]string{"tok": testReal})
	if err != nil {
		t.Fatal(err)
	}
	proxyCA, err := ca.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	h := &proxyHarness{proxyRoots: certPool(t, proxyCA.CertPEM()), upstreamRoots: certPool(t, upstreamCA.CertPEM())}
	srv := New(pol, proxyCA, audit.New(&h.audit, "test"), &netguard.Dialer{})
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		target := apiUpstream.Listener.Addr().String()
		if host == "plain.example.test" {
			if port == "80" {
				target = plainHTTPUpstream.Listener.Addr().String()
			} else {
				target = plainUpstream.Listener.Addr().String()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	srv.dial = dial
	srv.upstream.DialContext = dial
	srv.upstream.TLSClientConfig.RootCAs = h.upstreamRoots

	ctx, cancel := context.WithCancel(context.Background())
	connect := listenLocal(t)
	transparent := listenLocal(t)
	h.connectAddr = connect.Addr().String()
	h.transparentAddr = transparent.Addr().String()
	go func() { _ = srv.ServeConnect(ctx, connect) }()
	go func() { _ = srv.ServeTransparent(ctx, transparent) }()
	t.Cleanup(func() {
		cancel()
		srv.Shutdown()
		apiUpstream.Close()
		plainUpstream.Close()
		plainHTTPUpstream.Close()
	})
	return h
}

func newNamedTLSServer(t *testing.T, authority *ca.CA, host string, handler http.Handler) *httptest.Server {
	t.Helper()
	leaf, err := authority.Leaf(host)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	return server
}

func (h *proxyHarness) inspectedClient() *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: h.connectAddr}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: h.proxyRoots, NextProtos: []string{"http/1.1"}},
	}}
}

func (h *proxyHarness) assertAuditSafe(t *testing.T) {
	t.Helper()
	log := h.audit.String()
	if strings.Contains(log, testReal) || strings.Contains(log, testPlaceholder) {
		t.Fatalf("audit contains credential material: %s", log)
	}
}

func certPool(t *testing.T, pem []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("failed to parse CA")
	}
	return pool
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// websocketAccept is kept beside the integration harness so adding more raw
// WebSocket cases does not require a protocol dependency.
func websocketAccept(key string) string {
	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func serveTestWebSocket(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
	if err := rw.Flush(); err != nil {
		return
	}
	for {
		payload, err := readMaskedFrame(rw.Reader)
		if err != nil || len(payload) > 125 {
			return
		}
		if string(payload) == "leak" {
			// a careless server that echoes the credential it received
			payload = []byte("token=" + r.Header.Get("Authorization"))
		}
		if _, err := conn.Write(append([]byte{0x81, byte(len(payload))}, payload...)); err != nil {
			return
		}
	}
}

// lockedBuffer lets tests read the audit log while the proxy is still
// writing to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func writeMaskedFrame(t *testing.T, w io.Writer, payload []byte) {
	t.Helper()
	if len(payload) > 125 {
		t.Fatal("test frame too large")
	}
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload)), mask[0], mask[1], mask[2], mask[3]}
	for i, b := range payload {
		frame = append(frame, b^mask[i%len(mask)])
	}
	if _, err := w.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func readMaskedFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[1]&0x80 == 0 || header[1]&0x7f > 125 {
		return nil, fmt.Errorf("unexpected test frame")
	}
	length := int(header[1] & 0x7f)
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	return payload, nil
}

func readServerFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[1]&0x80 != 0 || header[1] > 125 {
		t.Fatalf("unexpected server frame header %x", header)
	}
	payload := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestRelayServerFramesDoesNotStallOnSecretPrefix(t *testing.T) {
	t.Parallel()
	reps := sameLengthReplacements([][2]string{{"xsecret", "sp_place"}})
	// A complete 2-byte text frame whose payload is a prefix of the secret
	// must be delivered whole before the server sends anything else.
	pr, pw := io.Pipe()
	defer pw.Close()
	out := make(chan []byte, 1)
	go func() {
		var got bytes.Buffer
		w := &notifyWriter{w: &got, ch: out, want: 4}
		_, _ = relayServerFrames(w, pr, reps)
	}()
	if _, err := pw.Write([]byte{0x81, 0x02, 'x', 's'}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-out:
		if !bytes.Equal(got, []byte{0x81, 0x02, 'x', 's'}) {
			t.Fatalf("relayed %x", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame ending in a secret prefix was withheld")
	}
}

// notifyWriter reports once at least want bytes have been written.
type notifyWriter struct {
	w    *bytes.Buffer
	ch   chan []byte
	want int
	sent bool
}

func (n *notifyWriter) Write(p []byte) (int, error) {
	c, err := n.w.Write(p)
	if !n.sent && n.w.Len() >= n.want {
		n.sent = true
		n.ch <- append([]byte(nil), n.w.Bytes()...)
	}
	return c, err
}

func TestRelayServerFramesScrubsLongAndPreservesEmptyControlFrame(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("S", 40)
	reps := sameLengthReplacements([][2]string{{secret, "sp_placeholder"}})
	payload := []byte("prefix " + secret + " suffix " + strings.Repeat("z", 200))
	frame := []byte{0x81, 126, byte(len(payload) >> 8), byte(len(payload))}
	frame = append(frame, payload...)
	ping := []byte{0x89, 0x00}
	var got bytes.Buffer
	_, err := relayServerFrames(&got, bytes.NewReader(append(frame, ping...)), reps)
	if err != io.EOF {
		t.Fatal(err)
	}
	out := got.Bytes()
	if len(out) != len(frame)+len(ping) || bytes.Contains(out, []byte(secret)) || !bytes.Contains(out, []byte("sp_placeholder")) {
		t.Fatalf("relayed %d bytes (want %d), contains secret=%v", len(out), len(frame)+len(ping), bytes.Contains(out, []byte(secret)))
	}
	if !bytes.Equal(out[len(frame):], ping) {
		t.Fatalf("control frame altered: %x", out[len(frame):])
	}
}

func TestRelayServerFramesUsesLongestSecretMatch(t *testing.T) {
	t.Parallel()
	frame := append([]byte{0x81, 0x06}, []byte("abcdef")...)
	reps := sameLengthReplacements([][2]string{{"abc", "one"}, {"abcdef", "two"}})
	var got bytes.Buffer
	_, err := relayServerFrames(&got, bytes.NewReader(frame), reps)
	if err != io.EOF {
		t.Fatal(err)
	}
	if want := []byte("two***"); !bytes.Equal(got.Bytes()[2:], want) {
		t.Fatalf("relayed payload = %q, want %q", got.Bytes()[2:], want)
	}
}
