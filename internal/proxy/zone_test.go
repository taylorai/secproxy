package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/ca"
	"github.com/taylorai/secproxy/internal/config"
	"github.com/taylorai/secproxy/internal/netguard"
	"github.com/taylorai/secproxy/internal/policy"
)

// With unmatched_host: passthrough, a zoned IPv6 literal ("[::1%lo0]") used
// to reach loopback services through the real netguard dialer, because a
// zone defeats every prefix check. Both the plain-HTTP and CONNECT paths
// must refuse it.
func TestZonedLoopbackIsRefused(t *testing.T) {
	const marker = "LOOPBACK_ONLY"
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	})}
	go func() { _ = backend.Serve(listener) }()
	defer backend.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	zone := loopbackInterfaceName(t)

	pol, err := policy.Compile(&config.Config{UnmatchedHost: "passthrough"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	srv := New(pol, authority, audit.New(&log, "zone"), &netguard.Dialer{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeConnect(ctx, front) }()

	hostport := "[::1%25" + zone + "]:" + port // %25 is how a URL spells the zone's "%"
	for _, request := range []string{
		fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostport, hostport),
		fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport, hostport),
	} {
		conn, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(conn, request)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		_ = conn.Close()
		if resp.StatusCode < 400 || strings.Contains(string(body), marker) {
			t.Errorf("%q: got %d %q, want a refusal", strings.SplitN(request, "\r\n", 2)[0], resp.StatusCode, body)
		}
	}
}

func loopbackInterfaceName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}
