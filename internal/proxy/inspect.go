package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/taylorai/secproxy/internal/audit"
)

// inspect terminates the client's TLS with a certificate for host, then
// serves HTTP/1.1 on the decrypted connection. Every request goes through
// handleInspectedRequest (forward.go).
//
// The client sees ALPN "http/1.1" only, so browsers-and-SDKs that would
// prefer h2 fall back cleanly. There is no h2 anywhere in the inspect path.
func (s *Server) inspect(ctx context.Context, raw net.Conn, host, port, listener string) {
	leaf, err := s.CA.Leaf(host)
	if err != nil {
		s.log(audit.Event{Decision: "error", Host: host, Reason: "leaf_cert", Listener: listener})
		_ = raw.Close()
		return
	}
	tlsConn := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.log(audit.Event{Decision: "error", Host: host, Reason: "client_tls", Listener: listener})
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	l := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler:           s.inspectedHandler(host, port, listener),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				_ = l.Close()
			}
		},
	}
	untrack := s.track(tlsConn)
	defer untrack()
	_ = srv.Serve(l)
}

// inspectedHandler binds the connection's destination into the request
// handler so forward.go can check that each request agrees with it.
func (s *Server) inspectedHandler(host, port, listener string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleInspectedRequest(w, r, host, port, listener)
	})
}

// oneShotListener hands one already-open connection to http.Server and
// then never produces another. Adapted from the same idea in Infisical CLI
// packages/agentproxy/proxy.go (MIT, Copyright (c) 2025 Infisical Inc.);
// see NOTICE.
type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	l := &oneShotListener{conn: conn, yield: make(chan net.Conn, 1), closed: make(chan struct{})}
	l.yield <- conn
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.yield:
		return conn, nil
	case <-l.closed:
		return nil, errors.New("proxy: one-shot listener closed")
	}
}

func (l *oneShotListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }
