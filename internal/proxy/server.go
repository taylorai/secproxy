// Package proxy is the data path. Two listeners feed one decision:
//
//	transparent listener  --- raw TLS, read SNI ---\
//	                                                 >-- handleTLSConn(host) --- deny | passthrough | inspect
//	connect listener      --- CONNECT host:443 -----/
//
// "inspect" terminates TLS with a certificate from our CA, parses HTTP/1.1,
// hands each request to the policy engine, and forwards it over a fresh,
// normally verified TLS connection to the real host.
package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/ca"
	"github.com/taylorai/secproxy/internal/netguard"
	"github.com/taylorai/secproxy/internal/policy"
)

// Limits that bound resource use. Generous where LLM traffic needs it
// (long streaming responses) and tight where nothing legitimate needs room.
const (
	maxConcurrentConns = 512
	maxHeaderBytes     = 64 << 10
	readHeaderTimeout  = 30 * time.Second
	idleTimeout        = 2 * time.Minute
	upstreamTLSTimeout = 15 * time.Second
	responseHeaderWait = 5 * time.Minute  // time-to-first-byte from an LLM can be long
	tunnelIdle         = 30 * time.Minute // passthrough / websocket idle cutoff
)

// Server owns the listeners and everything they share.
type Server struct {
	Policy *policy.Policy
	CA     *ca.CA
	Audit  *audit.Logger
	Dialer *netguard.Dialer

	upstream *http.Transport
	dial     func(context.Context, string, string) (net.Conn, error)

	mu      sync.Mutex
	tunnels map[net.Conn]struct{} // hijacked / spliced conns, closed on Shutdown
}

// New wires a Server. The upstream transport is HTTP/1.1 only, on purpose:
// we speak HTTP/1.1 to the client, and letting Go negotiate h2 upstream
// while re-serialising an HTTP/1.1 tunnel is a known way to hang.
// (Infisical CLI packages/agentproxy/proxy.go:196-206 documents the bug.)
func New(p *policy.Policy, c *ca.CA, a *audit.Logger, d *netguard.Dialer) *Server {
	s := &Server{Policy: p, CA: c, Audit: a, Dialer: d, dial: d.DialContext, tunnels: map[net.Conn]struct{}{}}
	s.upstream = &http.Transport{
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:   upstreamTLSTimeout,
		ResponseHeaderTimeout: responseHeaderWait,
		IdleConnTimeout:       idleTimeout,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{}, // non-nil and empty: never h2
		DisableCompression:    true,                                                   // we drop Accept-Encoding ourselves; see forward.go
	}
	return s
}

// ServeTransparent accepts raw TLS connections on l until ctx is done.
func (s *Server) ServeTransparent(ctx context.Context, l net.Listener) error {
	return s.acceptLoop(ctx, limitListener(l, maxConcurrentConns), func(c net.Conn) {
		s.handleTransparent(ctx, c)
	})
}

// ServeConnect runs an HTTP proxy (CONNECT + absolute-form http://) on l.
func (s *Server) ServeConnect(ctx context.Context, l net.Listener) error {
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handleConnectRequest),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(limitListener(l, maxConcurrentConns))
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown closes spliced and hijacked connections, which http.Server's own
// Shutdown does not know about.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.tunnels {
		_ = c.Close()
	}
	s.upstream.CloseIdleConnections()
}

// handleTLSConn is the point where both listeners meet. conn carries a TLS
// ClientHello that has not been consumed (the transparent listener peeks
// and rewinds; the connect listener has just written "200 Connection
// Established" and the client is about to send its hello). host is
// canonical.
func (s *Server) handleTLSConn(ctx context.Context, conn net.Conn, host, port, listener string) {
	action := s.Policy.Decide(host)
	switch action {
	case policy.Deny:
		s.log(audit.Event{Decision: "deny", Host: host, Reason: "unmatched_host", Listener: listener})
		_ = conn.Close()
	case policy.Passthrough:
		s.passthrough(ctx, conn, host, port, listener)
	case policy.Inspect:
		s.inspect(ctx, conn, host, port, listener)
	}
}

func (s *Server) log(ev audit.Event) {
	host := ev.Host
	ev.Host = s.safeClientText(host, ev.Host)
	ev.Method = s.safeClientText(host, ev.Method)
	ev.Path = s.safeClientText(host, ev.Path)
	for i := range ev.Bindings {
		ev.Bindings[i] = s.safeClientText(host, ev.Bindings[i])
	}
	for i := range ev.Automatic {
		ev.Automatic[i] = s.safeClientText(host, ev.Automatic[i])
	}
	s.Audit.Log(ev)
}

// track registers a long-lived conn so Shutdown can close it. Returns an
// untrack func for when the conn ends on its own.
func (s *Server) track(c net.Conn) func() {
	s.mu.Lock()
	s.tunnels[c] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.tunnels, c)
		s.mu.Unlock()
	}
}

func (s *Server) acceptLoop(ctx context.Context, l net.Listener, handle func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		go handle(c)
	}
}

// limitListener caps concurrent accepted connections. The shape follows
// the connection limiter in Infisical CLI packages/agentproxy/proxy.go
// (MIT, Copyright (c) 2025 Infisical Inc.); see NOTICE.
//
// It caps concurrent accepted connections. Accept blocks when
// the cap is reached; a closed conn frees a slot.
//
// A buffered channel acts as the semaphore. Accept acquires a slot, and the
// returned net.Conn's Close releases it exactly once.
func limitListener(l net.Listener, n int) net.Listener {
	return &limitedListener{Listener: l, sem: make(chan struct{}, n), closed: make(chan struct{})}
}

type limitedListener struct {
	net.Listener
	sem       chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
