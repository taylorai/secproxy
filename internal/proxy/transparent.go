package proxy

import (
	"context"
	"net"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/policy"
)

// handleTransparent serves one raw TLS connection delivered by a
// network-level relay. The only routing information is the SNI in the
// ClientHello; there is no original destination address. Port is assumed
// to be 443, which is what such relays carry.
func (s *Server) handleTransparent(ctx context.Context, conn net.Conn) {
	sni, replay, err := peekClientHello(conn)
	if err != nil {
		s.Audit.Log(audit.Event{Decision: "deny", Reason: "no_sni", Listener: "transparent"})
		_ = conn.Close()
		return
	}
	host, err := policy.CanonicalHost(sni)
	if err != nil {
		s.Audit.Log(audit.Event{Decision: "deny", Reason: "bad_sni", Listener: "transparent"})
		_ = conn.Close()
		return
	}
	s.handleTLSConn(ctx, replay, host, "443", "transparent")
}
