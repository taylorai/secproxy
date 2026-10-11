package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/taylorai/secproxy/internal/audit"
)

// passthrough splices the client's TLS stream to the real host without
// decrypting it. No policy beyond "this host is on the egress list" applies,
// and no secret can be involved because we never see the plaintext. This is
// what lets pip, npm, git-over-https and anything with certificate pinning
// work without trusting our CA.
//
// The splice:
//   - dial via s.Dialer.DialContext(ctx, "tcp", host+":"+port) with a
//     connect timeout; on error audit decision "error" reason "dial" and close
//   - track both conns (s.track) so Shutdown can cut them
//   - io.Copy in both directions; when either direction ends, close both.
//     No half-close dance: a TLS session cannot do anything useful after
//     one side is gone.
//   - refresh an idle deadline (tunnelIdle) on activity in either direction
//   - audit decision "passthrough" once at the end with bytes in/out and ms
func (s *Server) passthrough(ctx context.Context, client net.Conn, host, port, listener string) {
	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, upstreamTLSTimeout)
	upstream, err := s.dial(dialCtx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		s.log(audit.Event{Decision: "error", Host: host, Reason: "dial", Listener: listener})
		_ = client.Close()
		return
	}

	untrackClient := s.track(client)
	defer untrackClient()
	untrackUpstream := s.track(upstream)
	defer untrackUpstream()

	clientIdle := &activityConn{Conn: client, idle: tunnelIdle}
	upstreamIdle := &activityConn{Conn: upstream, idle: tunnelIdle}
	type result struct {
		clientToUpstream bool
		n                int64
	}
	done := make(chan result, 2)
	copyOne := func(dst io.Writer, src io.Reader, clientToUpstream bool) {
		buf := make([]byte, 32<<10)
		n, _ := io.CopyBuffer(dst, src, buf)
		done <- result{clientToUpstream: clientToUpstream, n: n}
	}
	go copyOne(upstreamIdle, clientIdle, true)
	go copyOne(clientIdle, upstreamIdle, false)

	first := <-done
	_ = client.Close()
	_ = upstream.Close()
	second := <-done

	var bytesIn, bytesOut int64
	for _, result := range []result{first, second} {
		if result.clientToUpstream {
			bytesIn = result.n
		} else {
			bytesOut = result.n
		}
	}
	s.log(audit.Event{
		Decision: "passthrough", Host: host, Listener: listener,
		BytesIn: bytesIn, BytesOut: bytesOut, Millis: time.Since(start).Milliseconds(),
	})
}

// activityConn applies the idle timeout to each operation, so traffic in
// either direction keeps an active tunnel alive without a timer goroutine.
type activityConn struct {
	net.Conn
	idle time.Duration
	mu   sync.Mutex
}

func (c *activityConn) refresh() {
	c.mu.Lock()
	_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	c.mu.Unlock()
}

func (c *activityConn) Read(p []byte) (int, error) {
	c.refresh()
	return c.Conn.Read(p)
}

func (c *activityConn) Write(p []byte) (int, error) {
	c.refresh()
	return c.Conn.Write(p)
}
