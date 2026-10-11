package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// peekClientHello reads the TLS ClientHello from conn without consuming it,
// returning the SNI hostname and a net.Conn that will replay the bytes
// already read followed by the rest of the stream. The TLS handshake has
// not happened; the caller either splices the replay conn to the real host
// (passthrough) or wraps it in tls.Server (inspect).
//
// The standard-library TLS parser keeps this routing logic aligned with the
// protocol implementation without adding a second ClientHello parser:
//   - wrap conn in a reader that tees everything read into a bytes.Buffer
//   - call tls.Server(readOnlyConn{r}, &tls.Config{GetConfigForClient: capture}).Handshake()
//     where capture records hello.ServerName and returns an error to abort
//     the handshake immediately after the hello is parsed
//   - readOnlyConn's Write returns io.ErrClosedPipe so nothing is sent back
//   - return sni, and a conn whose Read serves io.MultiReader(buffer, conn)
//     while Write/Close/deadlines go to the original conn
//   - apply a short read deadline (5s) for the hello; clear it after
//   - empty SNI is an error: we cannot route without it
func peekClientHello(conn net.Conn) (sni string, replay net.Conn, err error) {
	var read bytes.Buffer
	tee := io.TeeReader(conn, &read)
	probe := tls.Server(&readOnlyConn{Conn: conn, reader: tee}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errHelloCaptured
		},
	})

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", nil, err
	}
	_ = probe.Handshake()
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", nil, err
	}
	if sni == "" {
		return "", nil, errors.New("TLS ClientHello has no SNI")
	}
	return sni, &replayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(read.Bytes()), conn)}, nil
}

var errHelloCaptured = errors.New("client hello captured")

type readOnlyConn struct {
	net.Conn
	reader io.Reader
}

func (c *readOnlyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *readOnlyConn) Write([]byte) (int, error)  { return 0, io.ErrClosedPipe }

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
