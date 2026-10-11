package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestPeekClientHelloReplaysBytes(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	client := tls.Client(clientRaw, &tls.Config{
		ServerName: "api.example.test",
		MinVersion: tls.VersionTLS12,
	})
	done := make(chan error, 1)
	go func() { done <- client.Handshake() }()

	host, replay, err := peekClientHello(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	if host != "api.example.test" {
		t.Fatalf("SNI = %q", host)
	}
	_ = replay.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client handshake did not stop after replay connection closed")
	}
}

func TestLimitListenerReleasesOnce(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	limited := limitListener(listener, 1)

	client1, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()
	server1, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}

	client2, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := limited.Accept()
		accepted <- conn
	}()
	select {
	case <-accepted:
		t.Fatal("second Accept returned before the first connection closed")
	case <-time.After(50 * time.Millisecond):
	}

	if err := server1.Close(); err != nil {
		t.Fatal(err)
	}
	_ = server1.Close()
	select {
	case server2 := <-accepted:
		if server2 == nil {
			t.Fatal("second Accept failed")
		}
		_ = server2.Close()
	case <-time.After(time.Second):
		t.Fatal("second Accept did not resume")
	}
}
