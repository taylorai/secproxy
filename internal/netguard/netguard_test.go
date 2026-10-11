package netguard

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestBlockedRanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		hit          string
		miss         string
		allowPrivate bool
	}{
		{"loopback v4", "127.1.2.3", "126.255.255.255", true},
		{"loopback v6", "::1", "::2", true},
		{"unspecified v4", "0.0.0.0", "0.0.0.1", true},
		{"unspecified v6", "::", "::2", true},
		{"link local v4", "169.254.1.1", "169.253.255.255", true},
		{"link local v6", "fe80::1", "fe7f::1", true},
		{"multicast v4", "224.0.0.1", "223.255.255.255", true},
		{"multicast v6", "ff02::1", "feff::1", true},
		{"metadata v4", "169.254.169.254", "169.253.169.254", true},
		{"metadata v6", "fd00:ec2::254", "fd00:ec2::253", true},
		{"alibaba metadata", "100.100.100.200", "100.100.100.201", true},
		{"rfc1918 10", "10.2.3.4", "11.0.0.1", false},
		{"rfc1918 172", "172.31.2.3", "172.32.0.1", false},
		{"rfc1918 192", "192.168.2.3", "192.169.0.1", false},
		{"cgnat", "100.64.1.2", "100.128.0.1", false},
		{"ula", "fd12::1", "fe00::1", false},
		{"this network", "0.1.2.3", "1.0.0.1", false},
		{"ietf protocol assignments", "192.0.0.9", "192.0.1.1", false},
		{"benchmarking", "198.19.1.2", "198.20.0.1", false},
		{"reserved 240/4", "240.0.0.1", "223.255.255.254", true},
		{"broadcast", "255.255.255.255", "223.0.0.1", true},
		{"documentation", "203.0.113.7", "203.0.114.1", true},
		{"nat64 wrapping loopback", "64:ff9b::7f00:1", "64:ff9b::808:808", true},
		{"nat64 wrapping metadata", "64:ff9b::a9fe:a9fe", "64:ff9b::101:101", true},
		{"nat64 wrapping rfc1918", "64:ff9b::a00:1", "64:ff9b::1.1.1.1", false},
		{"local-use nat64 blocked outright", "64:ff9b:1:7f00:0:100:808:808", "64:ff9b::808:808", true},
		{"6to4 wrapping loopback", "2002:7f00:1::1", "2002:808:808::1", true},
		{"teredo", "2001::1", "2001:4860::1", true},
		{"discard only", "100::1", "101::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !Blocked(netip.MustParseAddr(tt.hit), tt.allowPrivate) {
				t.Fatalf("Blocked(%s) = false, want true", tt.hit)
			}
			if Blocked(netip.MustParseAddr(tt.miss), tt.allowPrivate) {
				t.Fatalf("Blocked(%s) = true, want false", tt.miss)
			}
		})
	}
}

func TestBlockedPrivateCanBeAllowed(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "fc00::1", "0.0.0.1", "192.0.0.1", "198.18.0.1"} {
		if Blocked(netip.MustParseAddr(raw), true) {
			t.Errorf("Blocked(%s, true) = true", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "169.254.169.254", "fd00:ec2::254", "100.100.100.200"} {
		if !Blocked(netip.MustParseAddr(raw), true) {
			t.Errorf("Blocked(%s, true) = false", raw)
		}
	}
}

func TestBlockedUnmapsIPv4(t *testing.T) {
	t.Parallel()
	if !Blocked(netip.MustParseAddr("::ffff:127.0.0.1"), true) {
		t.Fatal("IPv4-mapped loopback was allowed")
	}
	if !Blocked(netip.MustParseAddr("::ffff:10.0.0.1"), false) {
		t.Fatal("IPv4-mapped private address was allowed")
	}
}

func TestDialContextRefusesMixedDNSAnswer(t *testing.T) {
	t.Parallel()
	dialed := false
	d := &Dialer{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "example.test:443")
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("DialContext error = %v, want blocked address", err)
	}
	if dialed {
		t.Fatal("DialContext dialed before vetting every DNS answer")
	}
}

func TestDialContextIPLiteralSkipsDNSAndDialsVettedIP(t *testing.T) {
	t.Parallel()
	lookupCalled := false
	var got string
	d := &Dialer{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			lookupCalled = true
			return nil, errors.New("unexpected lookup")
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			got = addr
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if lookupCalled {
		t.Fatal("IP literal caused a DNS lookup")
	}
	if got != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want vetted literal", got)
	}
}

func TestDialContextDialsResolvedIPWithoutResolvingAgain(t *testing.T) {
	t.Parallel()
	var got string
	d := &Dialer{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			got = addr
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.test:8443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got != "93.184.216.34:8443" {
		t.Fatalf("dialed %q, want resolved IP", got)
	}
}

func TestDialContextTriesVettedAnswersInOrder(t *testing.T) {
	t.Parallel()
	var got []string
	d := &Dialer{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("93.184.216.35"),
			}, nil
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			got = append(got, addr)
			if len(got) == 1 {
				return nil, errors.New("first address refused")
			}
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	want := []string{"93.184.216.34:443", "93.184.216.35:443"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dial order = %v, want %v", got, want)
	}
}

func TestDialContextHidesResolverAndDialErrors(t *testing.T) {
	t.Parallel()
	const sensitive = "secret-in-internal-error"
	t.Run("lookup", func(t *testing.T) {
		d := &Dialer{lookup: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New(sensitive)
		}}
		_, err := d.DialContext(context.Background(), "tcp", "example.test:443")
		if err == nil || strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error was not safely redacted: %v", err)
		}
	})
	t.Run("dial", func(t *testing.T) {
		d := &Dialer{
			lookup: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			},
			dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New(sensitive)
			},
		}
		_, err := d.DialContext(context.Background(), "tcp", "example.test:443")
		if err == nil || strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error was not safely redacted: %v", err)
		}
	})
}

func TestDialContextRefusesLoopbackServer(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("sandbox does not permit local listeners: %v", err)
	}
	server := httptest.NewUnstartedServer(nil)
	server.Listener = listener
	server.Start()
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	if _, err := (&Dialer{AllowPrivate: true}).DialContext(context.Background(), "tcp", addr); err == nil {
		t.Fatal("connected to loopback httptest server")
	}
}

// A zone makes every netip.Prefix.Contains report false, so zoned addresses
// must be refused outright rather than checked against the ranges.
func TestBlockedRefusesZonedAddresses(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"::1%lo0", "fe80::1%en0", "fd00:ec2::254%eth0", "fd12::1%eth0", "64:ff9b::7f00:1%lo0", "2001:4860::1%eth0"} {
		if !Blocked(netip.MustParseAddr(raw), true) {
			t.Errorf("Blocked(%s, true) = false", raw)
		}
	}
}

func TestDialContextRefusesZonedLoopback(t *testing.T) {
	t.Parallel()
	zone := loopbackInterface(t)
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	addr := net.JoinHostPort("::1%"+zone, port)
	if conn, err := (&Dialer{AllowPrivate: true}).DialContext(context.Background(), "tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatalf("connected to loopback via %s", addr)
	}
}

func loopbackInterface(t *testing.T) string {
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
