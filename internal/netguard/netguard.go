// Package netguard is the dialer the proxy uses for every upstream
// connection. It refuses to connect to addresses that should never be a
// legitimate destination for a sandboxed agent's traffic: loopback,
// link-local, private ranges, and cloud metadata services. This holds even
// when DNS says otherwise, so a name that resolves to 169.254.169.254 is
// refused, not dialed.
//
// Design (ported from Infisical Agent Vault's internal/netguard, MIT):
//
//   - Resolve the name once, look at every answer, refuse if any answer is
//     blocked. Refusing on "any" rather than "all" closes the DNS-rebinding
//     trick where the first answer is public and the second is not.
//   - Dial the vetted IP directly, never re-resolve. The check and the dial
//     must see the same address.
//   - Cloud metadata addresses are always blocked. Private ranges are
//     blocked by default and can be allowed for deployments that legitimately
//     bind secrets to internal services.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// The address-checking and dial-by-vetted-IP design is adapted from
// Infisical Agent Vault (MIT, Copyright (c) 2022 Infisical Inc.); see NOTICE.

var alwaysBlocked = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),        // IPv4 loopback
	netip.MustParsePrefix("::1/128"),            // IPv6 loopback
	netip.MustParsePrefix("0.0.0.0/32"),         // IPv4 unspecified
	netip.MustParsePrefix("::/128"),             // IPv6 unspecified
	netip.MustParsePrefix("169.254.0.0/16"),     // IPv4 link-local
	netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
	netip.MustParsePrefix("224.0.0.0/4"),        // IPv4 multicast
	netip.MustParsePrefix("ff00::/8"),           // IPv6 multicast
	netip.MustParsePrefix("169.254.169.254/32"), // AWS, GCP, and Azure metadata
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS metadata over IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved, incl. 255.255.255.255
	netip.MustParsePrefix("192.0.2.0/24"),       // documentation ranges: never routed
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("100::/64"),       // IPv6 discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo: tunnels an IPv4 address we cannot vet
	netip.MustParsePrefix("64:ff9b:1::/48"), // RFC 8215 local-use NAT64: where the IPv4 sits depends on the operator's prefix length, so it cannot be vetted; not globally routed anyway
	netip.MustParsePrefix("::ffff:0:0/96"),  // IPv4-mapped that survived Unmap (cannot happen, belt and braces)
}

// Prefixes that embed an IPv4 address. The embedded address is what
// actually gets reached, so it is the one to check.
var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96") // RFC 6052 well-known prefix: IPv4 in the last 32 bits
	sixToFour = netip.MustParsePrefix("2002::/16")    // RFC 3056
)

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// Dialer implements the DialContext shape http.Transport expects.
type Dialer struct {
	// AllowPrivate permits RFC 1918, ULA, CGNAT and similar ranges. Metadata
	// and loopback stay blocked regardless.
	AllowPrivate bool

	// Timeout for the TCP connect. Zero means 10s.
	Timeout time.Duration

	// Resolver override, mainly for tests. nil means net.DefaultResolver.
	Resolver *net.Resolver

	lookup func(context.Context, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

// DialContext resolves addr ("host:port"), checks every answer, and dials
// one vetted address.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("netguard: invalid destination address")
	}

	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		lookup := d.lookup
		if lookup == nil {
			resolver := d.Resolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return resolver.LookupNetIP(ctx, "ip", host)
			}
		}
		ips, err = lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("netguard: DNS lookup failed for %q", host)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("netguard: DNS lookup returned no addresses for %q", host)
		}
	}

	for _, ip := range ips {
		if Blocked(ip, d.AllowPrivate) {
			return nil, fmt.Errorf("netguard: connection to %q (%s) blocked by network policy", host, ip)
		}
	}

	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dial := d.dial
	if dial == nil {
		netDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		dial = netDialer.DialContext
	}
	for _, ip := range ips {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("netguard: could not connect to %q", host)
}

// Blocked reports whether ip may never be dialed. Always true for loopback,
// unspecified, link-local, multicast, and the cloud metadata addresses
// (169.254.169.254, fd00:ec2::254, 100.100.100.200, metadata.google.internal
// resolves to 169.254.169.254). True for private ranges unless allowPrivate.
func Blocked(ip netip.Addr, allowPrivate bool) bool {
	if !ip.IsValid() {
		return true
	}
	// A zone ("::1%lo") picks the interface and makes every Prefix.Contains
	// below report false, so a zoned loopback or metadata address would
	// sail through. No public destination needs one.
	if ip.Zone() != "" {
		return true
	}
	ip = ip.Unmap()
	if embedded, ok := embeddedIPv4(ip); ok {
		return Blocked(embedded, allowPrivate)
	}
	for _, prefix := range alwaysBlocked {
		if prefix.Contains(ip) {
			return true
		}
	}
	if allowPrivate {
		return false
	}
	for _, prefix := range privateRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// embeddedIPv4 extracts the IPv4 address carried inside a NAT64 or 6to4
// IPv6 address, so that 64:ff9b::7f00:1 is judged as 127.0.0.1.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}
