package policy

import (
	"testing"
)

func TestCanonicalHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"API.Example.COM", "api.example.com"},
		{"api.example.com.", "api.example.com"},
		{"api.example.com:443", "api.example.com"},
		{"[2001:0db8::1]:443", "2001:db8::1"},
		{"[2001:0db8::1]", "2001:db8::1"},
		{"192.000.002.001", "192.000.002.001"}, // invalid IP syntax remains a DNS-like name
	}
	for _, tt := range tests {
		got, err := CanonicalHost(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("CanonicalHost(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, in := range []string{
		"", "example.com/path", "user@example.com", "example.com?x", "a..b",
		// IPv6 zones: net.ParseIP refuses them but netguard's parser does
		// not, so one slipping through here would reach netguard zoned.
		"::1%lo0", "[::1%lo0]:443", "fe80::1%en0", "fd00:ec2::254%eth0",
		"*.example.com", "exa\x00mple.com",
	} {
		if got, err := CanonicalHost(in); err == nil {
			t.Errorf("CanonicalHost(%q) = %q, want error", in, got)
		}
	}
}

func TestHostMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
	}
	for _, tt := range tests {
		if got := hostMatches(tt.pattern, tt.host); got != tt.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestPathGlobs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		{"star one segment", []string{"/repos/*/issues"}, "/repos/acme/issues", true},
		{"star not two segments", []string{"/repos/*/issues"}, "/repos/acme/tool/issues", false},
		{"double star zero", []string{"/repos/**"}, "/repos", true},
		{"double star many", []string{"/repos/**"}, "/repos/acme/tool/issues", true},
		{"literal mismatch", []string{"/repos/acme"}, "/repos/other", false},
		{"dot segment rejected", []string{"/**"}, "/a/../b", false},
		{"percent rejected", []string{"/**"}, "/a%2fb", false},
		{"backslash rejected", []string{"/**"}, `/a\b`, false},
		{"semicolon dot dot rejected", []string{"/ok/**"}, "/ok/..;/admin", false},
		{"semicolon param rejected", []string{"/ok/**"}, "/ok/x;jsessionid=1", false},
		{"empty segment rejected", []string{"/ok/*/read"}, "/ok//read", false},
		{"leading double slash rejected", []string{"/**"}, "//ok/x", false},
		{"dots only segment rejected", []string{"/**"}, "/ok/.../x", false},
		{"root allowed", []string{"/**"}, "/", true},
		{"ordinary api path allowed", []string{"/repos/*/*/issues/**"}, "/repos/acme/tool.js/issues/42/comments", true},
		{"dots inside a segment allowed", []string{"/v1/*"}, "/v1/file.tar.gz", true},
		// Leading and trailing slashes delimit segments rather than creating
		// empty ones, so these spell the same path for policy matching.
		{"trailing slash ignored", []string{"/repos/acme/"}, "/repos/acme", true},
		{"path trailing slash ignored", []string{"/repos/acme"}, "/repos/acme/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := anyPathMatches(tt.patterns, tt.path); got != tt.want {
				t.Fatalf("anyPathMatches(%q, %q) = %v, want %v", tt.patterns, tt.path, got, tt.want)
			}
		})
	}
}
