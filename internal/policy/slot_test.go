package policy

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/taylorai/secproxy/internal/config"
)

func headerPolicy(t *testing.T, methods, paths []string) *Policy {
	t.Helper()
	return compileTestPolicy(t, "deny", nil, []config.Binding{{
		Secret: "token", Hosts: []string{"api.example.com"},
		Slot:    config.Slot{Header: &config.HeaderSlot{Name: "Authorization", Format: "Bearer {secret}"}},
		Methods: methods, Paths: paths,
	}})
}

func request(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestApplyHeaderSlot(t *testing.T) {
	t.Parallel()
	p := headerPolicy(t, nil, nil)
	r := request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder)
	res, rej := p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 {
		t.Fatalf("Apply() = %#v, %v", res, rej)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+testSecret {
		t.Fatalf("Authorization = %q", got)
	}

	r = request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder+"x")
	_, rej = p.Apply(r, "api.example.com")
	assertRejection(t, rej, "placeholder_misplaced", "Authorization")
}

func TestApplyRejectsDuplicateSlotHeader(t *testing.T) {
	t.Parallel()
	p := headerPolicy(t, nil, nil)
	r := request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Add("Authorization", "Bearer "+testPlaceholder)
	r.Header.Add("Authorization", "Bearer "+testPlaceholder)
	_, rej := p.Apply(r, "api.example.com")
	assertRejection(t, rej, "placeholder_misplaced", "Authorization")
}

func TestApplyRejectsStrayPlaceholders(t *testing.T) {
	t.Parallel()
	p := headerPolicy(t, nil, nil)
	tests := []struct {
		name string
		make func() *http.Request
		want string
	}{
		{"other header", func() *http.Request {
			r := request(t, http.MethodGet, "https://api.example.com/v1")
			r.Header.Set("X-Leak", testPlaceholder)
			return r
		}, "X-Leak"},
		{"path", func() *http.Request { return request(t, http.MethodGet, "https://api.example.com/"+testPlaceholder) }, "the URL path"},
		{"query", func() *http.Request {
			return request(t, http.MethodGet, "https://api.example.com/v1?q="+testPlaceholder)
		}, "the query string"},
		{"userinfo", func() *http.Request {
			r := request(t, http.MethodGet, "https://api.example.com/v1")
			r.URL.User = url.UserPassword("user", testPlaceholder)
			return r
		}, "the URL userinfo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, rej := p.Apply(tt.make(), "api.example.com")
			assertRejection(t, rej, "placeholder_misplaced", tt.want)
		})
	}
}

func TestApplyRestrictionsOnlyWhenPlaceholderPresent(t *testing.T) {
	t.Parallel()
	p := headerPolicy(t, []string{http.MethodGet, http.MethodPost}, []string{"/allowed/**"})

	r := request(t, http.MethodDelete, "https://api.example.com/allowed/item")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder)
	_, rej := p.Apply(r, "api.example.com")
	assertRejection(t, rej, "method_not_allowed", "GET", "POST")

	r = request(t, http.MethodGet, "https://api.example.com/other")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder)
	_, rej = p.Apply(r, "api.example.com")
	assertRejection(t, rej, "path_not_allowed", "/allowed/**")

	r = request(t, http.MethodDelete, "https://api.example.com/other")
	res, rej := p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 0 {
		t.Fatalf("placeholder-free request = %#v, %v", res, rej)
	}
}

func TestApplyBasicSlot(t *testing.T) {
	t.Parallel()
	basic := &config.BasicSlot{Username: "x-access-token", Password: "{secret}"}
	p := compileTestPolicy(t, "deny", nil, []config.Binding{{
		Secret: "token", Hosts: []string{"api.example.com"}, Slot: config.Slot{Basic: basic},
	}})
	r := request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testPlaceholder)))
	res, rej := p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 {
		t.Fatalf("Apply() = %#v, %v", res, rej)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testSecret))
	if got := r.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}

	r = request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("wrong:"+testPlaceholder)))
	_, rej = p.Apply(r, "api.example.com")
	assertRejection(t, rej, "placeholder_misplaced", "Authorization")
}

func TestApplyQuerySlot(t *testing.T) {
	t.Parallel()
	p := compileTestPolicy(t, "deny", nil, []config.Binding{{
		Secret: "token", Hosts: []string{"api.example.com"}, Slot: config.Slot{Query: &config.QuerySlot{Param: "token"}},
	}})
	r := request(t, http.MethodGet, "https://api.example.com/v1?keep=a+b&token="+testPlaceholder)
	res, rej := p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 {
		t.Fatalf("Apply() = %#v, %v", res, rej)
	}
	values := r.URL.Query()
	if values.Get("token") != testSecret || values.Get("keep") != "a b" {
		t.Fatalf("query after substitution = %#v", values)
	}

	r = request(t, http.MethodGet, "https://api.example.com/v1?other="+testPlaceholder)
	_, rej = p.Apply(r, "api.example.com")
	assertRejection(t, rej, "placeholder_misplaced", "query string")
}

func TestSameSecretDifferentSlotsWorkIndependently(t *testing.T) {
	t.Parallel()
	p := compileTestPolicy(t, "deny", nil, []config.Binding{
		{Secret: "token", Hosts: []string{"api.example.com"}, Slot: config.Slot{Header: &config.HeaderSlot{Name: "X-Token", Format: "{secret}"}}},
		{Secret: "token", Hosts: []string{"api.example.com"}, Slot: config.Slot{Basic: &config.BasicSlot{Username: "x-access-token", Password: "{secret}"}}},
	})

	r := request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("X-Token", testPlaceholder)
	res, rej := p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 || r.Header.Get("X-Token") != testSecret {
		t.Fatalf("header binding = %#v, %v, %q", res, rej, r.Header.Get("X-Token"))
	}

	r = request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testPlaceholder)))
	res, rej = p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 {
		t.Fatalf("basic binding = %#v, %v", res, rej)
	}
}

func assertRejection(t *testing.T, rej *Rejection, reason string, messageParts ...string) {
	t.Helper()
	if rej == nil {
		t.Fatal("Apply returned no rejection")
	}
	if rej.Status != http.StatusForbidden || rej.Reason != reason {
		t.Fatalf("rejection = %#v, want status 403 reason %q", rej, reason)
	}
	for _, part := range messageParts {
		if !strings.Contains(rej.Message, part) {
			t.Errorf("message %q does not contain %q", rej.Message, part)
		}
	}
}

func alwaysPolicy(t *testing.T, methods []string) *Policy {
	t.Helper()
	return compileTestPolicy(t, "deny", nil, []config.Binding{{
		Secret: "token", Hosts: []string{"api.example.com"},
		Slot:    config.Slot{Header: &config.HeaderSlot{Name: "Authorization", Format: "Bearer {secret}"}},
		Methods: methods, Inject: config.InjectAlways,
	}})
}

func TestApplyAlwaysFillsEmptySlot(t *testing.T) {
	t.Parallel()
	p := alwaysPolicy(t, nil)
	r := request(t, http.MethodGet, "https://api.example.com/v1")
	res, rej := p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 || len(res.Automatic) != 1 {
		t.Fatalf("Apply() = %#v, %v", res, rej)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+testSecret {
		t.Fatalf("Authorization = %q", got)
	}

	// The placeholder still works, and is not reported as automatic.
	r = request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder)
	res, rej = p.Apply(r, "api.example.com")
	if rej != nil || len(res.Applied) != 1 || len(res.Automatic) != 0 {
		t.Fatalf("Apply() with placeholder = %#v, %v", res, rej)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+testSecret {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestApplyAlwaysRefusesOccupiedSlot(t *testing.T) {
	t.Parallel()
	p := alwaysPolicy(t, nil)
	r := request(t, http.MethodGet, "https://api.example.com/v1")
	r.Header.Set("Authorization", "Bearer someone-elses-token")
	_, rej := p.Apply(r, "api.example.com")
	assertRejection(t, rej, "slot_occupied", "Authorization", "different value")
	if got := r.Header.Get("Authorization"); got != "Bearer someone-elses-token" {
		t.Fatalf("occupied slot was rewritten to %q", got)
	}
}

func TestApplyAlwaysGatesTheRequestByMethod(t *testing.T) {
	t.Parallel()
	p := alwaysPolicy(t, []string{http.MethodGet})
	r := request(t, http.MethodDelete, "https://api.example.com/v1")
	_, rej := p.Apply(r, "api.example.com")
	assertRejection(t, rej, "method_not_allowed", "GET")
}

func TestApplyAlwaysBasicAndQuerySlots(t *testing.T) {
	t.Parallel()
	basic := &config.BasicSlot{Username: "x-access-token", Password: "{secret}"}
	p := compileTestPolicy(t, "deny", nil, []config.Binding{
		{Secret: "token", Hosts: []string{"git.example.com"}, Slot: config.Slot{Basic: basic}, Inject: config.InjectAlways},
		{Secret: "token", Hosts: []string{"q.example.com"}, Slot: config.Slot{Query: &config.QuerySlot{Param: "key"}}, Inject: config.InjectAlways},
	})

	r := request(t, http.MethodGet, "https://git.example.com/org/repo/info/refs")
	res, rej := p.Apply(r, "git.example.com")
	if rej != nil || len(res.Automatic) != 1 {
		t.Fatalf("basic Apply() = %#v, %v", res, rej)
	}
	if got := r.Header.Get("Authorization"); got != "Basic "+basicToken(basic, testSecret) {
		t.Fatalf("Authorization = %q", got)
	}
	r = request(t, http.MethodGet, "https://git.example.com/org/repo/info/refs")
	r.Header.Set("Authorization", "Bearer other")
	_, rej = p.Apply(r, "git.example.com")
	assertRejection(t, rej, "slot_occupied")

	r = request(t, http.MethodGet, "https://q.example.com/v1?keep=1")
	res, rej = p.Apply(r, "q.example.com")
	if rej != nil || len(res.Automatic) != 1 {
		t.Fatalf("query Apply() = %#v, %v", res, rej)
	}
	if values := r.URL.Query(); values.Get("key") != testSecret || values.Get("keep") != "1" {
		t.Fatalf("query after substitution = %#v", values)
	}
}

func TestPathRulesSeeTheEncodedPath(t *testing.T) {
	t.Parallel()
	p := headerPolicy(t, nil, []string{"/ok/**"})
	r := request(t, http.MethodGet, "https://api.example.com/ok%2F..%2Fother")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder)
	_, rej := p.Apply(r, "api.example.com")
	assertRejection(t, rej, "path_not_allowed")

	r = request(t, http.MethodGet, "https://api.example.com/ok/x%2Fy")
	r.Header.Set("Authorization", "Bearer "+testPlaceholder)
	_, rej = p.Apply(r, "api.example.com")
	assertRejection(t, rej, "path_not_allowed")
}

// Method and path rules check the request line. A request that uses a
// secret may not ask the upstream to act on a different one.
func TestApplyRefusesRoutingOverridesWithASecret(t *testing.T) {
	t.Parallel()
	p := headerPolicy(t, []string{http.MethodGet, http.MethodPost}, []string{"/ok/**"})
	overrides := []struct {
		header, value string
		query         string
	}{
		{header: "X-HTTP-Method-Override", value: "DELETE"},
		{header: "X-Http-Method", value: "DELETE"},
		{header: "X-Method-Override", value: "DELETE"},
		{header: "X_HTTP_METHOD_OVERRIDE", value: "DELETE"}, // CGI reads "_" as "-"
		{header: "X-Original-URL", value: "/admin"},
		{header: "X-Rewrite-URL", value: "/admin"},
		{header: "X-Forwarded-Host", value: "other.example.com"},
		{header: "X-Forwarded-Prefix", value: "/admin"},
		{header: "Forwarded", value: "host=other.example.com"},
		{header: "X-Original-Host", value: "other.example.com"},
		{query: "_method=DELETE"},
		{query: "_METHOD=delete"},
	}
	for _, o := range overrides {
		r := request(t, http.MethodPost, "https://api.example.com/ok/x?"+o.query)
		r.Header.Set("Authorization", "Bearer "+testPlaceholder)
		if o.header != "" {
			r.Header[o.header] = []string{o.value} // as sent, not canonicalised
		}
		_, rej := p.Apply(r, "api.example.com")
		if rej == nil || rej.Reason != "routing_override" {
			t.Errorf("override %+v: rejection = %v, want routing_override", o, rej)
		}

		// Without a secret there is nothing to protect: forward as-is.
		r = request(t, http.MethodPost, "https://api.example.com/anything?"+o.query)
		if o.header != "" {
			r.Header[o.header] = []string{o.value}
		}
		if _, rej := p.Apply(r, "api.example.com"); rej != nil {
			t.Errorf("override %+v without a secret: rejected %v", o, rej)
		}
	}
}
