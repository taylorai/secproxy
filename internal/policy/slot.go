package policy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/taylorai/secproxy/internal/config"
)

// slotState is what a binding's slot held when the request arrived.
type slotState int

const (
	slotEmpty       slotState = iota // nothing there at all
	slotPlaceholder                  // exactly the placeholder, formatted
	slotOther                        // something else: a real credential, a typo, two values
)

// probeSlot looks at the one place a binding's slot points to and reports
// what it holds. The returned func writes the real value into the slot; the
// caller decides whether to run it, after method and path checks pass.
//
// slotPlaceholder means "exactly", deliberately. A header slot with format
// "Bearer {secret}" matches the header value "Bearer <placeholder>" and
// nothing else. A placeholder that appears as a substring of something
// larger, or in a different header, is slotOther here and will be caught by
// findStrayPlaceholder as a misuse.
func probeSlot(slot config.Slot, req *http.Request, sec *secret) (slotState, func()) {
	switch {
	case slot.Header != nil:
		return probeHeader(slot.Header, req, sec)
	case slot.Basic != nil:
		return probeBasic(slot.Basic, req, sec)
	case slot.Query != nil:
		return probeQuery(slot.Query, req, sec)
	}
	return slotOther, nil
}

func probeHeader(h *config.HeaderSlot, req *http.Request, sec *secret) (slotState, func()) {
	substitute := func() {
		req.Header.Set(h.Name, strings.ReplaceAll(h.Format, "{secret}", sec.value))
	}
	vals := req.Header.Values(h.Name)
	if len(vals) == 0 {
		return slotEmpty, substitute
	}
	want := strings.ReplaceAll(h.Format, "{secret}", sec.placeholder)
	if len(vals) != 1 || vals[0] != want {
		return slotOther, substitute
	}
	return slotPlaceholder, substitute
}

// probeBasic decodes "Authorization: Basic <base64(user:pass)>" and compares
// the user and password against the templates with the placeholder filled
// in. Git, and anything using credentials in a URL, sends secrets this way.
// Any Authorization header that is not the expected Basic value, a Bearer
// token say, is slotOther: the slot is occupied.
func probeBasic(b *config.BasicSlot, req *http.Request, sec *secret) (slotState, func()) {
	substitute := func() {
		req.Header.Set("Authorization", "Basic "+basicToken(b, sec.value))
	}
	vals := req.Header.Values("Authorization")
	if len(vals) == 0 {
		return slotEmpty, substitute
	}
	if len(vals) != 1 {
		return slotOther, substitute
	}
	const prefix = "Basic "
	if !strings.HasPrefix(vals[0], prefix) {
		return slotOther, substitute
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(vals[0][len(prefix):]))
	if err != nil {
		return slotOther, substitute
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return slotOther, substitute
	}
	wantUser := strings.ReplaceAll(b.Username, "{secret}", sec.placeholder)
	wantPass := strings.ReplaceAll(b.Password, "{secret}", sec.placeholder)
	if user != wantUser || pass != wantPass {
		return slotOther, substitute
	}
	return slotPlaceholder, substitute
}

// probeQuery checks the named query parameter. Substitution rebuilds the
// query string, which is fine: order of parameters carries no meaning.
func probeQuery(q *config.QuerySlot, req *http.Request, sec *secret) (slotState, func()) {
	values := req.URL.Query()
	substitute := func() {
		values.Set(q.Param, sec.value)
		req.URL.RawQuery = values.Encode()
	}
	got := values[q.Param]
	if len(got) == 0 {
		return slotEmpty, substitute
	}
	if len(got) != 1 || got[0] != sec.placeholder {
		return slotOther, substitute
	}
	return slotPlaceholder, substitute
}

func describeSlot(slot config.Slot) string {
	switch {
	case slot.Header != nil:
		return fmt.Sprintf("header %s (%s)", slot.Header.Name, slot.Header.Format)
	case slot.Basic != nil:
		return "basic auth"
	case slot.Query != nil:
		return fmt.Sprintf("query param %s", slot.Query.Param)
	}
	return "?"
}
