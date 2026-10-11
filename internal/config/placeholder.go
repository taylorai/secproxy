package config

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// NewPlaceholder returns a random placeholder for the named secret, such as
// "sp_github_k7f3m9q2x8w4v1n6b0c5z2jd". The name is included so a human
// reading a request log or an error message can tell which secret the
// sandbox tried to use; the random tail is what makes it useless elsewhere.
func NewPlaceholder(name string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	tail := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, strings.ToLower(name))
	return fmt.Sprintf("sp_%s_%s", safe, tail)
}

// FillPlaceholders generates a placeholder for every secret that does not
// already have one. Call after Parse when the config is authored by hand;
// an orchestrator that needs to know the placeholders up front should set
// them in the config instead.
func (c *Config) FillPlaceholders() {
	for name, s := range c.Secrets {
		if s.Placeholder == "" {
			s.Placeholder = NewPlaceholder(name)
			c.Secrets[name] = s
		}
	}
}
