package main

import (
	"context"
	"testing"
)

func TestRunChildOverlaysEnvironmentAndReturnsExitCode(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "real-parent-value")
	code, err := runChild(context.Background(), []string{
		"/bin/sh", "-c", `if [ "$GITHUB_TOKEN" = "placeholder-child-value" ]; then echo "$GITHUB_TOKEN"; exit 3; else exit 4; fi`,
	}, map[string]string{"GITHUB_TOKEN": "placeholder-child-value"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Fatalf("runChild exit code = %d, want 3", code)
	}
}

func TestRunChildHidesSourceSecrets(t *testing.T) {
	t.Setenv("SP_GITHUB_TOKEN", "the-real-one")
	t.Setenv("SECPROXY_CONFIG", "yaml")
	code, err := runChild(context.Background(), []string{
		"/bin/sh", "-c", `if [ -z "$SP_GITHUB_TOKEN" ] && [ -z "$SECPROXY_CONFIG" ] && [ "$GITHUB_TOKEN" = "ph" ]; then exit 0; else exit 9; fi`,
	}, map[string]string{"GITHUB_TOKEN": "ph"}, []string{"SP_GITHUB_TOKEN", "SECPROXY_CONFIG"})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("child still saw a hidden variable (exit %d)", code)
	}
}
