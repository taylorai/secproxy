#!/usr/bin/env bash
# gofmt, go vet and the unit tests, as one hook so the Go toolchain is only
# located once. Runs on the whole module regardless of which files changed;
# the module is small and Go's build cache keeps this fast.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"

unformatted="$(gofmt -l . 2>/dev/null || true)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt: these files need formatting (run: gofmt -w .)" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./...
