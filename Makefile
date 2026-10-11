GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint linux clean

build:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o secproxy ./cmd/secproxy

test:
	$(GO) vet ./... && $(GO) test -race ./...

lint:
	gofmt -l . && test -z "$$(gofmt -l .)"

# Static Linux binaries, the form a container image or a sidecar wants.
linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/secproxy-linux-amd64 ./cmd/secproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/secproxy-linux-arm64 ./cmd/secproxy

clean:
	rm -rf secproxy dist
