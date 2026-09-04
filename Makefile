GO ?= /usr/local/go/bin/go
VERSION ?= dev

.PHONY: build test fmt
build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o guardrail ./cmd/guardrail

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...
