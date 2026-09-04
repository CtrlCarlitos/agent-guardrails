GO ?= /usr/local/go/bin/go
VERSION ?= dev
CGO_ENABLED ?= 0

.PHONY: build test fmt contract
build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o guardrail ./cmd/guardrail

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

contract:
	$(GO) test ./test/ -v

.PHONY: golden
golden:
	$(GO) test ./test/ -run Golden -update
