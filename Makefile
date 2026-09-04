GO ?= /usr/local/go/bin/go
VERSION ?= dev
CGO_ENABLED ?= 0

.PHONY: build test fmt contract golden vet check dist

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o guardrail ./cmd/guardrail

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: test vet
	@test -z "$$($(GO) run cmd/gofmt -l . 2>/dev/null || gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

contract:
	$(GO) test ./test/ -v

golden:
	$(GO) test ./test/ -run Golden -update

dist:
	./scripts/build-dist.sh
