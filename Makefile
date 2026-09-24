GO ?= /usr/local/go/bin/go
VERSION ?= dev
CGO_ENABLED ?= 0

.PHONY: build test fmt contract golden vet adversarial check dist smoke installer-test

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o guardrail ./cmd/guardrail

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: test vet adversarial
	@test -z "$$($(GO) run cmd/gofmt -l . 2>/dev/null || gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

adversarial:
	$(GO) test ./test/adversarial/ -v

contract:
	$(GO) test ./test/ -v

golden:
	$(GO) test ./test/ -run Golden -update

dist:
	./scripts/build-dist.sh

# Builds dist/ at a fixed version so the harness can match the binary's
# `version` output (the dist target's git-describe version would not).
installer-test:
	VERSION=v0.0.0-ci ./scripts/build-dist.sh
	VERSION=v0.0.0-ci DIST=dist bash test/installer/install_sh_test.sh

smoke:
	./test/smoke/claude_smoke.sh
