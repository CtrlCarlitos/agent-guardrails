#!/usr/bin/env bash
# Cross-compile the guardrail binary for every supported platform into dist/
# and emit dist/SHA256SUMS. Used by `make dist` and by .github/workflows/release.yml.
set -euo pipefail

GO="${GO:-go}"
command -v "$GO" >/dev/null || GO=/usr/local/go/bin/go

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
OUT="dist"
rm -rf "$OUT"
mkdir -p "$OUT"

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for t in $targets; do
  goos="${t%/*}"; goarch="${t#*/}"
  ext=""; [ "$goos" = "windows" ] && ext=".exe"
  name="guardrail_${goos}_${goarch}${ext}"
  echo "building $name ($VERSION)"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "$GO" build \
    -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$OUT/$name" ./cmd/guardrail
done

( cd "$OUT" && sha256sum guardrail_* > SHA256SUMS )
echo "---"
cat "$OUT/SHA256SUMS"
