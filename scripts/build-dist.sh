#!/usr/bin/env bash
# Cross-compile the guardrail binary for every supported platform into dist/,
# copy install.sh and install.ps1 beside them, and emit dist/SHA256SUMS over
# all eight assets. Used by `make dist` and by .github/workflows/release.yml.
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

cp install.sh install.ps1 "$OUT/"

# sha256sum on Linux and Git Bash; macOS runners only ship shasum.
if command -v sha256sum >/dev/null 2>&1; then
  sha=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  sha=(shasum -a 256)
else
  echo "build-dist: need sha256sum or shasum" >&2; exit 1
fi
# Git Bash's sha256sum on Windows CI defaults to binary mode outside a tty
# and prints "hash *name"; normalize that to "hash  name" (two spaces) like
# every other tool/OS combo, so install.ps1's checksum-line parsing and the
# test harness's tamper logic (which matches on the trailing " name") agree.
( cd "$OUT" && "${sha[@]}" guardrail_* install.sh install.ps1 | sed 's/ \*/  /' > SHA256SUMS )
echo "---"
cat "$OUT/SHA256SUMS"
