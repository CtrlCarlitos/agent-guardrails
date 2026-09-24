#!/usr/bin/env bash
# Hermetic harness for install.sh: stages a release from $DIST into a temp
# directory and runs every case with `--base-url <tmp>/releases --no-setup`.
# Prints PASS:/FAIL:/SKIP: per case and exits 1 on any FAIL. `make installer-test`.
# Portable to the bash 3.2 that macOS ships.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-$repo_root/install.sh}"
VERSION="${VERSION:-v0.0.0-ci}"
: "${DIST:?set DIST to a directory holding the guardrail_* assets and SHA256SUMS (VERSION=$VERSION ./scripts/build-dist.sh)}"

[ -f "$DIST/SHA256SUMS" ] || { echo "FAIL: setup: $DIST/SHA256SUMS missing"; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- staging ----------------------------------------------------------------
stage() { # $1 = releases root; copies the six assets (+ SHA256SUMS unless $2 = nosums)
  mkdir -p "$1/$VERSION"
  cp "$DIST"/guardrail_* "$1/$VERSION/"
  [ "${2:-}" = nosums ] || cp "$DIST/SHA256SUMS" "$1/$VERSION/"
}
stage "$tmp/releases"
stage "$tmp/tampered"
stage "$tmp/nosums" nosums
mkdir -p "$tmp/empty"

case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) os=unsupported ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch=unsupported ;; esac
asset="guardrail_${os}_${arch}"

# Flip the first hex digit of this platform's hash line.
sed -e "/ $asset\$/ s/^0/_/; / $asset\$/ s/^[1-9a-f]/0/; / $asset\$/ s/^_/1/" \
  "$DIST/SHA256SUMS" > "$tmp/tampered/$VERSION/SHA256SUMS"
if cmp -s "$DIST/SHA256SUMS" "$tmp/tampered/$VERSION/SHA256SUMS"; then
  echo "FAIL: setup: could not tamper the $asset line of SHA256SUMS"; exit 1
fi

# --- helpers ----------------------------------------------------------------
n=0
out="" err="" rc=0
run() { # run install.sh with the given args; sets out, err, rc
  n=$((n + 1))
  rc=0
  sh "$INSTALL_SH" "$@" >"$tmp/out.$n" 2>"$tmp/err.$n" || rc=$?
  out="$(cat "$tmp/out.$n")"
  err="$(cat "$tmp/err.$n")"
}
fresh() { mktemp -d "$tmp/dest.XXXXXX"; }
want_rc() { [ "$rc" -eq "$1" ] || { echo "  exit $rc, want $1"; dump; return 1; }; }
dump() { echo "  stdout: $out"; echo "  stderr: $err"; }
has() { # $1 = haystack name (out|err), $2 = needle
  local text
  if [ "$1" = out ]; then text="$out"; else text="$err"; fi
  case "$text" in *"$2"*) return 0 ;; esac
  echo "  $1 lacks: $2"; dump; return 1
}
reports() { # $1 = binary, $2 = version
  local got
  got="$("$1" version 2>/dev/null || true)"
  [ "$got" = "guardrail $2" ] || { echo "  $1 version printed '$got', want 'guardrail $2'"; return 1; }
}
is_empty() { [ -z "$(ls -A "$1")" ] || { echo "  $1 not empty:"; ls -A "$1"; return 1; }; }
absent() { [ ! -e "$1" ] || { echo "  $1 exists"; return 1; }; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

fake_guardrail() { # $1 = dest, $2 = version the fake reports
  mkdir -p "$1"
  cat >"$1/guardrail" <<'FAKE'
#!/bin/sh
d="$(dirname "$0")"
case "$1" in
  version) echo "guardrail $(cat "$d/.fake-version")" ;;
  update) echo "$*" >>"$d/update.log"; echo "$2" >"$d/.fake-version" ;;
  setup) exit 0 ;;
  *) exit 2 ;;
esac
FAKE
  chmod 0755 "$1/guardrail"
  echo "$2" >"$1/.fake-version"
}

# --- cases ------------------------------------------------------------------
boot_dest=""
case_bootstrap_installs_and_verifies() {
  boot_dest="$(fresh)"
  run --version "$VERSION" --dest "$boot_dest" --base-url "$tmp/releases" --no-setup
  want_rc 0 || return 1
  reports "$boot_dest/guardrail" "$VERSION" || return 1
  [ "$(mode_of "$boot_dest/guardrail")" = 755 ] || { echo "  mode $(mode_of "$boot_dest/guardrail"), want 755"; return 1; }
}

case_already_at_version_skips_download() {
  if [ -z "$boot_dest" ] || [ ! -x "$boot_dest/guardrail" ]; then echo "  needs bootstrap-installs-and-verifies"; return 1; fi
  run --version "$VERSION" --dest "$boot_dest" --base-url "$tmp/empty" --no-setup
  want_rc 0 || return 1
  has out "already installed" || return 1
  reports "$boot_dest/guardrail" "$VERSION"
}

case_latest_is_rejected() {
  local dest="$tmp/latest-dest"
  run --version latest --dest "$dest" --base-url "$tmp/releases" --no-setup
  want_rc 2 || return 1
  has err "exact release tag" || return 1
  absent "$dest"
}

case_tampered_checksum_refuses() {
  local dest="$tmp/tampered-dest"
  run --version "$VERSION" --dest "$dest" --base-url "$tmp/tampered" --no-setup
  want_rc 1 || return 1
  has err "CHECKSUM MISMATCH" || return 1
  absent "$dest/guardrail"
}

case_missing_sums_refuses() {
  local dest="$tmp/nosums-dest"
  run --version "$VERSION" --dest "$dest" --base-url "$tmp/nosums" --no-setup
  want_rc 1 || return 1
  absent "$dest"
}

case_disabled_with_no_binary_is_noop() {
  local dest
  dest="$(fresh)"
  run --version "$VERSION" --state disabled --dest "$dest" --base-url "$tmp/empty" --no-setup
  want_rc 0 || return 1
  has out "nothing to do" || return 1
  is_empty "$dest"
}

case_existing_at_or_above_floor_uses_self_update() {
  local dest
  dest="$(fresh)"
  fake_guardrail "$dest" v0.19.2-dev
  run --version "$VERSION" --dest "$dest" --base-url "$tmp/empty" --no-setup
  want_rc 0 || return 1
  grep -qx "update $VERSION" "$dest/update.log" 2>/dev/null || { echo "  update.log lacks 'update $VERSION'"; dump; return 1; }
  # still the fake: no asset was fetched or installed over it
  grep -q '\.fake-version' "$dest/guardrail" || { echo "  $dest/guardrail was replaced"; return 1; }
}

case_existing_below_floor_bootstraps() {
  local dest
  dest="$(fresh)"
  fake_guardrail "$dest" v0.3.0
  run --version "$VERSION" --dest "$dest" --base-url "$tmp/releases" --no-setup
  want_rc 0 || return 1
  reports "$dest/guardrail" "$VERSION" || return 1
  absent "$dest/update.log"
}

case_unsupported_arch_exits_2() {
  local dest fakebin="$tmp/fakebin"
  dest="$tmp/mips-dest"
  mkdir -p "$fakebin"
  cat >"$fakebin/uname" <<'FAKE'
#!/bin/sh
case "$1" in -s) echo Linux ;; -m) echo mips ;; *) echo Linux ;; esac
FAKE
  chmod 0755 "$fakebin/uname"
  PATH="$fakebin:$PATH" run --version "$VERSION" --dest "$dest" --base-url "$tmp/releases" --no-setup
  want_rc 2 || return 1
  has err "amd64/arm64" || return 1
  absent "$dest"
}

fails=0
check() { # $1 = case label, $2 = function
  if "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fails=$((fails + 1)); fi
}

check bootstrap-installs-and-verifies            case_bootstrap_installs_and_verifies
check already-at-version-skips-download          case_already_at_version_skips_download
check latest-is-rejected                         case_latest_is_rejected
check tampered-checksum-refuses                  case_tampered_checksum_refuses
check missing-sums-refuses                       case_missing_sums_refuses
check disabled-with-no-binary-is-noop            case_disabled_with_no_binary_is_noop
check existing-at-or-above-floor-uses-self-update case_existing_at_or_above_floor_uses_self_update
check existing-below-floor-bootstraps            case_existing_below_floor_bootstraps
check unsupported-arch-exits-2                   case_unsupported_arch_exits_2

if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -s sh "$INSTALL_SH"; then echo "PASS: shellcheck"; else echo "FAIL: shellcheck"; fails=$((fails + 1)); fi
else
  echo "SKIP: shellcheck (not installed)"
fi

[ "$fails" -eq 0 ] || { echo "$fails case(s) failed"; exit 1; }
echo "ALL PASS"
