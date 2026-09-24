#!/bin/sh
# install.sh — install an exact, checksum-verified guardrail release, then
# hand off to `guardrail setup`. POSIX sh; Linux, macOS, WSL.
#
#   install.sh --version <tag> [--state enabled|disabled] [--dest <dir>]
#              [--base-url <url-or-dir>] [--no-setup]
#   install.sh --help
#
# Exit codes: 2 usage / unsupported platform / missing tool; 1 download,
# checksum, install or post-install version failure; otherwise the exit code
# of `guardrail setup` (0 with --no-setup).
set -eu

# Oldest release whose `guardrail update` is the sanctioned replacement path.
# A fixed historical constant, not a pin.
SELF_UPDATE_FLOOR=v0.19.2-dev
DEFAULT_BASE_URL=https://github.com/CtrlCarlitos/agent-guardrails/releases/download

version=""
state=enabled
dest=""
base_url=$DEFAULT_BASE_URL
run_setup=1
asset=""
installed=""
tmp=""

say() { printf 'install: %s\n' "$*"; }
# die <exit-code> <message>
die() {
	code=$1
	shift
	printf 'install: %s\n' "$*" >&2
	exit "$code"
}

cleanup() {
	if [ -n "$tmp" ]; then
		rm -rf "$tmp"
		tmp=""
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
	cat <<'USAGE'
Usage:
  install.sh --version <tag> [--state enabled|disabled] [--dest <dir>]
             [--base-url <url-or-dir>] [--no-setup]
  install.sh --help

  --version <tag>     Exact release tag, e.g. v0.23.0-dev (required; 'latest' is not supported).
  --state <state>     enabled (default) or disabled.
  --dest <dir>        Install directory (default: $HOME/.local/bin).
  --base-url <base>   Release base: http(s) URL, file://<dir> or a directory
                      laid out as <base>/<tag>/<asset>
                      (default: https://github.com/CtrlCarlitos/agent-guardrails/releases/download).
  --no-setup          Stop once the binary is installed and verified; do not run `guardrail setup`.
USAGE
}

# valid_version <string>: exact release tag, nothing else.
valid_version() {
	case $1 in
	'' | *[!0-9A-Za-z.-]*) return 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
}

# version_at_least <a> <b>: a >= b on MAJOR.MINOR.PATCH; any -suffix is ignored.
# Both arguments must already satisfy valid_version.
version_at_least() {
	a=${1#v}
	a=${a%%-*}
	b=${2#v}
	b=${b%%-*}
	for _ in 1 2 3; do
		af=${a%%.*}
		bf=${b%%.*}
		[ "$af" -gt "$bf" ] && return 0
		[ "$af" -lt "$bf" ] && return 1
		a=${a#*.}
		b=${b#*.}
	done
	return 0
}

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--version | --state | --dest | --base-url)
			[ $# -ge 2 ] || die 2 "$1 needs a value (see --help)"
			case $1 in
			--version) version=$2 ;;
			--state) state=$2 ;;
			--dest) dest=$2 ;;
			--base-url) base_url=$2 ;;
			esac
			shift 2
			;;
		--no-setup)
			run_setup=0
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*) die 2 "unknown flag: $1 (see --help)" ;;
		esac
	done

	[ -n "$version" ] || die 2 "--version is required: pass an exact release tag such as v0.23.0-dev ('latest' is not supported)"
	valid_version "$version" || die 2 "--version must be an exact release tag such as v0.23.0-dev, got '$version' ('latest' is not supported)"

	case $state in
	enabled | disabled) ;;
	*) die 2 "--state must be enabled or disabled, got '$state'" ;;
	esac

	if [ -z "$dest" ]; then
		[ -n "${HOME:-}" ] || die 2 "HOME is not set; pass --dest <dir>"
		dest=$HOME/.local/bin
	fi

	case $base_url in
	http://* | https://*) ;;
	file://*)
		base_url=${base_url#file://}
		[ -d "$base_url" ] || die 2 "--base-url file://$base_url is not a directory"
		;;
	*) [ -d "$base_url" ] || die 2 "--base-url must be an http(s):// URL, a file:// URL or an existing directory, got '$base_url'" ;;
	esac
	base_url=${base_url%/}
}

resolve_platform() {
	os_raw=$(uname -s)
	arch_raw=$(uname -m)
	case $os_raw in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) os="" ;;
	esac
	case $arch_raw in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) arch="" ;;
	esac
	if [ -z "$os" ] || [ -z "$arch" ]; then
		die 2 "unsupported platform $os_raw/$arch_raw; supported: linux/darwin on amd64/arm64"
	fi
	asset=guardrail_${os}_${arch}
}

# probe_installed: sets $installed to the installed binary's version tag, or
# to "" when there is no usable binary at <dest>/guardrail.
probe_installed() {
	installed=""
	[ -x "$dest/guardrail" ] || return 0
	reported=$("$dest/guardrail" version 2>/dev/null) || reported=""
	case $reported in
	"guardrail "*) installed=${reported#guardrail } ;;
	esac
	valid_version "$installed" || installed=""
}

sha_tool=""
find_sha_tool() {
	for t in sha256sum gsha256sum shasum; do
		if command -v "$t" >/dev/null 2>&1; then
			sha_tool=$t
			return 0
		fi
	done
	die 2 "no SHA-256 tool found (need sha256sum, gsha256sum or shasum)"
}

sha_check() {
	if [ "$sha_tool" = shasum ]; then
		shasum -a 256 -c -
	else
		"$sha_tool" -c -
	fi
}

# fetch <file>: copy <base>/<version>/<file> into the temp dir.
fetch() {
	src=$base_url/$version/$1
	case $base_url in
	http://* | https://*) curl -fsSL --max-time 180 -o "$tmp/$1" "$src" ;;
	*) cp "$src" "$tmp/$1" ;;
	esac || die 1 "download failed: $src"
}

# verify: the downloaded asset matches its line in the release's SHA256SUMS.
verify() {
	line=$(grep " $asset\$" "$tmp/SHA256SUMS") ||
		die 1 "CHECKSUM MISMATCH: SHA256SUMS for $version has no entry for $asset; nothing installed"
	(cd "$tmp" && printf '%s\n' "$line" | sha_check) >/dev/null 2>&1 ||
		die 1 "CHECKSUM MISMATCH: $asset does not match SHA256SUMS for $version; nothing installed"
}

bootstrap() {
	find_sha_tool
	case $base_url in
	http://* | https://*)
		command -v curl >/dev/null 2>&1 || die 2 "curl is required to download from $base_url"
		;;
	esac
	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t guardrail-install) || die 1 "cannot create a temporary directory"

	say "downloading $asset $version from $base_url"
	fetch "$asset"
	fetch SHA256SUMS
	verify

	mkdir -p "$dest" || die 1 "cannot create $dest"
	# Stage beside the target and rename, so a running binary is never
	# overwritten in place and a failed copy never leaves a partial file.
	if ! { install -m 0755 "$tmp/$asset" "$dest/.guardrail.install" &&
		mv -f "$dest/.guardrail.install" "$dest/guardrail"; }; then
		rm -f "$dest/.guardrail.install"
		die 1 "failed to install $dest/guardrail"
	fi
	cleanup
}

verify_installed() {
	got=$("$dest/guardrail" version 2>/dev/null) || got=""
	[ "$got" = "guardrail $version" ] ||
		die 1 "$dest/guardrail did not report guardrail $version (got '$got')"
}

handoff() {
	cleanup
	if [ "$run_setup" -eq 0 ]; then
		say "guardrail $version installed at $dest/guardrail (setup skipped)"
		exit 0
	fi
	if [ "$state" = disabled ]; then
		exec "$dest/guardrail" setup --state disabled
	fi
	exec "$dest/guardrail" setup
}

main() {
	parse_args "$@"
	resolve_platform
	probe_installed

	if [ "$state" = disabled ]; then
		# No download ever happens when disabling.
		if [ ! -x "$dest/guardrail" ]; then
			say "no guardrail at $dest/guardrail; nothing to do"
			exit 0
		fi
		if [ "$run_setup" -eq 0 ]; then
			say "guardrail found at $dest/guardrail (setup --state disabled skipped)"
			exit 0
		fi
		handoff
	fi

	if [ "$installed" = "$version" ]; then
		say "guardrail $version already installed at $dest/guardrail"
	elif [ -n "$installed" ] && version_at_least "$installed" "$SELF_UPDATE_FLOOR"; then
		say "updating $dest/guardrail from $installed to $version via guardrail update"
		"$dest/guardrail" update "$version" || die 1 "guardrail update $version failed; $dest/guardrail left as it was"
	else
		bootstrap
	fi

	verify_installed
	handoff
}

main "$@"
