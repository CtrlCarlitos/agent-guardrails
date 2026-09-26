#!/bin/sh
# install.sh — install an exact, checksum-verified guardrail release, then
# hand off to `guardrail setup`. POSIX sh; Linux, macOS, WSL.
#
#   install.sh --version <tag> [--state enabled|disabled] [--dest <dir>]
#              [--base-url <url-or-dir>] [--no-setup]
#   install.sh --uninstall [--purge] [--dest <dir>] [--no-setup]
#   install.sh --help
#
# Exit codes: 2 usage / unsupported platform / missing tool; 1 download,
# checksum, install or post-install version failure, or an uninstall that
# could not disable the planes or remove a file; otherwise the exit code of
# `guardrail setup` (0 with --no-setup, and after an uninstall; a first
# install with no enrolled operator arms the planes and exits 0; 3 when the
# change needs the operator: no authenticator enrolled, no interactive terminal
# for an enrolled operator, the approval daemon not running, or the request
# denied or expired. The binary is installed and
# the planes keep what is registered; a caller may treat 3 as a warning).
set -eu

# Oldest release whose `guardrail update` is the sanctioned replacement path.
# A fixed historical constant, not a pin.
SELF_UPDATE_FLOOR=v0.19.2-dev
DEFAULT_BASE_URL=https://github.com/CtrlCarlitos/agent-guardrails/releases/download

version=""
state=enabled
state_given=0
dest=""
base_url=$DEFAULT_BASE_URL
run_setup=1
uninstall=0
purge=0
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
  install.sh --uninstall [--purge] [--dest <dir>] [--no-setup]
  install.sh --help

  --version <tag>     Exact release tag, e.g. v0.23.0-dev (required; 'latest' is not supported).
  --state <state>     enabled (default) or disabled.
  --dest <dir>        Install directory (default: $HOME/.local/bin).
  --base-url <base>   Release base: http(s) URL, file://<dir> or a directory
                      laid out as <base>/<tag>/<asset>
                      (default: https://github.com/CtrlCarlitos/agent-guardrails/releases/download).
  --no-setup          Stop once the binary is installed and verified; do not run `guardrail setup`.
                      With --uninstall: do not run `guardrail setup --state disabled` first.
  --uninstall         Disable every plane (`guardrail setup --state disabled`), then remove
                      the binary and the plugin file guardrail.js.
  --purge             With --uninstall: also remove guardrail's state, config and data directories.
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
			--state)
				state=$2
				state_given=1
				;;
			--dest) dest=$2 ;;
			--base-url) base_url=$2 ;;
			esac
			shift 2
			;;
		--no-setup)
			run_setup=0
			shift
			;;
		--uninstall)
			uninstall=1
			shift
			;;
		--purge)
			purge=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*) die 2 "unknown flag: $1 (see --help)" ;;
		esac
	done

	if [ "$purge" -eq 1 ] && [ "$uninstall" -eq 0 ]; then
		die 2 "--purge only works with --uninstall"
	fi
	if [ "$state_given" -eq 1 ] && [ "$uninstall" -eq 1 ]; then
		die 2 "--state cannot be combined with --uninstall"
	fi

	# --uninstall needs no release; a --version given anyway must still be valid.
	[ -n "$version" ] || [ "$uninstall" -eq 1 ] ||
		die 2 "--version is required: pass an exact release tag such as v0.23.0-dev ('latest' is not supported)"
	[ -z "$version" ] || valid_version "$version" || die 2 "--version must be an exact release tag such as v0.23.0-dev, got '$version' ('latest' is not supported)"

	case $state in
	enabled | disabled) ;;
	*) die 2 "--state must be enabled or disabled, got '$state'" ;;
	esac

	if [ -z "$dest" ]; then
		[ -n "${HOME:-}" ] || die 2 "HOME is not set; pass --dest <dir>"
		dest=$HOME/.local/bin
	fi
	# The plugin file and the state roots live under $HOME (or XDG_*).
	if [ "$uninstall" -eq 1 ] && [ -z "${HOME:-}" ]; then
		die 2 "HOME is not set; --uninstall needs it to find the plugin and state directories"
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

# sha_check <file>: verify the checksum lines in <file> (relative to the cwd).
# A file, not stdin: a BSD-compatible sha256sum may not read `-c -`.
sha_check() {
	if [ "$sha_tool" = shasum ]; then
		shasum -a 256 -c "$1"
	else
		"$sha_tool" -c "$1"
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
	printf '%s\n' "$line" >"$tmp/SHA256SUMS.one" || die 1 "cannot write $tmp/SHA256SUMS.one"
	(cd "$tmp" && sha_check SHA256SUMS.one) >/dev/null 2>&1 ||
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

# setup_supported: whether <dest>/guardrail has the `setup` subcommand.
# Probed as `setup --state disabled` with stdin not a terminal: disabling
# always needs a terminal, so a binary that has `setup` refuses before
# touching anything (exit 3 from #364 on, 2 before it, with "requires an
# interactive local terminal"), while one that predates it exits 2 with
# "unknown subcommand"; only that pair reads as unsupported. A bare
# `setup` would not do: with no operator enrolled it arms the planes
# (ADR-0030), and a probe must never have side effects. Probing first keeps
# the real run's output streaming and lets the hand-off exec.
setup_supported() {
	probe_rc=0
	probe_err=$("$dest/guardrail" setup --state disabled </dev/null 2>&1 >/dev/null) || probe_rc=$?
	if [ "$probe_rc" -eq 2 ]; then
		case $probe_err in *"unknown subcommand"*) return 1 ;; esac
	fi
	return 0
}

old_binary_hint="this guardrail predates 'setup'; re-run the installer with --version <a release that has it>"

handoff() {
	cleanup
	if [ "$run_setup" -eq 0 ]; then
		say "guardrail $version installed at $dest/guardrail (setup skipped)"
		# The steps still owed to the operator (#364). Best effort: a release
		# that predates `next` answers exit 2, which must not fail the install.
		"$dest/guardrail" next 2>/dev/null || true
		exit 0
	fi
	if ! setup_supported; then
		[ "$state" = disabled ] || die 1 "$old_binary_hint"
		say "this guardrail predates 'setup'; running guardrail plane disable --all"
		exec "$dest/guardrail" plane disable --all
	fi
	if [ "$state" = disabled ]; then
		exec "$dest/guardrail" setup --state disabled
	fi
	exec "$dest/guardrail" setup
}

# xdg_root <value> <default>: the XDG base directory to use. The XDG spec
# says a relative path is invalid and must be ignored; honouring one would
# point the removals below at the current directory.
xdg_root() {
	case $1 in
	/*) printf '%s\n' "$1" ;;
	*) printf '%s\n' "$2" ;;
	esac
}

# purge: remove every directory guardrail keeps state, config or data in.
purge() {
	for root in "$(xdg_root "${XDG_STATE_HOME:-}" "$HOME/.local/state")/guardrail" \
		"$(xdg_root "${XDG_CONFIG_HOME:-}" "$HOME/.config")/guardrail" \
		"$(xdg_root "${XDG_DATA_HOME:-}" "$HOME/.local/share")/guardrail"; do
		[ -e "$root" ] || continue
		rm -rf "$root" || die 1 "cannot remove $root"
		say "removed $root"
	done
}

# uninstall: disable every plane, then remove the binary and the plugin file
# (and, with --purge, every state root). Never downloads anything.
uninstall() {
	if [ ! -e "$dest/guardrail" ]; then
		say "nothing installed at $dest"
	else
		if [ "$run_setup" -eq 1 ]; then
			if setup_supported; then
				"$dest/guardrail" setup --state disabled ||
					die 1 "uninstall aborted: planes are still registered"
			else
				say "this guardrail predates 'setup'; running guardrail plane disable --all"
				"$dest/guardrail" plane disable --all ||
					die 1 "uninstall aborted: planes are still registered"
			fi
		fi
		rm -f "$dest/guardrail" || die 1 "cannot remove $dest/guardrail"
		# What `guardrail update` and bootstrap leave beside the binary.
		rm -f "$dest/guardrail.old" "$dest/.guardrail-update" "$dest/.guardrail.install" ||
			die 1 "cannot remove the update leftovers in $dest"
		plugin=$(xdg_root "${XDG_DATA_HOME:-}" "$HOME/.local/share")/guardrail/guardrail.js
		rm -f "$plugin" || die 1 "cannot remove $plugin"
		say "guardrail removed from $dest"
	fi
	if [ "$purge" -eq 1 ]; then
		purge
	fi
	exit 0
}

main() {
	parse_args "$@"
	if [ "$uninstall" -eq 1 ]; then
		uninstall
	fi
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
