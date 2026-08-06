#!/bin/sh
# Install the sbx-warden server and/or the sbx client from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.sh | sh -s -- --client
#
# The server (sbx-warden) runs on your host; the client (sbx) belongs inside a
# sandbox. Both are installed by default.

set -eu

REPO="cdupuis/sbx-warden"
API="https://api.github.com/repos/${REPO}"
# SBX_WARDEN_DOWNLOAD_BASE points the installer at a mirror holding the same
# release layout, for air-gapped installs and for testing this script.
DOWNLOADS="${SBX_WARDEN_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"

components="${SBX_WARDEN_COMPONENTS:-both}"
requested_version="${SBX_WARDEN_VERSION:-}"
install_dir="${SBX_WARDEN_INSTALL_DIR:-}"
force=""
tmpdir=""

info() { printf '%s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
	[ -n "$tmpdir" ] && [ -d "$tmpdir" ] && rm -rf "$tmpdir"
	return 0
}
trap cleanup EXIT HUP INT TERM

usage() {
	cat <<'EOF'
Usage: install.sh [options]

Options:
  --client            Install only the sbx client (for use inside a sandbox)
  --server            Install only the sbx-warden server (for your host)
  --version VERSION   Install a specific release instead of the latest
  --dir DIRECTORY     Install into DIRECTORY
  --force             Replace an existing sbx that is not an sbx-warden client
  -h, --help          Show this help

Environment:
  SBX_WARDEN_COMPONENTS      both (default), client or server
  SBX_WARDEN_VERSION         release to install, e.g. v0.1.0
  SBX_WARDEN_INSTALL_DIR     installation directory
  SBX_WARDEN_DOWNLOAD_BASE   mirror serving the release archives
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--client) components="client" ;;
	--server) components="server" ;;
	--both) components="both" ;;
	--force) force="yes" ;;
	--version)
		[ $# -ge 2 ] || die "--version needs a value"
		requested_version="$2"
		shift
		;;
	--dir)
		[ $# -ge 2 ] || die "--dir needs a value"
		install_dir="$2"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1 (try --help)" ;;
	esac
	shift
done

case "$components" in
both | client | server) ;;
*) die "components must be both, client or server, got: $components" ;;
esac

detect_os() {
	detect_os_uname="$(uname -s)"
	case "$detect_os_uname" in
	Linux) printf 'linux\n' ;;
	Darwin) printf 'darwin\n' ;;
	*) die "unsupported operating system: $detect_os_uname (use install.ps1 on Windows)" ;;
	esac
}

detect_arch() {
	detect_arch_uname="$(uname -m)"
	case "$detect_arch_uname" in
	x86_64 | amd64) printf 'amd64\n' ;;
	aarch64 | arm64) printf 'arm64\n' ;;
	*) die "unsupported architecture: $detect_arch_uname" ;;
	esac
}

http_get() {
	if have curl; then
		curl -fsSL --retry 3 "$1"
	elif have wget; then
		wget -qO- "$1"
	else
		die "need curl or wget to download files"
	fi
}

download() {
	if have curl; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif have wget; then
		wget -qO "$2" "$1"
	else
		die "need curl or wget to download files"
	fi
}

sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have openssl; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		die "need sha256sum, shasum or openssl to verify the download"
	fi
}

resolve_tag() {
	if [ -n "$requested_version" ]; then
		case "$requested_version" in
		v*) printf '%s\n' "$requested_version" ;;
		*) printf 'v%s\n' "$requested_version" ;;
		esac
		return 0
	fi
	resolve_tag_body="$(http_get "${API}/releases/latest")" ||
		die "could not query the latest release of ${REPO}"
	resolve_tag_value="$(
		printf '%s\n' "$resolve_tag_body" | tr ',' '\n' |
			sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
	)"
	[ -n "$resolve_tag_value" ] || die "could not determine the latest release tag of ${REPO}"
	printf '%s\n' "$resolve_tag_value"
}

resolve_install_dir() {
	if [ -n "$install_dir" ]; then
		mkdir -p "$install_dir" || die "cannot create $install_dir"
		printf '%s\n' "$install_dir"
		return 0
	fi
	if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		printf '/usr/local/bin\n'
		return 0
	fi
	# No sudo: stdin is the script itself when piped from curl, so a password
	# prompt could never be answered.
	resolve_install_dir_fallback="${HOME}/.local/bin"
	mkdir -p "$resolve_install_dir_fallback" ||
		die "cannot create $resolve_install_dir_fallback; set SBX_WARDEN_INSTALL_DIR"
	printf '%s\n' "$resolve_install_dir_fallback"
}

# is_our_client reports whether a path holds an sbx-warden client rather than the
# real Docker Sandboxes CLI, so an upgrade can be told apart from a collision.
is_our_client() {
	[ -f "$1" ] && [ -x "$1" ] || return 1
	SBX_WARDEN_PRINT_VERSION=1 "$1" 2>/dev/null | head -1 | grep -q '^sbx-warden client '
}

fetch_archive() {
	fetch_archive_name="$1"
	fetch_archive_url="${DOWNLOADS}/${tag}/${fetch_archive_name}"
	info "downloading ${fetch_archive_name}"
	download "$fetch_archive_url" "${tmpdir}/${fetch_archive_name}" ||
		die "could not download ${fetch_archive_url}"

	fetch_archive_expected="$(
		awk -v want="$fetch_archive_name" '$2 == want {print $1; exit}' "${tmpdir}/checksums.txt"
	)"
	[ -n "$fetch_archive_expected" ] ||
		die "${fetch_archive_name} is not listed in checksums.txt for ${tag}"
	fetch_archive_actual="$(sha256_of "${tmpdir}/${fetch_archive_name}")"
	[ "$fetch_archive_expected" = "$fetch_archive_actual" ] ||
		die "checksum mismatch for ${fetch_archive_name}: expected ${fetch_archive_expected}, got ${fetch_archive_actual}"

	tar -xzf "${tmpdir}/${fetch_archive_name}" -C "$tmpdir" ||
		die "could not extract ${fetch_archive_name}"
}

install_binary() {
	install_binary_name="$1"
	[ -f "${tmpdir}/${install_binary_name}" ] ||
		die "${install_binary_name} missing from the release archive"
	chmod 0755 "${tmpdir}/${install_binary_name}"
	# Replace via a temporary name so a running binary is not written in place.
	cp "${tmpdir}/${install_binary_name}" "${dir}/${install_binary_name}.new" ||
		die "cannot write to ${dir}; set SBX_WARDEN_INSTALL_DIR to a writable directory"
	mv -f "${dir}/${install_binary_name}.new" "${dir}/${install_binary_name}"
	info "installed ${dir}/${install_binary_name}"
}

os="$(detect_os)"
arch="$(detect_arch)"
tag="$(resolve_tag)"
version="${tag#v}"
dir="$(resolve_install_dir)"

tmpdir="$(mktemp -d)" || die "could not create a temporary directory"

info "sbx-warden ${tag} for ${os}/${arch} into ${dir}"
download "${DOWNLOADS}/${tag}/checksums.txt" "${tmpdir}/checksums.txt" ||
	die "could not download checksums for ${tag}"

installed_server=""
installed_client=""

if [ "$components" = "both" ] || [ "$components" = "server" ]; then
	fetch_archive "sbx-warden_${version}_${os}_${arch}.tar.gz"
	install_binary "sbx-warden"
	installed_server="yes"
fi

if [ "$components" = "both" ] || [ "$components" = "client" ]; then
	target="${dir}/sbx"
	skip_client=""

	if [ -e "$target" ] && ! is_our_client "$target"; then
		if [ -n "$force" ]; then
			warn "replacing ${target}, which is not an sbx-warden client"
		elif [ "$components" = "client" ]; then
			die "${target} exists and is not an sbx-warden client; pass --force to replace it or --dir to install elsewhere"
		else
			warn "skipping the client: ${target} exists and is not an sbx-warden client"
			warn "the client is only needed inside a sandbox; install it there, or pass --force"
			skip_client="yes"
		fi
	fi

	if [ -z "$skip_client" ]; then
		fetch_archive "sbx-client_${version}_${os}_${arch}.tar.gz"
		install_binary "sbx"
		installed_client="yes"

		# A different sbx earlier in PATH wins, so the client would never run.
		shadowed="$(command -v sbx 2>/dev/null || true)"
		if [ -n "$shadowed" ] && [ "$shadowed" != "$target" ]; then
			warn "${shadowed} comes first in PATH, so ${target} will not be used"
		fi
	fi
fi

case ":${PATH}:" in
*":${dir}:"*) ;;
*) warn "${dir} is not in PATH; add it with: export PATH=\"${dir}:\$PATH\"" ;;
esac

info ""
if [ -n "$installed_server" ]; then
	info "Start the server on your host:"
	info "  sbx-warden --addr 127.0.0.1:7391"
	info ""
	info "Then grant a sandbox and allow the port for it:"
	info "  sbx-warden grant SANDBOX"
	info "  sbx policy allow network localhost:7391 --sandbox SANDBOX"
fi
if [ -n "$installed_client" ]; then
	info ""
	info "Point the client at the host from inside a sandbox:"
	info "  export SBX_WARDEN_ADDR=host.docker.internal:7391"
	info ""
	info "SBX_WARDEN_TOKEN is set by \"sbx-warden grant\" on the host; the sandbox"
	info "has to be granted before it is created."
fi
