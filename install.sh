#!/bin/sh
# saiife installer.
#
#   curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --system     # /usr/local/bin, sudo if needed
#
# Environment:
#   SAIIFE_VERSION        version to install, e.g. 0.1.0 (default: latest)
#   SAIIFE_INSTALL_DIR    install directory (default: $HOME/.local/bin)
#   SAIIFE_DOWNLOAD_BASE  override the release download base URL
#
# The tarball is verified against the release's SHA256SUMS before anything is
# installed. Supported: Linux and macOS on x86_64 and aarch64.
set -eu

REPO_URL="https://github.com/HrRobinson/saiife"

err() {
  echo "saiife: $*" >&2
}

die() {
  err "$@"
  exit 1
}

usage() {
  cat <<'EOF'
Usage: install.sh [--system]

  --system   install to /usr/local/bin (uses sudo only if that is not writable)

Environment: SAIIFE_VERSION, SAIIFE_INSTALL_DIR, SAIIFE_DOWNLOAD_BASE
EOF
}

detect_target() {
  os="$(uname -s)"
  machine="$(uname -m)"
  case "$machine" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=aarch64 ;;
    *) die "unsupported platform: $os/$machine" ;;
  esac
  case "$os" in
    Linux) target="$arch-unknown-linux-musl" ;;
    Darwin) target="$arch-apple-darwin" ;;
    *) die "unsupported platform: $os/$machine" ;;
  esac
}

pick_downloader() {
  if command -v curl >/dev/null 2>&1; then
    downloader=curl
  elif command -v wget >/dev/null 2>&1; then
    downloader=wget
  else
    die "curl or wget is required to download saiife"
  fi
}

# download <url> <dest>
download() {
  case "$downloader" in
    curl)
      if [ -n "${SAIIFE_DOWNLOAD_BASE:-}" ]; then
        curl -fsSL -o "$2" "$1"
      else
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
      fi
      ;;
    wget)
      wget -q -O "$2" "$1"
      ;;
  esac
}

# sha256_check <sums-file>, run inside the download dir.
sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1" >/dev/null 2>&1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$1" >/dev/null 2>&1
  else
    die "sha256sum or shasum is required to verify the download"
  fi
}

# as_root <cmd...>: run directly, or through sudo when $sudo is set.
as_root() {
  if [ -n "$sudo" ]; then
    sudo "$@"
  else
    "$@"
  fi
}

main() {
  system=0
  for arg in "$@"; do
    case "$arg" in
      --system) system=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "unknown option: $arg"
        ;;
    esac
  done

  # Platform first: an unsupported machine never downloads anything.
  detect_target
  pick_downloader

  if [ "$system" -eq 1 ]; then
    install_dir=/usr/local/bin
  elif [ -n "${SAIIFE_INSTALL_DIR:-}" ]; then
    install_dir="$SAIIFE_INSTALL_DIR"
  else
    [ -n "${HOME:-}" ] || die "HOME is not set; set SAIIFE_INSTALL_DIR"
    install_dir="$HOME/.local/bin"
  fi

  version="${SAIIFE_VERSION:-}"
  version="${version#v}"
  if [ -n "${SAIIFE_DOWNLOAD_BASE:-}" ]; then
    base="$SAIIFE_DOWNLOAD_BASE"
  elif [ -n "$version" ]; then
    base="$REPO_URL/releases/download/v$version/"
  else
    base="$REPO_URL/releases/latest/download/"
  fi
  case "$base" in
    */) ;;
    *) base="$base/" ;;
  esac

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  download "${base}SHA256SUMS" "$tmp/SHA256SUMS" ||
    die "could not download ${base}SHA256SUMS"

  if [ -z "$version" ]; then
    # Latest: the tarball name carries the version, so read it from the one
    # SHA256SUMS line for this target.
    matches="$(awk -v suffix="-$target.tar.gz" '
      { f = $2; sub(/^\*/, "", f) }
      length(f) > length(suffix) && substr(f, length(f) - length(suffix) + 1) == suffix { print f }
    ' "$tmp/SHA256SUMS")"
    count="$(printf '%s\n' "$matches" | grep -c . || true)"
    [ "$count" -eq 1 ] || die "checksum verification failed"
    version="${matches#saiife-}"
    version="${version%-"$target".tar.gz}"
    case "$version" in
      "" | */* | *" "*) die "checksum verification failed" ;;
    esac
  fi

  name="saiife-$version-$target"
  tarball="$name.tar.gz"

  # Keep only the line for our tarball; no line means no install.
  awk -v f="$tarball" '{ g = $2; sub(/^\*/, "", g) } g == f' \
    "$tmp/SHA256SUMS" >"$tmp/SHA256SUMS.target"
  [ "$(grep -c . "$tmp/SHA256SUMS.target" || true)" -eq 1 ] ||
    die "checksum verification failed"

  download "$base$tarball" "$tmp/$tarball" ||
    die "could not download $base$tarball"

  (cd "$tmp" && sha256_check SHA256SUMS.target) ||
    die "checksum verification failed"

  tar -xzf "$tmp/$tarball" -C "$tmp" || die "could not extract $tarball"
  [ -f "$tmp/$name/saiife" ] || die "$tarball does not contain $name/saiife"
  chmod 0755 "$tmp/$name/saiife"

  # sudo only for the final step, and only when the directory needs it.
  sudo=""
  if [ "$system" -eq 1 ]; then
    mkdir -p "$install_dir" 2>/dev/null || true
    if [ ! -d "$install_dir" ] || [ ! -w "$install_dir" ]; then
      command -v sudo >/dev/null 2>&1 ||
        die "$install_dir is not writable and sudo is not available"
      sudo=sudo
    fi
  fi
  as_root mkdir -p "$install_dir" || die "could not create $install_dir"
  staged="$install_dir/.saiife.tmp.$$"
  if ! { as_root cp "$tmp/$name/saiife" "$staged" &&
    as_root chmod 0755 "$staged" &&
    as_root mv -f "$staged" "$install_dir/saiife"; }; then
    as_root rm -f "$staged" 2>/dev/null || true
    die "could not install to $install_dir/saiife"
  fi

  echo "saiife $version installed to $install_dir/saiife"
  case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) echo "Add it to your PATH: export PATH=\"$install_dir:\$PATH\"" ;;
  esac
}

main "$@"
