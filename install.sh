#!/bin/sh

#
# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#

set -eu

REPOSITORY="https://github.com/stalwartlabs/stalwart-migrate"
BINARY="stalwart-migrate"

usage() {
    cat <<EOF
Installs the stalwart-migrate binary from the GitHub releases.

Usage: stalwart-migrate-installer.sh [OPTIONS]

Options:
  --oss              Install the build for Stalwart servers compiled without the "enterprise" feature
  --fdb              Install the FoundationDB build (Linux x86_64 and aarch64 with glibc 2.34 or later)
  --version <VER>    Install release <VER> (for example 1.0.0) instead of the latest one
  --to <DIR>         Install into <DIR> (default: /usr/local/bin as root, ~/.local/bin otherwise)
  --musl             On Linux, install the statically linked musl build
  -h, --help         Print this help

The install directory can also be set with STALWART_MIGRATE_INSTALL_DIR.
EOF
}

say() {
    printf 'stalwart-migrate-installer: %s\n' "$1"
}

err() {
    say "error: $1" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || err "this script needs '$1', which was not found"
}

glibc_ok() {
    want=$1
    ver=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}') || return 1
    [ -n "$ver" ] || return 1
    major=${ver%%.*}
    minor=${ver#*.}
    minor=${minor%%.*}
    [ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge "$want" ]; }
}

cleanup() {
    if [ -n "${partial:-}" ]; then
        rm -f "$partial"
    fi
    if [ -n "${tmp:-}" ]; then
        rm -rf "$tmp"
    fi
}

main() {
    variant=""
    version=""
    install_dir="${STALWART_MIGRATE_INSTALL_DIR:-}"
    force_musl=0
    tmp=""
    partial=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --oss)
                [ -z "$variant" ] || err "--oss and --fdb cannot be combined"
                variant="-oss"
                ;;
            --fdb)
                [ -z "$variant" ] || err "--oss and --fdb cannot be combined"
                variant="-fdb"
                ;;
            --version)
                [ $# -ge 2 ] || err "--version needs a value"
                version="${2#v}"
                shift
                ;;
            --to)
                [ $# -ge 2 ] || err "--to needs a value"
                install_dir="$2"
                shift
                ;;
            --musl)
                force_musl=1
                ;;
            -h | --help)
                usage
                return 0
                ;;
            *)
                err "unknown option '$1' (see --help)"
                ;;
        esac
        shift
    done

    need uname
    need awk
    need tar
    need mktemp

    os=$(uname -s)
    arch=$(uname -m)

    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        armv7* | armv8l) arch=armv7 ;;
        *) err "unsupported CPU architecture: $arch" ;;
    esac

    case "$os" in
        Linux)
            if [ "$(getconf LONG_BIT 2>/dev/null || echo 64)" = 32 ]; then
                case "$arch" in
                    aarch64) arch=armv7 ;;
                    x86_64) err "32-bit x86 systems are not supported" ;;
                esac
            fi
            libc=gnu
            if [ "$force_musl" -eq 1 ]; then
                libc=musl
            elif ! glibc_ok 28; then
                libc=musl
            fi
            if [ "$variant" = "-fdb" ]; then
                if [ "$libc" != gnu ] || ! glibc_ok 34; then
                    err "the FoundationDB build needs glibc 2.34 or later"
                fi
                [ "$arch" != armv7 ] || err "the FoundationDB build is available for x86_64 and aarch64 only"
            fi
            if [ "$arch" = armv7 ]; then
                if [ "$libc" = gnu ]; then
                    target="armv7-unknown-linux-gnueabihf"
                else
                    target="armv7-unknown-linux-musleabihf"
                fi
            else
                target="$arch-unknown-linux-$libc"
            fi
            if ! command -v xz >/dev/null 2>&1 && ! { tar --help 2>&1 | grep -q BusyBox && tar --help 2>&1 | grep -q -- '-J'; }; then
                err "this script needs 'xz' to extract the archive, which was not found"
            fi
            ;;
        Darwin)
            [ "$variant" != "-fdb" ] || err "the FoundationDB build is available for Linux only"
            if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
                arch=aarch64
            fi
            [ "$arch" != armv7 ] || err "unsupported CPU architecture: $arch"
            target="$arch-apple-darwin"
            ;;
        *)
            err "unsupported operating system: $os. On Windows, run stalwart-migrate with Docker or in WSL"
            ;;
    esac

    if [ -z "$install_dir" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            install_dir=/usr/local/bin
        else
            [ -n "${HOME:-}" ] || err "HOME is not set; choose a directory with --to"
            install_dir="$HOME/.local/bin"
        fi
    fi

    if [ -n "$version" ]; then
        base="$REPOSITORY/releases/download/v$version"
    else
        base="$REPOSITORY/releases/latest/download"
    fi
    archive="$BINARY$variant-$target.tar.xz"

    if command -v curl >/dev/null 2>&1; then
        downloader=curl
    elif command -v wget >/dev/null 2>&1; then
        if wget --help 2>&1 | grep -q BusyBox; then
            downloader=busybox-wget
        else
            downloader=wget
        fi
    else
        err "this script needs curl or wget"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        hasher=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        hasher=shasum
    else
        err "this script needs sha256sum or shasum to verify the download"
    fi

    trap cleanup EXIT
    trap 'cleanup; exit 130' INT
    trap 'cleanup; exit 143' TERM
    tmp=$(mktemp -d)

    say "downloading $archive"
    fetch "$base/$archive" "$tmp/$archive" || err "cannot download $base/$archive"
    fetch "$base/$archive.sha256" "$tmp/$archive.sha256" || err "cannot download $base/$archive.sha256"

    expected=$(awk '{print $1}' "$tmp/$archive.sha256")
    actual=$(sha256 "$tmp/$archive")
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        err "checksum mismatch for $archive"
    fi

    tar -xJf "$tmp/$archive" -C "$tmp" || err "cannot extract $archive"
    extracted="$tmp/$BINARY$variant-$target/$BINARY"
    [ -f "$extracted" ] || err "the archive does not contain $BINARY"

    mkdir -p "$install_dir" 2>/dev/null || err "cannot create $install_dir; run as root or choose a directory with --to"
    [ -w "$install_dir" ] || err "$install_dir is not writable; run as root or choose a directory with --to"
    partial="$install_dir/.$BINARY.partial.$$"
    cp "$extracted" "$partial"
    chmod 0755 "$partial"
    mv -f "$partial" "$install_dir/$BINARY"
    partial=""

    say "installed $install_dir/$BINARY ($target)"

    case ":${PATH:-}:" in
        *":$install_dir:"*) ;;
        *) say "$install_dir is not in PATH; add it or run $install_dir/$BINARY" ;;
    esac

    if [ "$variant" = "-fdb" ]; then
        say "this build needs the FoundationDB client library (libfdb_c.so) installed on this host"
    fi
}

fetch() {
    if [ "$downloader" = curl ]; then
        curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$1" -o "$2"
    elif [ "$downloader" = wget ]; then
        wget --https-only -q -O "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

sha256() {
    if [ "$hasher" = sha256sum ]; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

main "$@"
