#!/bin/sh

#
# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#

set -eu

if [ $# -lt 2 ]; then
    echo "usage: $0 <default|oss|fdb> <target> [output-dir]" >&2
    exit 2
fi

variant=$1
target=$2
out=${3:-dist}
stores="rocks,sqlite,postgres,mysql,s3,azure,redis"

case "$variant" in
    default)
        app=stalwart-migrate
        features="$stores,enterprise"
        ;;
    oss)
        app=stalwart-migrate-oss
        features="$stores"
        ;;
    fdb)
        app=stalwart-migrate-fdb
        features="$stores,foundation,enterprise"
        ;;
    *)
        echo "unknown variant: $variant" >&2
        exit 2
        ;;
esac

case "$target" in
    aarch64-unknown-linux-*)
        target_var=$(echo "$target" | tr '-' '_')
        export "CFLAGS_$target_var=-moutline-atomics" "CXXFLAGS_$target_var=-moutline-atomics"
        ;;
esac

case "$target" in
    *-unknown-linux-gnu*)
        build="cargo zigbuild"
        if [ "$variant" = fdb ]; then
            cargo_target="$target.${GLIBC_VERSION:-2.34}"
        else
            cargo_target="$target.${GLIBC_VERSION:-2.28}"
        fi
        ;;
    *-unknown-linux-musl*)
        build="cargo zigbuild"
        cargo_target="$target"
        ;;
    *-apple-darwin)
        build="cargo build"
        cargo_target="$target"
        ;;
    *)
        echo "unsupported target: $target" >&2
        exit 2
        ;;
esac

if [ "$variant" = fdb ]; then
    case "$target" in
        x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu) ;;
        *)
            echo "the fdb variant is built for x86_64 and aarch64 Linux gnu only" >&2
            exit 2
            ;;
    esac
    if [ -z "${FDB_LIB_DIR:-}" ] || [ ! -f "$FDB_LIB_DIR/libfdb_c.so" ]; then
        echo "FDB_LIB_DIR must point to a directory containing libfdb_c.so" >&2
        exit 2
    fi
    export FDB_CLIENT_LIB_PATH="$FDB_LIB_DIR"
    rustflags_var="CARGO_TARGET_$(echo "$target" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
    export "$rustflags_var=-L $FDB_LIB_DIR"
fi

$build --release --locked -p migrate --bin stalwart-migrate \
    --no-default-features --features "$features" --target "$cargo_target"

target_dir=${CARGO_TARGET_DIR:-target}
binary="$target_dir/$target/release/stalwart-migrate"
if [ ! -f "$binary" ]; then
    binary="$target_dir/$cargo_target/release/stalwart-migrate"
fi
if [ ! -f "$binary" ]; then
    echo "built binary not found under $target_dir" >&2
    exit 1
fi

name="$app-$target"
mkdir -p "$out"
rm -rf "${out:?}/$name"
mkdir "$out/$name"
cp "$binary" "$out/$name/stalwart-migrate"
chmod 0755 "$out/$name/stalwart-migrate"
cp README.md "$out/$name/"
cp -R LICENSES "$out/$name/"
find "$out/$name" -type d -exec chmod 0755 {} +
find "$out/$name" -type f ! -name stalwart-migrate -exec chmod 0644 {} +

epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
if touch -d "@$epoch" "$out/$name" 2>/dev/null; then
    find "$out/$name" -exec touch -h -d "@$epoch" {} +
else
    stamp=$(date -u -r "$epoch" +%Y%m%d%H%M.%S)
    TZ=UTC find "$out/$name" -exec touch -h -t "$stamp" {} +
fi

(cd "$out" && find "$name" | LC_ALL=C sort > "$name.list")
if tar --version 2>/dev/null | grep -q "GNU tar"; then
    tar -C "$out" --no-recursion -T "$out/$name.list" --owner=0 --group=0 --numeric-owner \
        --mtime="@$epoch" --no-xattrs --format=gnu -cf - | xz -T1 -6 > "$out/$name.tar.xz"
else
    COPYFILE_DISABLE=1 TZ=UTC tar -C "$out" --no-recursion -T "$out/$name.list" --uid 0 --gid 0 \
        --uname "" --gname "" --no-xattrs --no-mac-metadata --format=gnutar -cf - | xz -T1 -6 > "$out/$name.tar.xz"
fi
rm -rf "${out:?}/$name" "${out:?}/$name.list"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$out" && sha256sum "$name.tar.xz" > "$name.tar.xz.sha256")
else
    (cd "$out" && shasum -a 256 "$name.tar.xz" > "$name.tar.xz.sha256")
fi

echo "$out/$name.tar.xz"
