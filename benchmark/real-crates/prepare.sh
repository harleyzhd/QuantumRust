#!/usr/bin/env bash
# Unpack the real-crate corpus and apply the patches it needs.
#
#   ./benchmark/real-crates/prepare.sh [dest] [crate ...]
#
# dest defaults to analysed-crates/ next to the repository folder. With crate
# names (age, sequoia, jsonwebtoken), only those are unpacked again, so the
# others keep their build caches. Each run unpacks fresh trees.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${1:-$(cd "$here/../../.." && pwd)/analysed-crates}"

age="age-0.12.1"
seq="sequoia-openpgp-2.4.1"
jwt="jsonwebtoken-11.1.0"

# sha256 of the crates.io tarballs.
expect_age="fd290633c2482479f70f6d1d96ae0e9f52c6a26cd5859edd47ee1fe33fc89f26"
expect_seq="0fbc8f9818a6fad141d85993777ba298ee52c80a09bd23d45dda461a6b7c83cb"
expect_jwt="e75fe14a82d81e5f5af639997db37d8b96045938a7ac6ab18cdbe1c7467e05e1"

shift || true
wanted=("$@")
want() {
    [ ${#wanted[@]} -eq 0 ] && return 0
    local w
    for w in "${wanted[@]}"; do [ "$w" = "$1" ] && return 0; done
    return 1
}

check() {
    local file="$1" want="$2" got
    got="$(shasum -a 256 "$file" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
        echo "error: $file has sha256 $got, expected $want" >&2
        exit 1
    fi
}

check "$here/$age.crate" "$expect_age"
check "$here/$seq.crate" "$expect_seq"
check "$here/$jwt.crate" "$expect_jwt"

mkdir -p "$dest"
if want age; then
    rm -rf "${dest:?}/$age"
    tar xzf "$here/$age.crate" -C "$dest"
fi
if want sequoia; then
    rm -rf "${dest:?}/$seq"
    tar xzf "$here/$seq.crate" -C "$dest"
    # The default backend, crypto-nettle, needs a system Nettle library. The
    # patch selects the pure-Rust crypto-rust backend, which changes which
    # crates are analysed.
    patch -p1 -s -d "$dest/$seq" < "$here/$seq-crypto-rust.patch"
fi
if want jsonwebtoken; then
    rm -rf "${dest:?}/$jwt"
    tar xzf "$here/$jwt.crate" -C "$dest"
    # jsonwebtoken selects no crypto backend by default. The patch selects
    # rust_crypto, the pure-Rust one (aws_lc_rs needs a C toolchain and CMake).
    # The choice decides what is analysed.
    patch -p1 -s -d "$dest/$jwt" < "$here/$jwt-rust-crypto.patch"
fi

# Pin the corpus to the repository's toolchain. The crates sit outside the
# repository, so its rust-toolchain.toml does not reach them, and a cargo run
# by hand there would use the default toolchain.
channel="$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' "$here/../../rust-toolchain.toml")"
if [ -z "$channel" ]; then
    echo "error: no channel found in rust-toolchain.toml" >&2
    exit 1
fi
cat > "$dest/rust-toolchain.toml" <<EOF
# Written by benchmark/real-crates/prepare.sh: the toolchain the repository pins.
[toolchain]
channel = "$channel"
EOF

printf 'corpus ready in %s, pinned to %s\n\n' "$dest" "$channel"
for pair in "$age:age" "$jwt:jsonwebtoken" "$seq:sequoia"; do
    crate="${pair%%:*}"
    if [ -d "$dest/$crate" ]; then
        echo "  quantumrust analyze $dest/$crate --out out/${pair##*:}"
    fi
done
