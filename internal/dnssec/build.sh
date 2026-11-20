#!/usr/bin/env bash
# Rebuilds the prebuilt dnssec-prover static libraries (pinned upstream tag and
# Cargo.lock; no LTO/bitcode since cgo in Go 1.27.3+ rejects it). Needs Rust +
# `rustup component add llvm-tools` for darwin, Docker for linux. Afterwards
# regenerate SHA256SUMS. Archives aren't bit-for-bit reproducible.
# usage: ./build.sh darwin|linux
set -euo pipefail
TAG=v0.6.10
COMMIT=04a6f240fc0f1e12d69d11bb7f6a415ff2a2e02c
RUST_IMAGE=rust:1.88
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
git clone -q https://github.com/TheBlueMatt/dnssec-prover.git "$work/src"
git -C "$work/src" checkout -q "$TAG"
[ "$(git -C "$work/src" rev-parse HEAD)" = "$COMMIT" ] || { echo "tag $TAG does not match pinned commit" >&2; exit 1; }
cp "$here/Cargo.lock" "$work/src/uniffi/Cargo.lock"
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 RUSTFLAGS="-C embed-bitcode=no"
case "${1:-}" in
darwin)
  (cd "$work/src/uniffi" && cargo rustc --locked --release --lib --crate-type staticlib)
  oc=$(find ~/.rustup -name llvm-objcopy | head -1)   # rustup component add llvm-tools
  "$oc" --remove-section=__LLVM,__bitcode --remove-section=__LLVM,__cmdline \
        --remove-section=__LLVM,__asm --remove-section=__LLVM,__swift_cmdline \
        "$work/src/uniffi/target/release/libdnssec_prover_uniffi.a" "$here/libdnssec_darwin_arm64.a" ;;
linux)
  docker run --rm --platform linux/amd64 -v "$work/src:/src:ro" -v "$here:/out" \
    -e RUSTFLAGS -e CARGO_PROFILE_RELEASE_LTO -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS -e CARGO_TARGET_DIR=/tmp/t "$RUST_IMAGE" bash -c '
    cp -r /src /work && cd /work/uniffi && cargo rustc --locked --release --lib --crate-type staticlib &&
    objcopy -R .llvmbc -R .llvmcmd -R .llvm.lto /tmp/t/release/libdnssec_prover_uniffi.a /out/libdnssec_linux_amd64.a' ;;
*) echo "usage: $0 darwin|linux" >&2; exit 2 ;;
esac
echo "built; now update SHA256SUMS: (cd $here && shasum -a 256 libdnssec_*.a > SHA256SUMS)"
