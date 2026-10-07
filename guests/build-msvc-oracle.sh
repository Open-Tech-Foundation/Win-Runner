#!/usr/bin/env bash
# Build the MSVC-ABI Windows-oracle probes (guests/oracle-msvc) into
# tests/artifacts/exe: a C++ probe with clang-cl against the MSVC CRT
# (/EHsc /MD, so VCRUNTIME140 handles exceptions) and a std Rust probe for
# x86_64-pc-windows-msvc. Needs cargo-xwin, whose cache provides the MSVC
# CRT/SDK and the clang-cl/lld-link links. The .exe files are committed,
# so CI's oracle jobs use them without this toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART="$ROOT/tests/artifacts/exe"
SRC="$ROOT/guests/oracle-msvc"
XWIN_CACHE="${XWIN_CACHE_DIR:-$HOME/.local/cache/cargo-xwin}"
XWIN="$XWIN_CACHE/xwin"

cargo xwin build --release --target x86_64-pc-windows-msvc \
    --manifest-path "$SRC/rust_unwind/Cargo.toml"
cp "$SRC/rust_unwind/target/x86_64-pc-windows-msvc/release/oracle_rust_unwind.exe" \
    "$ART/oracle_rust_unwind.exe"
echo "built $ART/oracle_rust_unwind.exe"

if [[ ! -x "$XWIN_CACHE/clang-cl" || ! -d "$XWIN/crt" ]]; then
    echo "error: cargo-xwin cache not found at $XWIN_CACHE (run cargo xwin once)" >&2
    exit 1
fi
OBJ="$(mktemp -d)"
trap 'rm -rf "$OBJ"' EXIT
PATH="$XWIN_CACHE:$PATH" "$XWIN_CACHE/clang-cl" --target=x86_64-pc-windows-msvc \
    /nologo /O2 /EHsc /MD /std:c++17 -fuse-ld=lld-link -Wno-unused-command-line-argument \
    /imsvc "$XWIN/crt/include" /imsvc "$XWIN/sdk/include/ucrt" \
    /imsvc "$XWIN/sdk/include/um" /imsvc "$XWIN/sdk/include/shared" \
    "/Fo$OBJ/" "$SRC/cxx_eh.cpp" \
    /link "/libpath:$XWIN/crt/lib/x86_64" "/libpath:$XWIN/sdk/lib/um/x86_64" \
    "/libpath:$XWIN/sdk/lib/ucrt/x86_64" "/out:$ART/oracle_cxx_eh.exe"
echo "built $ART/oracle_cxx_eh.exe"
