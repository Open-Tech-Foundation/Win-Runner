#!/usr/bin/env bash
# Build the Rust guest programs (x86_64-pc-windows-msvc, no_std) into real
# PE32+ binaries using only rustup parts: rustc + rust-lld, no mingw/xwin.
# Output: guests/out/*.exe, copied to tests/artifacts/exe/rust_*.exe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/guests/out"
ART="$ROOT/tests/artifacts/exe"
TARGET="x86_64-pc-windows-msvc"

if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
    echo "error: rust target '${TARGET}' not installed." >&2
    echo "run: rustup target add ${TARGET}" >&2
    exit 1
fi

SYSROOT="$(rustc --print sysroot)"
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
LLD="$SYSROOT/lib/rustlib/$HOST_TRIPLE/bin/rust-lld"
if [[ ! -x "$LLD" ]]; then
    echo "error: rust-lld not found at $LLD" >&2
    exit 1
fi

mkdir -p "$OUT"
# Import library for exactly the APIs WinCLI implements.
"$LLD" -flavor link \
    "/DEF:$ROOT/guests/kernel32.def" \
    "/OUT:$OUT/kernel32.lib" \
    /MACHINE:x64

# Sysroot rlibs for the guest target: lets no_std guests use `extern crate
# alloc` and out-of-line core helpers (bounds-check panics, slice helpers)
# without CRT. Guest-provided memcpy/memset satisfy compiler-builtins refs.
RLIB="$SYSROOT/lib/rustlib/$TARGET/lib"
# shellcheck disable=SC2206
GUEST_RLIBS=(
    $RLIB/liballoc-*.rlib
    $RLIB/libcore-*.rlib
    $RLIB/libcompiler_builtins-*.rlib
    $RLIB/libpanic_abort-*.rlib
)

# Force a retained absolute image reference into each otherwise
# position-independent guest, so PE base relocations are available to native
# CreateProcessW child mapping.
RELOCATION_OBJ="$OUT/relocation.o"
rustc --target "$TARGET" --crate-type lib --emit obj \
    -C panic=abort -C opt-level=2 --edition 2021 \
    "$ROOT/guests/relocation.rs" -o "$RELOCATION_OBJ"

build_guest() {
    local src="$1" entry="$2" dest="$3"
    local obj="$OUT/$(basename "$src" .rs).o"
    rustc --target "$TARGET" --crate-type lib --emit obj \
        -C panic=abort -C opt-level=2 --edition 2021 \
        "$ROOT/guests/$src" -o "$obj"
    "$LLD" -flavor link \
        "/OUT:$obj.exe" \
        "/ENTRY:$entry" \
        /NODEFAULTLIB /SUBSYSTEM:CONSOLE /DYNAMICBASE \
        "$obj" "$RELOCATION_OBJ" "$OUT/kernel32.lib" "${GUEST_RLIBS[@]}"
    cp "$obj.exe" "$ART/$dest"
    echo "built $ART/$dest"
}

build_guest hello.rs guest_entry rust_hello.exe
build_guest fs_selftest.rs guest_entry rust_fs.exe
build_guest argv_echo.rs guest_entry rust_argv.exe
build_guest lang.rs guest_entry rust_lang.exe
build_guest fp.rs guest_entry rust_fp.exe
build_guest alloc.rs guest_entry rust_alloc.exe
build_guest alloc_fs.rs guest_entry rust_alloc_fs.exe
build_guest hashmap.rs guest_entry rust_hashmap.exe
build_guest memcpy.rs guest_entry rust_memcpy.exe
build_guest iocp.rs guest_entry rust_iocp.exe
