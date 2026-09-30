#!/usr/bin/env bash
# Build the Windows-oracle probes (guests/oracle/*.rs) into PE32+ .exe files
# with rustc + rust-lld only. Output: tests/artifacts/exe/oracle_<name>.exe.
# The probes import only guests/oracle/kernel32.def statically; every other
# API is found with GetProcAddress at run time. See tests/oracle/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/guests/out"
ART="$ROOT/tests/artifacts/exe"
TARGET="x86_64-pc-windows-msvc"

if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
    echo "error: rust target '${TARGET}' not installed (rustup target add ${TARGET})" >&2
    exit 1
fi
SYSROOT="$(rustc --print sysroot)"
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
LLD="$SYSROOT/lib/rustlib/$HOST_TRIPLE/bin/rust-lld"
RLIB="$SYSROOT/lib/rustlib/$TARGET/lib"
mkdir -p "$OUT" "$ART"

"$LLD" -flavor link \
    "/DEF:$ROOT/guests/oracle/kernel32.def" \
    "/OUT:$OUT/oracle_kernel32.lib" \
    /MACHINE:x64

for probe in "$ROOT"/guests/oracle/*.rs; do
    name="$(basename "$probe" .rs)"
    [[ "$name" == common ]] && continue
    obj="$OUT/oracle_$name.o"
    rustc --target "$TARGET" --crate-type lib --emit obj \
        -C panic=abort -C opt-level=2 --edition 2021 \
        "$probe" -o "$obj"
    "$LLD" -flavor link \
        "/OUT:$ART/oracle_$name.exe" \
        /ENTRY:probe_entry \
        /NODEFAULTLIB /SUBSYSTEM:CONSOLE /DYNAMICBASE \
        "$obj" "$OUT/oracle_kernel32.lib" \
        "$RLIB"/libcore-*.rlib "$RLIB"/libcompiler_builtins-*.rlib
    echo "built $ART/oracle_$name.exe"
done
