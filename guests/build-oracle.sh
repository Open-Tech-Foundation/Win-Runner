#!/usr/bin/env bash
# Build the Windows-oracle probes (guests/oracle/*.rs) into PE32+ .exe files
# with rustc + rust-lld only. Output: tests/artifacts/exe/oracle_<name>.exe.
# Most probes import only kernel32.def statically; native_startup also uses
# ntdll.def to exercise NT import binding. Other APIs use GetProcAddress. See tests/oracle/README.md.
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

"$LLD" -flavor link "/DEF:$ROOT/guests/oracle/ntdll.def" "/OUT:$OUT/oracle_ntdll.lib" /MACHINE:x64

# Small real DLLs embedded by the DLL-search probe. Two copies export distinct
# values; a parent/middle chain exercises recursive dependency lookup.
mkdir -p "$ROOT/tests/artifacts/dll"
for variant in app user; do
    config=()
    [[ "$variant" == user ]] && config=(--cfg user_directory)
    rustc --target "$TARGET" --crate-type lib --emit obj -C panic=abort -C opt-level=2 --edition 2021 \
        "${config[@]}" "$ROOT/guests/oracle/dll_value_support.rs" -o "$OUT/dll_value_$variant.o"
    base=0x500700000000
    [[ "$variant" == user ]] && base=0x500800000000
    "$LLD" -flavor link /DLL /NOENTRY /NODEFAULTLIB /DYNAMICBASE "/BASE:$base" \
        "/OUT:$ROOT/tests/artifacts/dll/oracle_search_$variant.dll" /EXPORT:OracleSearchValue "/IMPLIB:$OUT/oracle_search_$variant.lib" \
        "$OUT/dll_value_$variant.o" "$RLIB"/libcore-*.rlib "$RLIB"/libcompiler_builtins-*.rlib
done
cat > "$OUT/oracle_search_value.def" <<'DEF'
LIBRARY oracle_search_value.dll
EXPORTS
OracleSearchValue
DEF
"$LLD" -flavor link "/DEF:$OUT/oracle_search_value.def" "/OUT:$OUT/oracle_search_value.lib" /MACHINE:x64
for kind in middle parent; do
    rustc --target "$TARGET" --crate-type lib --emit obj -C panic=abort -C opt-level=2 --edition 2021 \
        "$ROOT/guests/oracle/dll_${kind}_support.rs" -o "$OUT/dll_$kind.o"
    export_name=OracleSearchMiddle
    dependency=oracle_search_value
    base=0x500900000000
    if [[ "$kind" == parent ]]; then
        export_name=OracleSearchParent
        dependency=oracle_search_middle
        base=0x500a00000000
    fi
    "$LLD" -flavor link /DLL /NOENTRY /NODEFAULTLIB /DYNAMICBASE "/BASE:$base" \
        "/OUT:$ROOT/tests/artifacts/dll/oracle_search_$kind.dll" "/IMPLIB:$OUT/oracle_search_$kind.lib" "/EXPORT:$export_name" \
        "$OUT/dll_$kind.o" "$OUT/$dependency.lib" "$RLIB"/libcore-*.rlib "$RLIB"/libcompiler_builtins-*.rlib
done

for probe in "$ROOT"/guests/oracle/*.rs; do
    name="$(basename "$probe" .rs)"
    # Shared code, included by the probes.
    [[ "$name" == common || "$name" == *_support ]] && continue
    obj="$OUT/oracle_$name.o"
    rustc --target "$TARGET" --crate-type lib --emit obj \
        -C panic=abort -C opt-level=2 --edition 2021 \
        "$probe" -o "$obj"
    "$LLD" -flavor link \
        "/OUT:$ART/oracle_$name.exe" \
        /ENTRY:probe_entry \
        /NODEFAULTLIB /SUBSYSTEM:CONSOLE /DYNAMICBASE \
        "$obj" "$OUT/oracle_kernel32.lib" "$OUT/oracle_ntdll.lib" \
        "$RLIB"/libcore-*.rlib "$RLIB"/libcompiler_builtins-*.rlib
    echo "built $ART/oracle_$name.exe"
done
