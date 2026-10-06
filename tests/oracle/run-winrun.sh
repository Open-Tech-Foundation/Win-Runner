#!/usr/bin/env bash
# Run every Windows-oracle probe under Win-Runner, one transcript per probe.
#
#   tests/oracle/run-winrun.sh <winrun> <output-dir>
#
# Each probe starts in a fresh directory, C:\oracle-run, as run-windows.ps1
# starts it in a fresh directory on Windows.
set -euo pipefail
WINRUN="$(realpath "$1")"
OUT="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$OUT"
for exe in "$ROOT"/tests/artifacts/exe/oracle_*.exe; do
    name="$(basename "$exe" .exe)"
    name="${name#oracle_}"
    if [[ "$name" == process_runtime || "$name" == console_runtime || "$name" == native_startup || "$name" == desktop_clipboard ]]; then
        commands=$(printf 'New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n@seed "%s" C:\\oracle-run\\%s.exe\nC:\\oracle-run\\%s.exe\nexit\n' "$exe" "$name" "$name")
    elif [[ "$name" == dll_search ]]; then
        commands=$(printf 'New-Item C:\\oracle-run\\app -ItemType Directory\ncd C:\\oracle-run\n@seed "%s" C:\\oracle-run\\app\\oracle_dll_search.exe\nC:\\oracle-run\\app\\oracle_dll_search.exe\nexit\n' "$exe")
    else
        commands=$(printf 'New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n"%s"\nexit\n' "$exe")
    fi
    printf '%s\n' "$commands" |
        "$WINRUN" shell 2>"$OUT/$name.stderr" | tr -d '\r' >"$OUT/$name.txt" || true
    echo "ran $name: $(wc -l <"$OUT/$name.txt") lines"
done
for script in "$ROOT"/tests/oracle/*.ps1; do
    name="$(basename "$script" .ps1)"
    [[ "$name" == run-* ]] && continue
    printf 'New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n@seed "%s" C:\\oracle-run\\%s.ps1\npowershell -File C:\\oracle-run\\%s.ps1\nexit\n' "$script" "$name" "$name" |
        "$WINRUN" shell 2>"$OUT/$name.stderr" | tr -d '\r' >"$OUT/$name.txt" || true
    echo "ran $name: $(wc -l <"$OUT/$name.txt") lines"
done
