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
    if [[ "$name" == process_runtime ]]; then
        commands=$(printf 'New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n@seed "%s" C:\\oracle-run\\process_runtime.exe\nC:\\oracle-run\\process_runtime.exe\nexit\n' "$exe")
    else
        commands=$(printf 'New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n"%s"\nexit\n' "$exe")
    fi
    printf '%s\n' "$commands" |
        "$WINRUN" shell 2>"$OUT/$name.stderr" | tr -d '\r' >"$OUT/$name.txt" || true
    echo "ran $name: $(wc -l <"$OUT/$name.txt") lines"
done
