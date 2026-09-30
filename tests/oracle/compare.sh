#!/usr/bin/env bash
# Compare Win-Runner transcripts with Windows ones, probe by probe.
#
#   tests/oracle/compare.sh <windows-dir> <winrun-dir>
#
# Prints a unified diff per differing probe and exits 1 if any differ or a
# transcript is missing.
set -uo pipefail
WINDOWS="$1"
WINRUN="$2"
status=0
for expected in "$WINDOWS"/*.txt; do
    name="$(basename "$expected")"
    actual="$WINRUN/$name"
    if [[ ! -f "$actual" ]]; then
        echo "MISSING under Win-Runner: $name"
        status=1
        continue
    fi
    if diff -u --label "windows/$name" --label "winrun/$name" "$expected" "$actual"; then
        echo "MATCH $name ($(wc -l <"$expected") lines)"
    else
        echo "DIFFERS $name: $(diff "$expected" "$actual" | grep -c '^>') line(s) differ"
        status=1
    fi
done
exit $status
