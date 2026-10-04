#!/usr/bin/env bash
set -euo pipefail
fixture_dir="${1:-target/micro-fixture}"
mkdir -p "$fixture_dir"
cd "$fixture_dir"
archive=micro-2.0.15-win64.zip
curl -fLsS --retry 3 -o "$archive" "https://github.com/micro-editor/micro/releases/download/v2.0.15/$archive"
printf '%s  %s\n' 90635c53c11aa2a0d997f5e3ed43528877740725500207640b29551cef18479b "$archive" | sha256sum -c -
unzip -oq "$archive"
