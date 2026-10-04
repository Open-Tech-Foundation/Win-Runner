#!/usr/bin/env bash
set -euo pipefail
fixture_dir="${1:-target/curl-fixture}"
mkdir -p "$fixture_dir"
cd "$fixture_dir"
archive=curl-8.22.0_2-win64-mingw.zip
curl -fLsS --retry 3 -o "$archive" "https://curl.se/windows/dl-8.22.0_2/$archive"
printf '%s  %s\n' 7c8c6b953b4eb2953d2bdc08cca1d5f09a964e9f86c361693559400c9a6d6db0 "$archive" | sha256sum -c -
unzip -oq "$archive"
