#!/bin/sh
# End-to-end check for the native GeoIP helper and the mmdblookup fallback.
#
# Compiles src/log-viewer-geoip.c against the real libmaxminddb, downloads
# MaxMind's public test databases, and asserts that a known address resolves.
# Linux-only (needs cc, libmaxminddb, mmdblookup and curl); skips elsewhere.
set -eu

# The CDPATH= prefix is deliberate: it keeps cd from printing a path.
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lv-geoip-e2e.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

skip() { echo "skip: $1"; exit 0; }

command -v cc >/dev/null 2>&1 || skip "no compiler"
command -v curl >/dev/null 2>&1 || skip "no curl"
if ! cc -O2 -Wall -Wextra -o "$WORK/log-viewer-geoip" "$ROOT/src/log-viewer-geoip.c" -lmaxminddb 2>"$WORK/cc.log"; then
  cat "$WORK/cc.log" >&2
  skip "libmaxminddb headers or library unavailable"
fi

BASE="https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data"
curl -fsSL -o "$WORK/GeoLite2-Country.mmdb" "$BASE/GeoLite2-Country-Test.mmdb" || skip "country test db unavailable"
curl -fsSL -o "$WORK/GeoLite2-ASN.mmdb" "$BASE/GeoLite2-ASN-Test.mmdb" || skip "asn test db unavailable"

"$WORK/log-viewer-geoip" --db "$WORK" --batch 2.125.160.216 81.2.69.142 > "$WORK/native.ndjson"
grep -q '"country_code":"GB"' "$WORK/native.ndjson" || { echo 'native helper did not resolve the test address'; cat "$WORK/native.ndjson"; exit 1; }
if grep -q '"error"' "$WORK/native.ndjson"; then
  echo 'native helper reported an error'
  cat "$WORK/native.ndjson"
  exit 1
fi
echo "native helper resolves the test database"

if command -v mmdblookup >/dev/null 2>&1; then
  LOG_VIEWER_GEOIP_HELPER=/nonexistent GEOIP_DB_DIR="$WORK" \
    sh "$ROOT/root/usr/bin/flint4-geoip" --batch 2.125.160.216 > "$WORK/fallback.ndjson"
  grep -q '"country_code":"GB"' "$WORK/fallback.ndjson" || {
    echo 'mmdblookup fallback did not resolve the test address'
    cat "$WORK/fallback.ndjson"
    exit 1
  }
  echo "mmdblookup fallback resolves the test database"
else
  echo "skip: mmdblookup not installed, fallback not exercised"
fi
