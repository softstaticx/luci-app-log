#!/bin/sh
# Parse the generated nftables rulesets with the real nft binary.
#
# The watcher validates its own output before applying it, but this runs the
# same files through `nft -c` in CI so a syntax regression is caught before a
# release rather than on a router. Skips quietly when nft is not installed.
set -eu

# The CDPATH= prefix is deliberate: it keeps `cd` from printing a path.
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lv-nft.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

# Resolve the real binary before the fake nft is placed on PATH.
REAL_NFT=$(command -v nft || true)
[ -n "$REAL_NFT" ] || { echo 'nft not installed; skipping'; exit 0; }

ENV_DIR="$WORK/env"
mkdir -p "$ENV_DIR/bin" "$ENV_DIR/nft" "$ENV_DIR/include"
cp "$ROOT/tests/support/fake-uci" "$ENV_DIR/bin/uci"
cp "$ROOT/tests/support/fake-nft" "$ENV_DIR/bin/nft"
cp "$ROOT/tests/support/fake-fw4" "$ENV_DIR/bin/fw4"
chmod +x "$ENV_DIR/bin/uci" "$ENV_DIR/bin/nft" "$ENV_DIR/bin/fw4"

export FAKE_UCI="$ENV_DIR/uci"
export FAKE_NFT_DIR="$ENV_DIR/nft"
export FAKE_FW4_INIT_LOG="$ENV_DIR/fw4.log"
export LOG_VIEWER_FUNCTIONS="$ROOT/tests/support/functions.sh"
export LOG_VIEWER_FIREWALL_CONFIG="$ENV_DIR/no-firewall.conf"
export LOG_VIEWER_INCLUDE_DIR="$ENV_DIR/include"
export LOG_VIEWER_FW4_INIT=""
PATH="$ENV_DIR/bin:$PATH"
export PATH

printf '%s\n' \
  'infra-port-watch.main.enabled=1' \
  'infra-port-watch.main.mode=probe' \
  'infra-port-watch.main.wan_interface=eth2' \
  'infra-port-watch.main.ipv6=1' \
  'infra-port-watch.main.log_other_ports=1' \
  'infra-port-watch.main.ports=22 80 443 8080 8443' > "$FAKE_UCI"

sh "$ROOT/root/usr/sbin/infra-port-watch" apply >/dev/null
"$REAL_NFT" -c -f "$FAKE_NFT_DIR/checked"
echo 'probe ruleset parses'

printf '%s\n' \
  'infra-port-watch.main.enabled=1' \
  'infra-port-watch.main.mode=verdict' \
  'infra-port-watch.main.wan_zone=wan' \
  'infra-port-watch.main.ipv6=1' \
  'infra-port-watch.main.log_other_ports=0' \
  'infra-port-watch.main.ports=22 80 443' > "$FAKE_UCI"

sh "$ROOT/root/usr/sbin/infra-port-watch" apply >/dev/null

# Rebuild the shape fw4 produces: a table with our set and our chain fragments.
{
  printf 'table inet fw4 {\n'
  cat "$ENV_DIR/include/table-pre/10-log-viewer.nft"
  printf '\tchain input_wan {\n'
  cat "$ENV_DIR/include/chain-post/input_wan/10-log-viewer.nft"
  printf '\t}\n'
  printf '\tchain forward_wan {\n'
  cat "$ENV_DIR/include/chain-post/forward_wan/10-log-viewer.nft"
  printf '\t}\n'
  printf '}\n'
} > "$WORK/fw4.nft"

"$REAL_NFT" -c -f "$WORK/fw4.nft"
echo 'verdict include parses'
