#!/bin/sh
# Integration tests for the shell side of luci-app-log-viewer.
#
# Runs with a plain POSIX shell (dash, busybox ash, or bash) and does not need
# a router: uci, nft, fw4 and mmdblookup are replaced by the deterministic
# stand-ins in tests/support. CI runs this file directly; run it locally before
# sending a release.
set -u

# The CDPATH= prefix is deliberate: it keeps `cd` from printing a path.
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SUPPORT="$ROOT/tests/support"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lv-tests.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0
FAIL=0
CURRENT=""

group() {
	CURRENT="$1"
	printf '\n# %s\n' "$CURRENT"
}

ok() { PASS=$((PASS + 1)); }
no() {
	FAIL=$((FAIL + 1))
	printf 'not ok - %s\n' "$1"
}

check() {
	desc="$1"
	shift
	if "$@" >/dev/null 2>&1; then ok; else no "$desc"; fi
}

has() { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }
file_exists() { [ -e "$1" ]; }
file_missing() { [ ! -e "$1" ]; }
equals() { [ "$1" = "$2" ]; }

json_ok() {
	if command -v node >/dev/null 2>&1; then
		node -e 'const fs=require("fs");JSON.parse(fs.readFileSync(process.argv[1],"utf8"));' "$1" >/dev/null 2>&1
	else
		return 0
	fi
}

# ------------------------------------------------------------------ setup ---

new_env() {
	env_dir="$WORK/$1"
	mkdir -p "$env_dir/bin" "$env_dir/nft" "$env_dir/include" "$env_dir/data"
	: > "$env_dir/uci"
	cp "$SUPPORT/fake-uci" "$env_dir/bin/uci"
	cp "$SUPPORT/fake-nft" "$env_dir/bin/nft"
	cp "$SUPPORT/fake-fw4" "$env_dir/bin/fw4"
	cp "$SUPPORT/fake-fw4-init" "$env_dir/fw4-init"
	chmod +x "$env_dir/bin/uci" "$env_dir/bin/nft" "$env_dir/bin/fw4" "$env_dir/fw4-init"
	export FAKE_UCI="$env_dir/uci"
	export FAKE_NFT_DIR="$env_dir/nft"
	export FAKE_FW4_INIT_LOG="$env_dir/fw4.log"
	export FAKE_NFT_INSTALLED=0
	export FAKE_NFT_REJECT=0
	export LOG_VIEWER_FUNCTIONS="$SUPPORT/functions.sh"
	export LOG_VIEWER_FIREWALL_CONFIG="$env_dir/no-firewall.conf"
	export LOG_VIEWER_INCLUDE_DIR="$env_dir/include"
	export LOG_VIEWER_FW4_INIT="$env_dir/fw4-init"
	export LOG_VIEWER_WATCH_INIT="$env_dir/fw4-init"
	export LOG_VIEWER_WATCH_BIN="$ROOT/root/usr/sbin/infra-port-watch"
	export LOG_VIEWER_TMP="$env_dir/data"
	PATH="$env_dir/bin:$PATH"
	export PATH
}

uci_set() {
	printf '%s=%s\n' "$1" "$2" >> "$FAKE_UCI"
}

watch_apply() { sh "$ROOT/root/usr/sbin/infra-port-watch" apply; }
watch_get() { sh "$ROOT/root/usr/sbin/infra-port-watch" get; }

# ------------------------------------------------------------------ watch ---

group "watch: probe mode generates a native nftables ruleset"
new_env probe
uci_set infra-port-watch.main.enabled 1
uci_set infra-port-watch.main.mode probe
uci_set infra-port-watch.main.wan_interface eth2
uci_set infra-port-watch.main.ipv6 1
uci_set infra-port-watch.main.log_other_ports 0
uci_set infra-port-watch.main.ports "22 80 443"
check "probe apply succeeds" watch_apply
PROBE="$FAKE_NFT_DIR/applied"
check "probe ruleset checked before apply" file_exists "$FAKE_NFT_DIR/checked"
check "probe table is inet" has "$PROBE" "table inet log_viewer_probe"
check "probe hooks raw prerouting" has "$PROBE" "hook prerouting priority raw"
check "probe matches the WAN device" has "$PROBE" 'iifname "eth2"'
check "probe uses the confirmed prefix set" has "$PROBE" "INFRA_PORT_HIT"
check "probe limits per IPv4 source" has "$PROBE" "ip saddr timeout 2m"
check "probe limits per IPv6 source" has "$PROBE" "ip6 saddr timeout 2m"
check "probe only logs TCP SYNs" has "$PROBE" "tcp flags & (fin|syn|rst|ack) == syn"
check "probe does not use iptables" hasnt "$PROBE" "iptables"
watch_get > "$env_dir/data/status.json" 2>/dev/null || true
check "probe status is valid JSON" json_ok "$env_dir/data/status.json"
check "probe status reports the mode" has "$env_dir/data/status.json" '"mode":"probe"'
check "probe status reports unknown verdicts" has "$env_dir/data/status.json" '"verdict":"unknown"'
check "probe status counts ports" has "$env_dir/data/status.json" '"port_count":3'
check "probe status does not claim installation" has "$env_dir/data/status.json" '"installed":false'

group "watch: verdict mode writes fw4 chain-post includes"
new_env verdict
uci_set infra-port-watch.main.enabled 1
uci_set infra-port-watch.main.mode verdict
uci_set infra-port-watch.main.wan_zone wan
uci_set infra-port-watch.main.wan_interface auto
uci_set infra-port-watch.main.ipv6 0
uci_set infra-port-watch.main.log_other_ports 1
uci_set infra-port-watch.main.ports "22 443"
check "verdict apply succeeds" watch_apply
SET_FILE="$env_dir/include/table-pre/10-log-viewer.nft"
IN_FILE="$env_dir/include/chain-post/input_wan/10-log-viewer.nft"
FWD_FILE="$env_dir/include/chain-post/forward_wan/10-log-viewer.nft"
check "table-pre set exists" file_exists "$SET_FILE"
check "set holds the configured ports" has "$SET_FILE" "elements = { 22, 443 }"
check "input include exists" file_exists "$IN_FILE"
check "forward include exists" file_exists "$FWD_FILE"
check "input include logs confirmed drops" has "$IN_FILE" "INFRA_PORT_BLOCK"
check "input include uses the shared set" has "$IN_FILE" "@lv_watch_ports"
check "input include is IPv4-only when IPv6 is off" hasnt "$IN_FILE" "ip6 saddr"
check "other-port sampling adds a complementary rule" has "$IN_FILE" "tcp dport != @lv_watch_ports"
check "firewall was reloaded once" has "$env_dir/fw4.log" "reload"
check "no probe table was loaded in verdict mode" file_missing "$env_dir/nft/applied"
FAKE_NFT_INSTALLED=1 watch_get > "$env_dir/data/status.json" 2>/dev/null || true
check "verdict status is valid JSON" json_ok "$env_dir/data/status.json"
check "verdict status reports the mode" has "$env_dir/data/status.json" '"mode":"verdict"'
check "verdict status reports confirmed verdicts" has "$env_dir/data/status.json" '"verdict":"confirmed"'
check "verdict status reports the zone" has "$env_dir/data/status.json" '"wan_zone":"wan"'
check "verdict status detects installed rules" has "$env_dir/data/status.json" '"installed":true'

group "watch: a rejected ruleset changes nothing"
new_env reject
uci_set infra-port-watch.main.enabled 1
uci_set infra-port-watch.main.mode probe
uci_set infra-port-watch.main.wan_interface eth2
uci_set infra-port-watch.main.ports "22"
FAKE_NFT_REJECT=1 watch_apply > "$env_dir/data/out" 2>&1
check "rejected ruleset exits non-zero" equals "$?" "1"
check "rejected ruleset explains itself" has "$env_dir/data/out" "rejected by nft"
check "rejected ruleset is never applied" file_missing "$FAKE_NFT_DIR/applied"

group "watch: disabling removes every artifact"
new_env disable
uci_set infra-port-watch.main.enabled 0
uci_set infra-port-watch.main.mode verdict
uci_set infra-port-watch.main.wan_zone wan
uci_set infra-port-watch.main.ports "22"
mkdir -p "$env_dir/include/chain-post/input_wan"
printf 'stale\n' > "$env_dir/include/chain-post/input_wan/10-log-viewer.nft"
watch_apply > "$env_dir/data/out" 2>&1
check "disabled apply succeeds" equals "$?" "0"
check "disabled apply reports disabled" has "$env_dir/data/out" "disabled"
check "disabled apply removes the include" file_missing "$env_dir/include/chain-post/input_wan/10-log-viewer.nft"

group "watch: a zone rename does not leave an orphaned include"
new_env orphan
uci_set infra-port-watch.main.enabled 1
uci_set infra-port-watch.main.mode verdict
uci_set infra-port-watch.main.wan_zone wan
uci_set infra-port-watch.main.ports "22"
watch_apply > /dev/null 2>&1
mkdir -p "$env_dir/include/chain-post/input_lan"
printf 'stale\n' > "$env_dir/include/chain-post/input_lan/10-log-viewer.nft"
uci_set infra-port-watch.main.wan_zone wan2
watch_apply > /dev/null 2>&1
check "the old zone include is gone after a rename" file_missing "$env_dir/include/chain-post/input_lan/10-log-viewer.nft"
check "the new zone include exists" file_exists "$env_dir/include/chain-post/input_wan2/10-log-viewer.nft"

group "watch: configuration writer validates and stores settings"
new_env config
sh "$ROOT/root/usr/sbin/infra-port-watch-config" set 1 verdict wan eth2 1 0 "22,80" > "$env_dir/data/out" 2>&1
writer_status=$?
if [ "$writer_status" -ne 0 ]; then
  printf 'writer exited %s\n' "$writer_status"
  sed -n '1,20p' "$env_dir/data/out"
fi
check "valid settings are accepted" equals "$writer_status" "0"
check "writer stores the mode" has "$env_dir/uci" "infra-port-watch.main.mode=verdict"
check "writer stores the zone" has "$env_dir/uci" "infra-port-watch.main.wan_zone=wan"
check "writer stores IPv6" has "$env_dir/uci" "infra-port-watch.main.ipv6=1"
check "writer stores ports" has "$env_dir/uci" "infra-port-watch.main.ports=22"
check "writer prints status JSON" json_ok "$env_dir/data/out"
sh "$ROOT/root/usr/sbin/infra-port-watch-config" set 1 verdict wan eth2 1 0 "22,99999" >/dev/null 2>&1
check "out-of-range port is rejected" equals "$?" "2"
sh "$ROOT/root/usr/sbin/infra-port-watch-config" set 1 later wan eth2 1 0 "22" >/dev/null 2>&1
check "unknown mode is rejected" equals "$?" "2"
sh "$ROOT/root/usr/sbin/infra-port-watch-config" set 1 verdict "bad zone" eth2 1 0 "22" >/dev/null 2>&1
check "invalid zone is rejected" equals "$?" "2"

# ---------------------------------------------------------------- history ---

make_logread() {
	dir="$1"
	shift
	mkdir -p "$dir/bin"
	{
		printf '#!/bin/sh\n'
		printf "cat <<'EOF'\n"
		for line in "$@"; do printf '%s\n' "$line"; done
		printf 'EOF\n'
	} > "$dir/bin/logread"
	chmod +x "$dir/bin/logread"
}

group "history: restarting does not duplicate the persisted tail"
new_env history
H="$env_dir"
make_logread "$env_dir" \
	"Oct 31 06:00:00 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN" \
	"Oct 31 06:00:01 2026 router kernel: INFRA_PORT_BLOCK: IN=wan SRC=203.0.113.9 DST=192.0.2.1 PROTO=UDP DPT=443"
export PATH="$H/bin:$PATH"
export LOG_VIEWER_RING="$H/data/events.ring"
export LOG_VIEWER_STATUS="$H/data/events.status"
export LOG_VIEWER_BUFFER="$H/data/buffer"
export LOG_VIEWER_STATE_DIR="$H/data"
export LOG_VIEWER_PERSIST=1
export LOG_VIEWER_PERSIST_TEST=1
export LOG_VIEWER_PERSIST_DIR="$H/data/persist"
export LOG_VIEWER_PERSIST_DAYS=7
export LOG_VIEWER_PERSIST_MAX_MB=8
HISTORY="$ROOT/root/usr/sbin/log-viewer-history"
sh "$HISTORY" update > "$H/data/state1.json" 2>/dev/null
sh "$HISTORY" update > "$H/data/state2.json" 2>/dev/null
COUNT=$(cat "$H/data"/persist/firewall-*.log | wc -l | tr -d ' ')
check "two runs keep two unique lines" equals "$COUNT" "2"
check "status JSON is valid after two runs" json_ok "$H/data/state2.json"
rm -f "$H/data/events.ring"
sh "$HISTORY" update > /dev/null 2>&1
COUNT=$(cat "$H/data"/persist/firewall-*.log | wc -l | tr -d ' ')
check "reboot rescan does not duplicate persisted lines" equals "$COUNT" "2"
check "ring is rebuilt after reboot" file_exists "$H/data/events.ring"
sh "$HISTORY" clear > "$H/data/cleared.json" 2>/dev/null
check "clear empties the ring" file_missing "$H/data/events.ring"
check "clear removes the daily files" equals "$(cat "$H/data"/persist/firewall-*.log 2>/dev/null | wc -w | tr -d ' ')" "0"

QUERY="$ROOT/root/usr/sbin/log-viewer-query"

group "query: streaming filters, paging and field anchoring"
Q="$env_dir/query"
mkdir -p "$Q"
cat > "$Q/ring" <<'EOF'
Oct 31 06:00:01 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN
Oct 31 06:00:02 2026 router kernel: INFRA_PORT_BLOCK: MACSRC=198.51.100.77 IN=wan SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP DPT=443 SYN NOTE=pat\h
Oct 31 06:00:03 2026 router kernel: INFRA_PORT_OTHER: IN=wan SRC=203.0.113.10 DST=192.0.2.1 PROTO=UDP DPT=25125
Oct 31 06:00:04 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.11 DST=192.0.2.1 PROTO=TCP DPT=22 SYN
Oct 31 06:00:05 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.12 DST=192.0.2.1 PROTO=TCP DPT=22 SYN
EOF
export LOG_VIEWER_RING="$Q/ring"
export LOG_VIEWER_BUFFER="$Q/buffer"
export LOG_VIEWER_TMP="$Q"
export LOG_VIEWER_PERSIST=0
run_query() { sh "$QUERY" "$@"; }

run_query --limit 2 --offset 0 --order desc > "$Q/run1.json" 2>/dev/null
check "desc page is valid JSON" json_ok "$Q/run1.json"
check "desc counts every line" has "$Q/run1.json" '"total":5'
check "desc starts with the newest line" has "$Q/run1.json" "203.0.113.12"
check "desc honours the page size" has "$Q/run1.json" '"limit":2'

run_query --limit 2 --offset 2 --order desc > "$Q/run2.json" 2>/dev/null
check "desc second page skips the newest" hasnt "$Q/run2.json" "203.0.113.12"
check "desc second page has the third and fourth lines" has "$Q/run2.json" "203.0.113.10"
check "desc second page keeps the fourth line" has "$Q/run2.json" "203.0.113.9"

run_query --limit 2 --order asc > "$Q/asc.json" 2>/dev/null
check "asc starts with the oldest line" has "$Q/asc.json" "203.0.113.8"

run_query --source 198.51.100.77 > "$Q/mac.json" 2>/dev/null
check "source filter ignores MACSRC" has "$Q/mac.json" '"total":0'
run_query --source 203.0.113.9 > "$Q/src.json" 2>/dev/null
check "source filter matches the real SRC" has "$Q/src.json" '"total":1'

run_query --search 'pat\h' > "$Q/backslash.json" 2>/dev/null
check "search keeps a literal backslash" has "$Q/backslash.json" '"total":1'
check "search is not mangled by awk escapes" hasnt "$Q/backslash.json" '"total":0'

run_query --verdict blocked > "$Q/blocked.json" 2>/dev/null
check "blocked filter counts confirmed drops" has "$Q/blocked.json" '"total":1'
run_query --verdict probe > "$Q/probe.json" 2>/dev/null
check "probe filter counts undecided hits" has "$Q/probe.json" '"total":3'
run_query --protocol udp > "$Q/udp.json" 2>/dev/null
check "protocol filter works" has "$Q/udp.json" '"total":1'
run_query --port 22 --limit 10 > "$Q/port.json" 2>/dev/null
check "port filter works" has "$Q/port.json" '"total":3'

run_query --sort source --order asc --limit 2 > "$Q/sortsrc.json" 2>/dev/null
check "source sort is valid JSON" json_ok "$Q/sortsrc.json"
check "source sort orders by address" has "$Q/sortsrc.json" '203.0.113.10'
run_query --sort port --order desc --limit 1 > "$Q/sortport.json" 2>/dev/null
check "port sort puts the highest port first" has "$Q/sortport.json" "25125"

check "queries leave no temporary directory behind" equals "$(find "$Q" -maxdepth 1 -name 'log-viewer-query.*' | wc -l | tr -d ' ')" "0"

# ----------------------------------------------------------------- geoip ---

group "geoip: shell fallback emits newline-delimited JSON"
new_env geoip
G="$env_dir"
mkdir -p "$G/data/db" "$G/bin"
printf 'stub' > "$G/data/db/GeoLite2-Country.mmdb"
printf 'stub' > "$G/data/db/GeoLite2-ASN.mmdb"
cp "$SUPPORT/fake-mmdblookup" "$G/bin/mmdblookup"
chmod +x "$G/bin/mmdblookup"
export PATH="$G/bin:$PATH"
export GEOIP_DB_DIR="$G/data/db"
export LOG_VIEWER_GEOIP_HELPER="$G/bin/does-not-exist"
sh "$ROOT/root/usr/bin/flint4-geoip" --batch 1.2.3.4 not-an-ip > "$G/data/batch.ndjson" 2>/dev/null
check "batch emits two lines for two addresses" equals "$(wc -l < "$G/data/batch.ndjson" | tr -d ' ')" "2"
check "batch reports country" has "$G/data/batch.ndjson" '"country_code":"DE"'
check "batch reports the country name" has "$G/data/batch.ndjson" '"country_name":"Germany"'
check "batch reports the ASN" has "$G/data/batch.ndjson" '"asn":"3320"'
check "batch reports the ASN organisation" has "$G/data/batch.ndjson" '"asn_organization":"Deutsche Telekom AG"'
check "batch flags the invalid address" has "$G/data/batch.ndjson" '"error":"invalid ip"'
sh "$ROOT/root/usr/bin/flint4-geoip" --status > "$G/data/status.json" 2>/dev/null
check "status is valid JSON" json_ok "$G/data/status.json"
check "status reports availability" has "$G/data/status.json" '"available":true'
check "status exposes the database size" has "$G/data/status.json" '"country_bytes":4'

# ------------------------------------------------------------ geoip update ---

group "geoip: updater finishes on the shipped empty checksum defaults"
new_env geoipupdate
U="$env_dir"
mkdir -p "$U/data/geodb" "$U/data/scratch"
printf 'country-db' > "$U/data/country.mmdb"
printf 'asn-db' > "$U/data/asn.mmdb"
# The shipped configuration has empty sha256_country and sha256_asn values.
uci_set log-viewer.geoip.directory "$U/data/geodb"
uci_set log-viewer.geoip.url "https://example.invalid/geolite"
uci_set log-viewer.geoip.sha256_country ""
uci_set log-viewer.geoip.sha256_asn ""
cp "$SUPPORT/fake-mmdblookup" "$env_dir/bin/mmdblookup"
cp "$SUPPORT/fake-uclient-fetch" "$env_dir/bin/uclient-fetch"
chmod +x "$env_dir/bin/mmdblookup" "$env_dir/bin/uclient-fetch"
export FAKE_COUNTRY_FILE="$U/data/country.mmdb"
export FAKE_ASN_FILE="$U/data/asn.mmdb"
export GEOIP_DB_DIR="$U/data/geodb"
export GEOIP_UPDATE_TMP="$U/data/scratch"
export GEOIP_UPDATE_STATUS="$U/data/geo.status"
export GEOIP_UPDATE_LOCK="$U/data/geo.lock"
export FAKE_FETCH_FAIL=0
UPDATER="$ROOT/root/usr/bin/flint4-geoip-update"

sh "$UPDATER" > "$U/data/out" 2>&1
check "updater exits 0 with empty checksum options" equals "$?" "0"
check "updater writes a complete status" has "$U/data/geo.status" '"state":"complete"'
check "updater applies the country database" file_exists "$U/data/geodb/GeoLite2-Country.mmdb"
check "updater applies the ASN database" file_exists "$U/data/geodb/GeoLite2-ASN.mmdb"
check "updater leaves no staging files" file_missing "$U/data/geodb/GeoLite2-Country.mmdb.new"
check "update status is valid JSON" json_ok "$U/data/geo.status"

sh "$ROOT/root/usr/bin/flint4-geoip" --status > "$U/data/lookup-status.json" 2>/dev/null
check "lookup status is valid JSON" json_ok "$U/data/lookup-status.json"
check "lookup sees the installed databases" has "$U/data/lookup-status.json" '"available":true'

group "geoip: updater reports a failed download"
export FAKE_FETCH_FAIL=1
sh "$UPDATER" > "$U/data/fail.out" 2>&1
check "failed download exits non-zero" equals "$?" "1"
check "failed download records an error state" has "$U/data/geo.status" '"state":"error"'
check "failed download explains itself" has "$U/data/geo.status" "Could not download"
check "failed download keeps the previous database" equals "$(cat "$U/data/geodb/GeoLite2-Country.mmdb")" "country-db"
check "failed download prints the reason" has "$U/data/fail.out" "Could not download"
export FAKE_FETCH_FAIL=0

group "geoip: a checksum pin mismatch aborts before replacing anything"
export GEOIP_SHA256_COUNTRY="0000000000000000000000000000000000000000000000000000000000000000"
sh "$UPDATER" > "$U/data/sha.out" 2>&1
check "checksum mismatch exits non-zero" equals "$?" "1"
check "checksum mismatch records an error" has "$U/data/geo.status" 'checksum mismatch'
check "checksum mismatch keeps the previous database" equals "$(cat "$U/data/geodb/GeoLite2-Country.mmdb")" "country-db"
unset GEOIP_SHA256_COUNTRY

group "geoip: lookup works when the geoip UCI section is missing"
new_env geipnouci
L="$env_dir"
mkdir -p "$L/data/db"
printf 'x' > "$L/data/db/GeoLite2-Country.mmdb"
printf 'y' > "$L/data/db/GeoLite2-ASN.mmdb"
cp "$SUPPORT/fake-mmdblookup" "$env_dir/bin/mmdblookup"
cp "$SUPPORT/fake-geoip-helper" "$env_dir/bin/log-viewer-geoip"
chmod +x "$env_dir/bin/mmdblookup" "$env_dir/bin/log-viewer-geoip"
# PATH still has the fake uci, but the database has no log-viewer.geoip keys,
# which is what a half-migrated router looks like. The native helper keeps the
# test independent of the default database path.
unset GEOIP_DB_DIR
export LOG_VIEWER_GEOIP_HELPER="$env_dir/bin/log-viewer-geoip"
sh "$ROOT/root/usr/bin/flint4-geoip" --batch 1.2.3.4 > "$L/data/out.ndjson" 2>"$L/data/err"
check "lookup survives an empty geoip section" equals "$?" "0"
check "lookup still answers the address" has "$L/data/out.ndjson" '"country_code":"DE"'
check "lookup prints one line" equals "$(wc -l < "$L/data/out.ndjson" | tr -d ' ')" "1"

# -------------------------------------------------------------- migration ---


group "upgrade: 3.x configuration migrates without losing settings"
new_env migrate
uci_set log-viewer.main history
uci_set log-viewer.main.enabled 1
uci_set log-viewer.main.directory /mnt/usb/logs
uci_set log-viewer.main.days 30
uci_set log-viewer.main.max_mb 64
uci_set infra-port-watch.main.enabled 1
uci_set infra-port-watch.main.wan_interface pppoe-wan
uci_set infra-port-watch.main.ports 2222
sh "$ROOT/root/usr/sbin/log-viewer-migrate" > "$env_dir/data/out" 2>&1
check "migration succeeds" equals "$?" "0"
check "migration creates the history section" has "$env_dir/uci" "log-viewer.history=history"
check "migration carries the history switch" has "$env_dir/uci" "log-viewer.history.enabled=1"
check "migration carries the history directory" has "$env_dir/uci" "log-viewer.history.directory=/mnt/usb/logs"
check "migration carries retention" has "$env_dir/uci" "log-viewer.history.days=30"
check "migration adds the ring size" has "$env_dir/uci" "log-viewer.history.ring=500"
check "migration adds the geoip section" has "$env_dir/uci" "log-viewer.geoip=geoip"
check "migration sets the default mode" has "$env_dir/uci" "infra-port-watch.main.mode=verdict"
check "migration keeps the saved WAN device" has "$env_dir/uci" "infra-port-watch.main.wan_interface=pppoe-wan"
check "migration keeps the saved port" has "$env_dir/uci" "infra-port-watch.main.ports=2222"
if [ -f "$env_dir/uci" ]; then
	check "migration removes the old section" hasnt "$env_dir/uci" "log-viewer.main."
else
	no "uci database disappeared"
fi
sh "$ROOT/root/usr/sbin/log-viewer-migrate" > /dev/null 2>&1
check "migration is idempotent" has "$env_dir/uci" "log-viewer.history.enabled=1"

# ------------------------------------------------------------------ done ---

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
