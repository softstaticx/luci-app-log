# Changelog

## v4.0.3 (2026-11-06)

### GeoIP diagnostics

- `flint4-geoip --status` now performs one real lookup against the country
  database and reports a `reason`: `no database`, `mmdblookup missing` or
  `database unreadable`. A truncated file is no longer reported as available.
- A lookup without a database or without `mmdblookup` returns an explicit
  `{"error":"no database"}` / `{"error":"no mmdblookup"}` record instead of an
  empty object, so the page can explain itself.
- The GeoIP banner uses that reason (`GeoIP off · no database`, …) and points at
  the update button.
- Shell tests cover missing, corrupt and unreadable database states, and each
  test case now starts from a clean environment.

## v4.0.2 (2026-11-06)

### GeoIP

- The lookup wrapper no longer `exec`s the native helper blindly. It captures
  the helper's output and falls back to `mmdblookup(1)` when the helper produces
  nothing, so a broken or missing `/usr/libexec/log-viewer-geoip` no longer turns
  every lookup into a silent miss.
- The page now says **GeoIP off** and shows a banner with an update button when
  no databases are installed, instead of printing "unavailable" on every row.
- Lookup failures are reported once with the actual reason ("no database",
  "invalid ip", …) instead of being cached as empty results.
- After a successful update the miss cache is cleared and the table is enriched
  immediately; previously it kept empty entries for up to five minutes and only
  refreshed on the next tick.

### Tests

- New CI job compiles the helper against the real libmaxminddb, downloads
  MaxMind's public test databases, and asserts that `2.125.160.216` resolves to
  `GB`, both through the native helper and through the `mmdblookup` fallback.

## v4.0.1 (2026-11-06)

GeoIP updates were broken on a default 4.0.0 install. Two shell bugs made the
updater exit before it printed anything, and the page then reported success
because cgi-io answers 200 even for a failed command.

### Fixed

- **GeoIP updater aborted silently.** `load_uci()` ended with
  `[ -n "$v" ] && VAR="$v"`. With the shipped empty `sha256_country` and
  `sha256_asn` options the function returned 1, and `set -e` exited the script.
  Every branch is now an explicit `if`, and the function returns 0.
- **Stderr was swallowed.** `exec 9>"$LOCK" 2>/dev/null` applies its
  redirections to the whole shell, so the updater (and the history collector)
  lost every error message. The lock no longer redirects stderr.
- **The page claimed success for failed writes.** cgi-io always returns
  `200 OK` for cgi-exec, so the promise resolving means nothing. Settings
  saves, history changes, clearing history, re-applying rules and GeoIP updates
  now verify the JSON/status the script produced and surface the failure.
- **The installer hid the reason.** It now prints the updater's own output and
  the status file when a GeoIP refresh fails.
- `flint4-geoip` had the same `set -e` pattern when the `geoip` UCI section was
  missing; it now works on a half-migrated configuration.
- The 3.x history-section migration used the same pattern for empty options.

### Tests

- The GeoIP updater is now executed by the shell suite: empty checksum
  defaults, a failed download, a checksum-pin mismatch, and a lookup on a
  router without a `geoip` section. These tests fail on 4.0.0.

## v4.0.0 (2026-11-06)

The "confirmed verdicts" release. The watcher moved from iptables to native
nftables, and the page now distinguishes a packet the firewall really dropped
from a probe whose verdict was never observed.

### Verdicts

- Emit `INFRA_PORT_BLOCK` from fw4 chain-post includes on `input_<zone>` and
  `forward_<zone>`. The rule sits after every allow rule and before the zone
  policy, so a **Blocked** row is a fact, not an inference. Default mode.
- Keep raw-prerouting logging as an opt-in **probe** mode. Its rows are labelled
  **Probe** and the page, the details panel and the status line all state that
  the verdict was not observed.
- Show the verdict source in event details ("Confirmed by the firewall" vs
  "Not observed (probe mode)").
- Restore explicit accept logs as **Allowed**; drop the old heuristic that
  treated any allow/forward label as proof.

### Watcher

- Rewrite `/usr/sbin/infra-port-watch` on nftables: no iptables, no
  `iptables-mod-hashlimit`, no xtables compatibility shim.
- Per-source meters replace hashlimit; IPv6 is logged alongside IPv4.
- Verdict includes are picked up by fw4 automatically and survive fw4 reloads.
  A generated ruleset is validated with `nft -c` and with the rendered firewall
  before anything is applied; a bad file is rolled back.
- Remove 3.x iptables chains on upgrade.
- Add **Re-apply rules** for the case where `fw4 flush`/`firewall stop` removed
  every table.

### History

- Stop duplicating the persisted tail on every restart: the collector resumes
  after the last persisted line and only rebuilds the ring after a reboot.
- Configurable ring size (100–5000 lines) in the UI.
- `flock` around every writer, a PID file for the collector, and a throttle on
  directory pruning.
- Rewrite `/usr/sbin/log-viewer-query` as a streaming pass: no more full copies
  of the history in `/tmp` (a 32 MB history needed ~128 MB of RAM before).
- Fix `--source` matching `MACSRC=` and fix `--search` mangling backslashes.
- Add `--days` for age-bounded searches and report when a source/port sort only
  covered the most recent 2,000 matches.
- Move the shipped section from `log-viewer.main` to `log-viewer.history` and
  migrate it automatically.

### GeoIP

- Add `log-viewer-geoip`, a small C helper that keeps both databases mapped and
  answers a whole batch in one process. The shell implementation remains as a
  fallback.
- Emit newline-delimited JSON; the page also still reads a 3.x object payload.
- Serialise updates with a lock, check free space, support checksum pins and a
  configurable database directory/mirror, and validate downloads with
  `mmdblookup` before replacing anything.

### UI

- Inherit the active LuCI theme through its CSS variables instead of forcing a
  hard-coded palette; light, dark and legacy themes all work.
- Card layout below 760 px so the page is usable on a phone.
- Mirror filters into the URL and add **Copy view link**.
- Add `port:`, `country:`, `asn:`, `proto:`, `verdict:`, `src:` and `after:`
  search tokens.
- Add a history age filter, "Re-apply rules", and the new mode/zone/IPv6 fields.
- Move the stylesheet out of the view into `log-viewer/firewall.css`.

### Security and packaging

- Split the ACL: read-only access keeps the menu entry, while settings, history
  retention, GeoIP updates and destructive actions require
  `luci-app-log-viewer-admin`. The collector no longer grants every subcommand
  to the read group.
- Bound reverse DNS with `timeout` and validate the address properly.
- Single-source the version in `VERSION`; the Makefile, installer and tests read
  it.
- Add `.gitattributes` (LF for scripts), ShellCheck and a 93-case shell
  integration suite, plus `dash -n` and C syntax checks to CI.
- Build the GeoIP helper in the package and drop `PKGARCH:=all`.

### Fixes

- Persistent history no longer grows on every service restart.
- The shipped `log-viewer` conffile is now actually read.
- `install.sh` no longer misses the log-viewer configuration.
- `uninstall.sh` removes generated nftables includes and the watch table.

## v3.3.5 (2026-11-01)
