# Changelog

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
