# luci-app-log v4.0.0

OpenWrt 25.12 release. The package name remains `luci-app-log-viewer`. IPv4 and IPv6.

## What changed

**Blocked now means blocked.** The watcher is injected into the firewall chain
after every allow rule, so a `Blocked` row is a packet the firewall evaluated
and the zone policy dropped. The old behaviour (log first, guess later) is still
available as **probe mode**, and those rows are labelled **Probe** with a note
that the verdict was not observed.

The watcher is now native nftables: no iptables, no `iptables-mod-hashlimit`, no
xtables compatibility layer. Logging is limited per source address, covers IPv6,
and the generated rules are validated before they are applied.

**Nothing leaves the router.** Country and ASN come from a local GeoLite2
database, now read by a small helper that answers a whole batch in one process.

## Upgrading from 3.x

Run the installer again, or `apk add --upgrade` the two packages from the
release. The upgrade:

- moves the old `log-viewer.main` section to `log-viewer.history` and keeps its values;
- adds the new `mode`, `wan_zone`, `ipv6` and `ring` options and leaves your ports and WAN device alone;
- removes the 3.x iptables rules and restarts both services;
- keeps `/etc/config/infra-port-watch`, your history directory and your saved ports.

**One permission change:** settings, history retention and GeoIP updates now
require the `luci-app-log-viewer-admin` group. `root` has it implicitly. If you
gave a non-root account this page in 3.x, add that account to the new group in
**System → Administration**, otherwise it keeps read-only access.

## After upgrading

1. Open **Status → Firewall Log**.
2. **Settings → WAN watch settings**: check that the WAN zone is the zone name
   from **Network → Firewall** (default `wan`) and that the mode is
   **Confirmed drops only**.
3. Press **Save settings**. If the status line says *rules not detected*, press
   **Re-apply rules**.
4. Optional: **Settings → Files → Update GeoIP databases**.

Probe mode is there when you want to see attempts against forwarded ports, but
it cannot confirm verdicts, and the page says so.

GeoLite2 databases are not in the APK. See the README for the MaxMind EULA.
