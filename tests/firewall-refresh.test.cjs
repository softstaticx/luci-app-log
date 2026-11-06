const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/log-viewer/firewall.css'), 'utf8');

function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} must be a top-level function`);
  const next = source.indexOf('\nfunction ', start + 1);
  const body = source.slice(start, next === -1 ? source.length : next);
  return new Function(`${body}\nreturn ${name};`)();
}

test('GeoIP batches stay under the rpcd argument limit', () => {
  const geoBatchChunks = extract('geoBatchChunks');
  const ips = Array.from({length: 80}, (_, i) => `203.0.113.${i % 250}`);
  const chunks = geoBatchChunks(ips, 900);
  assert.ok(chunks.length > 1);
  assert.equal(chunks.flat().length, ips.length);
  chunks.forEach(chunk => {
    const bytes = '--batch'.length + chunk.reduce((sum, ip) => sum + 1 + ip.length, 0);
    assert.ok(bytes <= 900, `chunk is ${bytes} bytes`);
  });
  assert.deepEqual(geoBatchChunks([], 900), []);
});

test('positive GeoIP hits are remembered and misses are not kept for a week', () => {
  const readGeoMemory = extract('readGeoMemory');
  const writeGeoMemory = extract('writeGeoMemory');
  const now = Date.UTC(2026, 9, 31, 5, 0, 0);
  let store = writeGeoMemory({}, '203.0.113.8', {
    country_code: 'DE', country_name: 'Germany', asn_organization: 'Example'
  }, now, 2);
  store = writeGeoMemory(store, '198.51.100.9', {
    country_code: 'US', country_name: 'United States', asn_organization: 'Other'
  }, now + 1000, 2);
  store = writeGeoMemory(store, '192.0.2.10', {
    country_code: 'JP', country_name: 'Japan', asn_organization: 'Third'
  }, now + 2000, 2);
  assert.equal(store['203.0.113.8'], undefined);
  assert.equal(store['192.0.2.10'].country_code, 'JP');
  const loaded = readGeoMemory(JSON.stringify(store), now + 2000 + 6 * 86400000, 7 * 86400000);
  assert.equal(loaded['192.0.2.10'].country_name, 'Japan');
  const expired = readGeoMemory(JSON.stringify(store), now + 2000 + 8 * 86400000, 7 * 86400000);
  assert.deepEqual(expired, {});
  assert.deepEqual(readGeoMemory('{', now, 1000), {});
});

test('watch status stays fresh for a minute instead of reloading on every live tick', () => {
  const watchConfigIsFresh = extract('watchConfigIsFresh');
  assert.equal(watchConfigIsFresh(0, 1000, 60000), false);
  assert.equal(watchConfigIsFresh(1000, 50000, 60000), true);
  assert.equal(watchConfigIsFresh(1000, 61000, 60000), false);
  assert.match(source, /WATCH_CONFIG_TTL_MS = 60000/);
  const refresh = source.slice(source.indexOf('refreshEvents:'), source.indexOf('enrichAndRender:'));
  assert.match(refresh, /loadWatchConfig\(false\)/);
  assert.doesNotMatch(refresh, /loadWatchConfig\(true\)/);
});

test('search tokens are parsed, validated and degraded to free text', () => {
  const parseQuery = extract('parseQuery');
  assert.deepEqual(parseQuery('22 jellyfin'), {
    words: ['22', 'jellyfin'], port: null, country: '', asn: '', proto: '', verdict: '', source: '', afterMs: 0
  });
  const query = parseQuery('port:22 country:cn verdict:blocked proto:udp src:203.0.113.9 after:1h asn:telekom');
  assert.equal(query.port, 22);
  assert.equal(query.country, 'CN');
  assert.equal(query.verdict, 'blocked');
  assert.equal(query.proto, 'udp');
  assert.equal(query.source, '203.0.113.9');
  assert.equal(query.afterMs, 3600000);
  assert.equal(query.asn, 'telekom');
  assert.deepEqual(query.words, []);
  const invalid = parseQuery('port:99999 country:zzz verdict:nope proto:sctp after:9h');
  assert.equal(invalid.port, null);
  assert.equal(invalid.country, '');
  assert.equal(invalid.verdict, '');
  assert.equal(invalid.proto, '');
  assert.equal(invalid.afterMs, 0);
  assert.deepEqual(invalid.words, ['port:99999', 'country:zzz', 'verdict:nope', 'proto:sctp', 'after:9h']);
  assert.equal(extract('queryIsEmpty')(parseQuery('')), true);
  assert.equal(extract('queryIsEmpty')(parseQuery('port:22')), false);
});

test('filters are mirrored into the URL so a view can be shared', () => {
  assert.match(source, /loadUrlState: function/);
  assert.match(source, /saveUrlState: function/);
  assert.match(source, /new URLSearchParams\(location\.search\)/);
  assert.match(source, /history\.replaceState/);
  assert.match(source, /this\.saveUrlState\(\)/);
  assert.match(source, /Copy view link/);
  assert.match(source, /params\.get\(key\)/);
  assert.match(source, /params\.get\('q'\)/);
});

test('an insight filter describes itself and settings are grouped by job', () => {
  const insightFilterText = extract('insightFilterText');
  assert.equal(insightFilterText('', null, null), '');
  assert.equal(insightFilterText('203.0.113.8', 22, null), '203.0.113.8 · port 22');
  assert.equal(insightFilterText('', null, {start: 1, end: 2}), 'time bar');
  assert.match(source, /summary', \{\}, _\('Settings'\)\)/);
  assert.doesNotMatch(source, /_\('More options'\)/);
  assert.match(source, /fw-settings-watch/);
  assert.match(source, /fw-settings-labels/);
  assert.match(source, /fw-settings-history/);
  assert.match(source, /fw-settings-files/);
  assert.match(source, /handleSaveApply: null/);
  assert.match(source, /Confirmed drops only/);
  assert.match(source, /value: 'probe'/);
  assert.match(source, /verdictKnown/);
  assert.match(source, /value: 'other'/);
  assert.doesNotMatch(source, /WAN watchlist/);
  assert.match(source, /fw-primary-toolbar[\s\S]{0,500}this\.presets/);
  assert.doesNotMatch(source, /_\('Clear insight filters'\)/);
});

test('the table is readable, responsive and honest about verdicts', () => {
  assert.match(source, /data-label=/);
  assert.match(source, /fw-' \+ kindClass/);
  assert.match(source, /e\.kind === 'Probe'/);
  assert.match(source, /Log this port at the full budget/);
  assert.match(source, /event\.kind === 'Other'/);
  assert.match(css, /\.fw-table[\s\S]*min-width: 960px/);
  assert.match(css, /font-size: 13px/);
  assert.match(css, /\.fw-stat strong[\s\S]*font-size: 22px/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*data-label|@media \(max-width: 760px\)[\s\S]*attr\(data-label\)/);
  assert.match(css, /\.fw-table td::before/);
  assert.match(css, /\.fw-badge\.probe/);
});

test('a missing GeoIP database is shown as off, not as a silent blank', () => {
  assert.match(source, /fw-geo-banner/);
  assert.match(source, /this\.geoBanner\.hidden = available/);
  assert.match(source, /GeoIP is off: no local databases are installed/);
  assert.match(source, /GeoIP off · no local databases/);
  assert.match(source, /_\('GeoIP off'\)/);
  assert.match(source, /GeoIP lookups are failing: /);
  assert.match(css, /\.fw-geo-banner/);
});

test('a successful database update clears cached misses and fills the table', () => {
  assert.match(source, /this\.geoCache = \{\};/);
  assert.match(source, /this\.geoCacheAt = \{\};/);
  assert.match(source, /this\.geoLookupError = '';/);
  const update = source.slice(source.indexOf('updateGeoDatabases: async function'), source.indexOf('getTimeWindowMs: function'));
  assert.match(update, /this\.enrichAndRender\(\);/);
  assert.match(update, /status\.state === 'error'/);
  assert.match(update, /databases are still unavailable/);
});

test('the lookup wrapper falls back to mmdblookup when the helper is broken', () => {
  const wrapper = fs.readFileSync(path.join(__dirname, '../root/usr/bin/flint4-geoip'), 'utf8');
  assert.ok(wrapper.includes('helper_out="$("$HELPER" --db "$DB_DIR" --batch "$@"'));
  assert.ok(wrapper.includes('if [ -n "$helper_out" ]'));
  assert.ok(wrapper.includes('for ip in "$@"; do'));
});
test('the page inherits the LuCI theme instead of shipping its own palette', () => {
  assert.match(source, /L\.resource\('log-viewer\/firewall\.css'\)/);
  assert.doesNotMatch(source, /--mp-bg/, 'the hard-coded palette must be gone');
  assert.match(css, /var\(--background-color-high, Canvas\)/);
  assert.match(css, /var\(--text-color-high, CanvasText\)/);
  assert.match(css, /prefers-color-scheme|CanvasText/);
  assert.match(css, /@media \(prefers-reduced-motion/);
  assert.match(css, /@media print/);
});

test('missing default ports are appended and GeoIP can be refreshed from settings', () => {
  const mergeMissingDefaultPorts = extract('mergeMissingDefaultPorts');
  const listed = source.match(/const DEFAULT_WATCH_PORTS = \[([^\]]+)\]/);
  assert.ok(listed, 'the page must carry the default watch ports');
  const defaults = listed[1].split(',').map(item => Number(item.trim()));
  const uci = fs.readFileSync(path.join(__dirname, '../root/etc/config/infra-port-watch'), 'utf8');
  const shipped = [...uci.matchAll(/list ports '(\d+)'/g)].map(match => Number(match[1]));
  assert.deepEqual(defaults, shipped);

  assert.deepEqual(mergeMissingDefaultPorts('25125,22', [22, 80, 443]), {
    ok: true, added: [80, 443], ports: '25125,22,80,443'
  });
  assert.deepEqual(mergeMissingDefaultPorts('22, 80', [22, 80]), {
    ok: true, added: [], ports: '22,80'
  });
  assert.equal(mergeMissingDefaultPorts('nope', [22]).ok, false);
  const full = Array.from({length: 256}, (_, i) => i + 1).join(',');
  assert.equal(mergeMissingDefaultPorts(full, [700]).reason, 'full');

  assert.match(source, /Add missing default ports/);
  assert.match(source, /Update GeoIP databases/);
  assert.match(source, /\/usr\/bin\/flint4-geoip-update/);
});

test('server history, sorting, chips and the source drawer are wired', () => {
  assert.match(source, /openServerHistory/);
  assert.match(source, /log-viewer-query/);
  assert.match(source, /--days/);
  assert.match(source, /sorted the most recent 2,000 matches/);
  assert.match(source, /log-viewer-history', \[\s*'configure'/);
  assert.match(source, /openIpDrawer/);
  assert.match(source, /log-viewer-ip/);
  assert.match(source, /fw-source-link/);
  assert.match(source, /sortEvents/);
  assert.match(source, /fw-chips/);
  assert.match(source, /renderChips/);
  assert.match(source, /geoip-update\.status/);
  assert.match(source, /formatBytes/);
});

test('known ports are shown by default and other-port sampling is opt-in', () => {
  assert.match(source, /kindFilter: 'known'/);
  assert.match(source, /Known ports only/);
  assert.match(source, /Also sample other ports/);
  assert.match(source, /log_other_ports/);
  assert.match(source, /otherSample\.checked/);
});

test('modals use the LuCI 25.12 showModal signature and keep actions in content', () => {
  assert.equal((source.match(/ui\.showModal\(/g) || []).length, 9);
  assert.equal((source.match(/'fw-modal'/g) || []).length, 9);
  assert.match(source, /fw-modal-actions/);
  assert.match(source, /fw-watch-grid/);
  assert.match(source, /fw-watch-status/);
  assert.match(source, /this\.eventById = new Map/);
  assert.match(source, /this\.eventById\.get/);
  assert.doesNotMatch(source, /_\('Edit WAN watch'/);
  assert.match(source, /_\('WAN watch settings'\)/);
});

test('empty or malformed watch status is treated as unavailable', () => {
  const parseWatchConfig = extract('parseWatchConfig');
  assert.equal(parseWatchConfig(''), null);
  assert.equal(parseWatchConfig('{}'), null);
  assert.equal(parseWatchConfig('null'), null);
  assert.equal(parseWatchConfig('{'), null);
  assert.deepEqual(parseWatchConfig('{"enabled":true,"wan_interface":"auto","ports":"22"}'), {
    enabled: true, wan_interface: 'auto', ports: '22'
  });
  assert.match(source, /const config = parseWatchConfig\(raw\);/);
  assert.match(source, /const savedConfig = parseWatchConfig\(raw\);/);
  assert.match(source, /if \(!savedConfig\) throw new Error/);
  assert.match(source, /if \(!updated\) throw new Error/);
  assert.match(source, /if \(!imported\) throw new Error/);

  const watchEnabled = extract('watchEnabled');
  assert.equal(watchEnabled(null), true);
  assert.equal(watchEnabled({enabled: false}), false);
  assert.equal(watchEnabled({enabled: 0}), false);
  assert.equal(watchEnabled({enabled: '0'}), false);
  assert.equal(watchEnabled({enabled: true}), true);

  const watchInstalled = extract('watchInstalled');
  assert.equal(watchInstalled(null), false);
  assert.equal(watchInstalled({installed: false}), false);
  assert.equal(watchInstalled({installed: true}), true);
});
