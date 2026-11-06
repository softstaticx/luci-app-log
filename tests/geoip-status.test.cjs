const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const updater = fs.readFileSync(path.join(__dirname, '../root/usr/bin/flint4-geoip-update'), 'utf8');
const view = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');
const acl = JSON.parse(fs.readFileSync(path.join(__dirname, '../root/usr/share/rpcd/acl.d/luci-app-log-viewer.json'), 'utf8'));

test('GeoIP updater exposes progress and the page polls it', () => {
  assert.match(updater, /set_status/);
  assert.match(updater, /--status/);
  assert.match(updater, /set_status validating/);
  assert.match(updater, /set_status applying/);
  assert.match(updater, /set_status complete/);
  assert.match(view, /geoip-update\.status/);
  assert.match(view, /fs\.exec_direct\('\/usr\/bin\/flint4-geoip-update'/);
  assert.match(view, /state === 'complete'/);
  assert.ok(Object.keys(acl['luci-app-log-viewer'].read.file).includes('/tmp/log-viewer/geoip-update.status'));
  assert.ok(Object.keys(acl['luci-app-log-viewer-admin'].write.file).includes('/usr/bin/flint4-geoip-update'));
});

test('GeoIP update is serialised and verifies what it downloads', () => {
  assert.match(updater, /flock/);
  assert.match(updater, /require_space/);
  assert.match(updater, /sha256/);
  assert.match(updater, /sha256_country/);
  assert.match(updater, /sha256_asn/);
  assert.match(updater, /mmdblookup --file "\$TMP\/GeoLite2-Country\.mmdb" --ip 8\.8\.8\.8/);
  assert.match(updater, /mmdblookup --file "\$TMP\/GeoLite2-ASN\.mmdb" --ip 8\.8\.8\.8/);
  assert.match(updater, /mv "\$BASE\/GeoLite2-Country\.mmdb\.new"/);
});

test('the page streams GeoIP answers as newline-delimited JSON', () => {
  assert.match(view, /flint4-geoip', \['--batch'\]/);
  assert.match(view, /text\.split\('\\n'\)/);
  assert.match(view, /function parseGeoBatch/);
  assert.match(view, /parseGeoBatch\(raw\)/);
});

test('the packaged helper is documented as falling back to the shell implementation', () => {
  const script = fs.readFileSync(path.join(__dirname, '../root/usr/bin/flint4-geoip'), 'utf8');
  assert.match(script, /\/usr\/libexec\/log-viewer-geoip/);
  assert.ok(script.includes('helper_out="$("$HELPER" --db "$DB_DIR" --batch "$@"'));
  assert.ok(script.includes('for ip in "$@"; do'));
  assert.match(script, /log-viewer\.geoip\.directory/);
});
