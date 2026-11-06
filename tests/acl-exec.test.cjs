const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const acl = JSON.parse(fs.readFileSync(path.join(__dirname, '../root/usr/share/rpcd/acl.d/luci-app-log-viewer.json'), 'utf8'));
const view = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');
const read = acl['luci-app-log-viewer'];
const admin = acl['luci-app-log-viewer-admin'];

test('the page keeps its menu ACL group and adds a separate admin group', () => {
  assert.ok(read, 'read group must keep the menu dependency name');
  assert.ok(admin, 'admin group must exist for settings and destructive actions');
  assert.deepEqual(admin.write.ubus.file, ['exec']);
});

test('read access is granted on exact read-only command lines', () => {
  const files = Object.keys(read.read.file);
  assert.ok(files.includes('/usr/sbin/infra-port-watch get'));
  assert.ok(files.includes('/usr/sbin/log-viewer-history status'));
  assert.ok(!files.includes('/usr/sbin/log-viewer-history'),
    'the bare collector path would allow any subcommand, including clear');
  assert.ok(read.read.ubus.file.includes('read'));
  assert.ok(read.read.ubus.file.includes('exec'));
  assert.ok(read.read.ubus.log.includes('read'));
});

test('destructive and configuration verbs live only in the admin group', () => {
  const adminFiles = Object.keys(admin.write.file);
  for (const grant of [
    '/usr/sbin/infra-port-watch-config',
    '/usr/sbin/infra-port-watch',
    '/usr/sbin/log-viewer-history configure',
    '/usr/sbin/log-viewer-history clear',
    '/usr/bin/flint4-geoip-update'
  ]) assert.ok(adminFiles.includes(grant), `admin group must grant ${grant}`);
  assert.ok(!Object.keys(read.read.file).includes('/usr/bin/flint4-geoip-update'));
  assert.ok(!Object.keys(read.read.file).includes('/usr/sbin/log-viewer-history configure'));
});

test('log reading is allowed through ubus and the OpenWrt 25.12 logread path', () => {
  assert.ok(Object.keys(read.read.file).includes('/usr/libexec/logread-ubox*'));
  assert.match(view, /object: 'log'/);
  assert.match(view, /\/usr\/libexec\/logread-ubox/);
});

test('GeoIP reads stay in the read group and updates require the admin group', () => {
  assert.ok(Object.keys(read.read.file).includes('/usr/bin/flint4-geoip'));
  assert.deepEqual(admin.write.file['/usr/bin/flint4-geoip-update'], ['exec']);
});

test('server history, reverse DNS, and update status paths are readable', () => {
  const readPaths = Object.keys(read.read.file);
  assert.ok(readPaths.includes('/usr/sbin/log-viewer-query'));
  assert.ok(readPaths.includes('/usr/sbin/log-viewer-ip'));
  assert.ok(readPaths.includes('/tmp/log-viewer/events.status'));
  assert.ok(readPaths.includes('/tmp/log-viewer/geoip-update.status'));
  assert.ok(readPaths.includes('/tmp/log-viewer/events.ring'));
  assert.ok(readPaths.includes('/etc/log-viewer/policies.json'));
});
