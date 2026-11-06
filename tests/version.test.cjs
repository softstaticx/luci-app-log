const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');
const version = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim();
const makefile = fs.readFileSync(path.join(root, 'Makefile'), 'utf8');
const installer = fs.readFileSync(path.join(root, 'install-online.sh'), 'utf8');
const changelog = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
const notes = fs.readFileSync(path.join(root, '.github/RELEASE_NOTES.md'), 'utf8');
const menu = JSON.parse(fs.readFileSync(path.join(root, 'root/usr/share/luci/menu.d/luci-app-log-viewer.json'), 'utf8'));
const acl = JSON.parse(fs.readFileSync(path.join(root, 'root/usr/share/rpcd/acl.d/luci-app-log-viewer.json'), 'utf8'));

const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

test('VERSION is the single source of the release number', () => {
  assert.match(version, /^\d+\.\d+\.\d+$/, 'VERSION must be a plain semantic version');
  assert.match(makefile, /\$\(shell cat \$\(CURDIR\)\/VERSION/, 'the Makefile must read VERSION');
  assert.match(installer, new RegExp(`^VERSION_FALLBACK=v${escape(version)}$`, 'm'));
});

test('release notes and changelog describe the current version', () => {
  assert.match(changelog, new RegExp(`^## v${escape(version)} `, 'm'));
  assert.match(notes, new RegExp(`v${escape(version)}`));
  const older = changelog.split('\n').filter(line => /^## v/.test(line)).slice(1);
  assert.ok(older.length > 0, 'the changelog keeps previous releases');
});

test('the package identity and menu path stay stable across releases', () => {
  assert.match(makefile, /PKG_NAME:=luci-app-log-viewer/);
  assert.match(makefile, /PKG_LICENSE:=MIT/);
  assert.ok(menu['admin/status/log-viewer'], 'menu entry must keep its path');
  assert.deepEqual(menu['admin/status/log-viewer'].action, {type: 'view', path: 'log-viewer/firewall'});
  assert.deepEqual(menu['admin/status/log-viewer'].depends, {acl: ['luci-app-log-viewer']});
  assert.ok(acl['luci-app-log-viewer']);
});

test('the package no longer depends on the iptables compatibility layer', () => {
  assert.doesNotMatch(makefile, /iptables-nft/);
  assert.doesNotMatch(makefile, /iptables-mod-hashlimit/);
  assert.match(makefile, /\+firewall4/);
  assert.match(makefile, /PKG_BUILD_DEPENDS:=libmaxminddb/);
  assert.match(makefile, /log-viewer-geoip/);
  assert.doesNotMatch(makefile, /PKGARCH:=all/);
});

test('the release pipeline ships the version file and the C source', () => {
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/build-release.yml'), 'utf8');
  assert.match(workflow, /cp -a Makefile htdocs root src VERSION/);
});

test('the installer targets this repository and tolerates upgrades', () => {
  assert.match(installer, /^REPO=softstaticx\/luci-app-log$/m);
  assert.match(installer, /apk version -t/);
  assert.match(installer, /--force-reinstall|APK_FORCE_REINSTALL/);
  assert.match(installer, /installed_pkgver/);
});

test('CI runs both test suites and the static checks', () => {
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/validate.yml'), 'utf8');
  assert.match(workflow, /node --test/);
  assert.match(workflow, /shell-tests\.sh/);
  assert.match(workflow, /shellcheck/);
  assert.match(workflow, /dash -n/);
  assert.match(workflow, /libmaxminddb-dev/);
});
