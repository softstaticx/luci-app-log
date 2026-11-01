const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const installer = fs.readFileSync(path.join(__dirname, '../install-online.sh'), 'utf8');
const match = installer.match(/^pkgver_of\(\) \{[\s\S]*?^install_downloaded_packages\(\) \{[\s\S]*?^\}/m);
assert.ok(match, 'installer must decide install, upgrade, replace, or keep');

test('a fresh router installs both packages', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Installing libmaxminddb 1\.0\.0-r1/);
    assert.match(result.out, /Installing luci-app-log-viewer 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/lib\.apk \/tmp\/app\.apk/);
    assert.equal(result.log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('an older install is upgraded in place', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '1.0.0-r1'],
      ['luci-app-log-viewer', '3.2.1-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Upgrading luci-app-log-viewer from 3\.2\.1-r1 to 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/app\.apk/);
    assert.equal(result.log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('the same release is replaced when the installer runs again', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '1.0.0-r1'],
      ['luci-app-log-viewer', '3.3.1-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Replacing installed luci-app-log-viewer 3\.3\.1-r1/);
    assert.match(result.log, /del luci-app-log-viewer/);
    assert.match(result.log, /del libmaxminddb/);
    const delApp = result.log.indexOf('del luci-app-log-viewer');
    const delLib = result.log.indexOf('del libmaxminddb');
    const add = result.log.indexOf('add --allow-untrusted --upgrade');
    assert.ok(delApp < delLib && delLib < add);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('an older helper is upgraded without touching a newer app', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '0.9.0-r1'],
      ['luci-app-log-viewer', '9.0.0-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Upgrading libmaxminddb from 0\.9\.0-r1 to 1\.0\.0-r1/);
    assert.match(result.out, /newer than 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/lib\.apk/);
    assert.equal(result.log.includes('add --allow-untrusted --upgrade /tmp/app.apk'), false);
    assert.equal(result.log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('a newer installed app is left in place', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '1.0.0-r1'],
      ['luci-app-log-viewer', '9.0.0-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /newer than 3\.3\.1-r1/);
    assert.equal(result.log.includes('del '), false);
    assert.equal(result.log.includes('add '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('APK v3 metadata comes from apk adbdump, not tar', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [], '1.13.3-r1', '3.3.1-r1');
    assert.match(result.log, /adbdump \/tmp\/lib\.apk/);
    assert.match(result.log, /adbdump \/tmp\/app\.apk/);
    assert.match(result.out, /Installing libmaxminddb 1\.13\.3-r1/);
    assert.match(result.out, /Installing luci-app-log-viewer 3\.3\.1-r1/);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('APK v2 .PKGINFO is still read when adbdump is unavailable', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [], '1.13.3-r1', '3.3.1-r1', {
      adbdumpFail: true,
      tar: true
    });
    assert.match(result.out, /Installing libmaxminddb 1\.13\.3-r1/);
    assert.match(result.out, /Installing luci-app-log-viewer 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/lib\.apk \/tmp\/app\.apk/);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('an unreadable package fails before apk add or del', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    assert.throws(
      () => runPlan(root, [], '1.13.3-r1', '3.3.1-r1', {adbdumpFail: true, tarFail: true}),
      err => {
        assert.match(String(err.stderr), /couldn't read the package version/);
        return true;
      }
    );
    const log = fs.readFileSync(path.join(root, 'apk.log'), 'utf8');
    assert.equal(log.includes('add '), false);
    assert.equal(log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function runPlan(root, installed, libVer, appVer, opts = {}) {
  const log = path.join(root, 'apk.log');
  const db = path.join(root, 'installed');
  const adbdumpFail = opts.adbdumpFail ? 1 : 0;
  const tarFail = opts.tarFail ? 1 : 0;
  const tarLibVer = opts.tar ? libVer : '0.0.0-bad';
  const tarAppVer = opts.tar ? appVer : '0.0.0-bad';
  fs.writeFileSync(db, installed.map(row => row.join(' ')).join('\n') + (installed.length ? '\n' : ''));
  const fake = `
apk() {
  printf '%s\\n' "$*" >> "${log}"
  cmd="$1"; shift
  case "$cmd" in
    adbdump)
      [ ${adbdumpFail} -eq 0 ] || return 1
      case "$1" in
        *lib.apk*) name=libmaxminddb; ver="${libVer}" ;;
        *) name=luci-app-log-viewer; ver="${appVer}" ;;
      esac
      printf '#%%SCHEMA: 676B6370\\n# ADB block, size: 7668, compat: 0, ver: 0\\ninfo:\\n  name: %s\\n  version: %s\\n  depends:\\n    - name: musl\\n      version: 1.2.5-r0\\npaths:\\n  - name: /usr/share/luci/menu.d\\n' "$name" "$ver"
      ;;
    list)
      name=""
      while [ $# -gt 0 ]; do
        case "$1" in -*) shift ;; *) name="$1"; shift ;; esac
      done
      if [ -n "$name" ] && grep -q "^$name " "${db}"; then
        ver=$(awk -v n="$name" '$1 == n { print $2; exit }' "${db}")
        echo "$name-$ver arch {world} [installed]"
      fi
      ;;
    version)
      a=""; b=""
      while [ $# -gt 0 ]; do
        case "$1" in -t) shift; a="$1"; b="$2"; break ;; *) shift ;; esac
      done
      if [ "$a" = "$b" ]; then echo '='
      else
        awk -v a="$a" -v b="$b" 'BEGIN {
          na=split(a,x,/[-.]/); nb=split(b,y,/[-.]/); n=na>nb?na:nb
          for (i=1;i<=n;i++) {
            if ((x[i]+0) < (y[i]+0)) { print "<"; exit }
            if ((x[i]+0) > (y[i]+0)) { print ">"; exit }
          }
          print "="
        }'
      fi
      ;;
    add|del) ;;
  esac
}

tar() {
  [ ${tarFail} -eq 0 ] || return 1
  case "$2" in
    *lib.apk*) echo 'pkgver = ${tarLibVer}' ;;
    *) echo 'pkgver = ${tarAppVer}' ;;
  esac
}
`;
  const out = execFileSync('sh', ['-c', `set -eu
${fake}
${match[0]}
install_downloaded_packages /tmp/lib.apk /tmp/app.apk`], {
    encoding: 'utf8'
  });
  return {out, log: fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : ''};
}
