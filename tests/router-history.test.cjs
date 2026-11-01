const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const helper = path.join(__dirname, '../root/usr/sbin/log-viewer-history');
const initScript = path.join(__dirname, '../root/etc/init.d/log-viewer-history');

test('router history keeps firewall lines in a tmpfs ring and drops other syslog', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-history-'));
  const bin = path.join(root, 'bin');
  const ring = path.join(root, 'events.ring');
  fs.mkdirSync(bin);
  const log = [
    'Oct 31 06:00:00 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN',
    'Oct 31 06:00:01 2026 router dnsmasq[1]: query[A] example.test from 192.168.1.2',
    'Oct 31 06:00:04 2026 router kernel: INFRA_PORT_OTHER: IN=wan SRC=203.0.113.11 DST=192.0.2.1 PROTO=TCP DPT=25125 SYN',
    'Oct 31 06:00:02 2026 router kernel: DROP: IN=wan SRC=198.51.100.9 DST=192.0.2.1 PROTO=TCP DPT=443 SYN',
    'Oct 31 06:00:03 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN'
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'logread'), `#!/bin/sh\ncat <<'EOF'\n${log}EOF\n`, {mode: 0o755});

  const env = {
    ...process.env,
    PATH: `${bin}:/usr/bin:/bin`,
    LOG_VIEWER_RING: ring,
    LOG_VIEWER_RING_CAP: '4'
  };
  try {
    const status = JSON.parse(execFileSync(helper, ['update'], {env, encoding: 'utf8'}));
    assert.equal(status.storage, 'tmpfs');
    assert.equal(status.cap, 4);
    assert.equal(status.count, 4);
    const lines = fs.readFileSync(ring, 'utf8').trim().split('\n');
    assert.equal(lines.some(line => line.includes('dnsmasq')), false);
    assert.equal(lines.filter(line => line.includes('INFRA_PORT_HIT')).length, 2);
    assert.equal(lines.some(line => line.includes('INFRA_PORT_OTHER:')), true);
    assert.equal(lines.some(line => line.includes('DROP:')), true);

    const cleared = JSON.parse(execFileSync(helper, ['clear'], {env, encoding: 'utf8'}));
    assert.equal(cleared.count, 0);
    assert.equal(fs.existsSync(ring), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('history collector is started with the package and survives without the page open', () => {
  const init = fs.readFileSync(initScript, 'utf8');
  const makefile = fs.readFileSync(path.join(__dirname, '../Makefile'), 'utf8');
  assert.match(init, /log-viewer-history follow/);
  assert.match(makefile, /log-viewer-history enable/);
  assert.match(makefile, /log-viewer-history start/);
});

test('optional persistent history writes daily files without rescanning on every tick', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-history-persist-'));
  const bin = path.join(root, 'bin');
  const ring = path.join(root, 'events.ring');
  const status = path.join(root, 'events.status');
  const buffer = path.join(root, 'persist.buffer');
  const persist = path.join(root, 'persist');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'logread'), `#!/bin/sh
printf '%s\\n' 'Oct 31 06:00:00 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN'
printf '%s\\n' 'Oct 31 06:00:01 2026 router kernel: INFRA_PORT_OTHER: IN=wan SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP DPT=25125 SYN'
`, {mode: 0o755});
  const env = {
    ...process.env,
    PATH: `${bin}:/usr/bin:/bin`,
    LOG_VIEWER_RING: ring,
    LOG_VIEWER_STATUS: status,
    LOG_VIEWER_BUFFER: buffer,
    LOG_VIEWER_PERSIST: '1',
    LOG_VIEWER_PERSIST_TEST: '1',
    LOG_VIEWER_PERSIST_DIR: persist,
    LOG_VIEWER_PERSIST_DAYS: '7',
    LOG_VIEWER_PERSIST_MAX_MB: '1'
  };
  try {
    const result = JSON.parse(execFileSync(helper, ['update'], {env, encoding: 'utf8'}));
    assert.equal(result.storage, 'tmpfs+disk');
    assert.equal(result.persist_enabled, 1);
    const files = fs.readdirSync(persist).filter(name => /^firewall-\d{4}-\d{2}-\d{2}\.log$/.test(name));
    assert.equal(files.length, 1);
    const content = fs.readFileSync(path.join(persist, files[0]), 'utf8');
    assert.equal(content.includes('INFRA_PORT_HIT'), true);
    assert.equal(content.includes('INFRA_PORT_OTHER'), true);

    const source = fs.readFileSync(helper, 'utf8');
    assert.match(source, /follow_log/);
    assert.match(source, /logread -f/);
    assert.doesNotMatch(source, /follow\(\) \{[\s\S]*?update >\/dev\/null \|\| true\n    sleep 15/);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('server-side history query filters, sorts, and paginates', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-query-'));
  const ring = path.join(root, 'events.ring');
  const persist = path.join(root, 'persist');
  const tmp = path.join(root, 'tmp');
  fs.mkdirSync(persist);
  fs.mkdirSync(tmp);
  const lines = [
    'Oct 31 06:00:00 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN',
    'Oct 31 06:00:01 2026 router kernel: DROP: IN=wan SRC=198.51.100.9 DST=192.0.2.1 PROTO=UDP DPT=443',
    'Oct 31 06:00:02 2026 router kernel: INFRA_PORT_OTHER: IN=wan SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP DPT=25125 SYN'
  ];
  fs.writeFileSync(path.join(persist, 'firewall-2026-10-31.log'), lines.slice(0, 2).join('\n') + '\n');
  fs.writeFileSync(ring, lines[2] + '\n');
  const env = {
    ...process.env,
    LOG_VIEWER_RING: ring,
    LOG_VIEWER_BUFFER: path.join(root, 'buffer'),
    LOG_VIEWER_PERSIST: '1',
    LOG_VIEWER_PERSIST_TEST: '1',
    LOG_VIEWER_PERSIST_DIR: persist,
    LOG_VIEWER_TMP: tmp
  };
  const query = path.join(__dirname, '../root/usr/sbin/log-viewer-query');
  try {
    const all = JSON.parse(execFileSync(query, ['--limit', '10', '--sort', 'time', '--order', 'desc'], {env, encoding: 'utf8'}));
    assert.equal(all.total, 3);
    assert.equal(all.lines[0].includes('INFRA_PORT_OTHER'), true);
    assert.equal(all.lines[2].includes('INFRA_PORT_HIT'), true);

    const other = JSON.parse(execFileSync(query, ['--verdict', 'other'], {env, encoding: 'utf8'}));
    assert.equal(other.total, 1);
    assert.equal(other.lines[0].includes('INFRA_PORT_OTHER'), true);

    const page = JSON.parse(execFileSync(query, ['--limit', '1', '--offset', '1', '--sort', 'time', '--order', 'desc'], {env, encoding: 'utf8'}));
    assert.equal(page.total, 3);
    assert.equal(page.lines.length, 1);
    assert.equal(page.lines[0].includes('DPT=443'), true);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});
