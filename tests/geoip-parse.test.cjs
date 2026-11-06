const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');

const start = source.indexOf('function parseGeoBatch(');
assert.ok(start >= 0, 'firewall view must define parseGeoBatch');
const next = source.indexOf('\nfunction ', start + 1);
const parseGeoBatch = new Function(`${source.slice(start, next === -1 ? source.length : next)}\nreturn parseGeoBatch;`)();

const line = (ip, cc) => `{"ip":"${ip}","country_code":"${cc}","country_name":"X","asn":"1","asn_organization":"Y"}`;

test('parses one object per line', () => {
  const batch = [line('203.0.113.8', 'DE'), line('198.51.100.9', 'US'), line('192.0.2.10', 'JP')].join('\n') + '\n';
  const rows = parseGeoBatch(batch);
  assert.equal(rows.size, 3);
  assert.equal(rows.get('203.0.113.8').country_code, 'DE');
  assert.equal(rows.get('192.0.2.10').country_code, 'JP');
});

test('a whole batch is never fed to JSON.parse', () => {
  // This is the exact shape that used to throw
  // "Unexpected non-whitespace character after JSON at position ...".
  const batch = [line('1.1.1.1', 'AU'), line('2.2.2.2', 'BR')].join('\n');
  assert.doesNotThrow(() => parseGeoBatch(batch));
  assert.equal(parseGeoBatch(batch).size, 2);
  assert.doesNotMatch(source, /text\.startsWith\('\{'\)/);
  assert.match(source, /const byIp = parseGeoBatch\(raw\);/);
});

test('accepts the 3.x single-object payload keyed by address', () => {
  const legacy = JSON.stringify({
    '203.0.113.8': {country_code: 'DE', country_name: 'Germany', asn: '3320', asn_organization: 'Telekom'},
    '198.51.100.9': {country_code: 'US', country_name: 'United States'}
  });
  const rows = parseGeoBatch(legacy);
  assert.equal(rows.size, 2);
  assert.equal(rows.get('203.0.113.8').country_code, 'DE');
  assert.equal(rows.get('203.0.113.8').ip, '203.0.113.8');
});

test('keeps error records so the page can explain them', () => {
  const rows = parseGeoBatch('{"ip":"1.2.3.4","error":"no database"}\n');
  assert.equal(rows.size, 1);
  assert.equal(rows.get('1.2.3.4').error, 'no database');
});

test('ignores empty, garbage and non-object lines', () => {
  assert.equal(parseGeoBatch('').size, 0);
  assert.equal(parseGeoBatch(null).size, 0);
  assert.equal(parseGeoBatch('not json\n[1,2,3]\n42\n').size, 0);
  assert.equal(parseGeoBatch('{"ip":"1.2.3.4"}\n\n{"ip":"5.6.7.8"}\n').size, 2);
});
