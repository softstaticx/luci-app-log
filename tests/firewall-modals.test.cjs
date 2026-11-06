const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');

function makeE() {
  function E(tag, attrs, ...children) {
    const node = {tag, attrs: attrs || {}, children: [], value: attrs && attrs.value, checked: attrs && attrs.checked,
      addEventListener() {}, removeEventListener() {}, appendChild(child) { this.children.push(child); }};
    const add = child => {
      if (child == null) return;
      if (Array.isArray(child)) child.forEach(add);
      else node.children.push(child);
    };
    children.forEach(add);
    return node;
  }
  return E;
}

function walk(node, out = []) {
  if (Array.isArray(node)) {
    node.forEach(child => walk(child, out));
    return out;
  }
  if (!node || typeof node !== 'object') return out;
  out.push(node);
  (node.children || []).forEach(child => walk(child, out));
  return out;
}

async function load(watchJson) {
  let modal = null;
  const calls = [];
  const ui = {
    showModal(title, content, ...classes) {
      if (!classes.every(c => typeof c === 'string')) throw new Error('showModal classes must be strings');
      modal = {title, content, classes};
    },
    hideModal() {},
    addNotification() {}
  };
  const fsStub = {
    exec_direct: async (command, args) => { calls.push([command, args]); return watchJson; },
    read: async () => '',
    exec: async () => ''
  };
  const rpc = {declare: () => async () => []};
  const view = {extend: obj => obj};
  const document = {createElement: tag => ({tag}), head: {appendChild() {}}, body: {}};
  const window = {URLSearchParams, location: {search: '', pathname: '/', hash: ''}, history: {replaceState() {}}};
  const localStorage = {getItem: () => null, setItem() {}};
  const _ = value => value;
  const factory = new Function('view', 'fs', 'rpc', 'ui', 'E', '_', 'document', 'window', 'localStorage', 'URLSearchParams', 'history',
    source + '\n//# sourceURL=firewall.js');
  return {
    obj: factory(view, fsStub, rpc, ui, makeE(), _, document, window, localStorage,
      URLSearchParams, window.history),
    getModal: () => modal,
    calls
  };
}

const textareas = nodes => nodes.filter(node => node.tag === 'textarea');
const textInputs = nodes => nodes.filter(node => node.tag === 'input' && node.attrs.type === 'text');
const buttonNamed = (nodes, label) => nodes.filter(node => node.tag === 'button').find(node => node.children.includes(label));

test('Firewall event details open with actions in the modal content', async () => {
  const {obj, getModal} = await load('{}');
  obj.showEventDetails({
    id: 1, timestamp: 'Sun Nov 1 06:41:40 2026', kind: 'Blocked', source: '159.223.98.51',
    destination: '5.103.97.94', protocol: 'TCP', sport: '20668', dport: 23, service: 'Telnet',
    iface: 'eth2', ttl: '50', flags: 'SYN', marker: 'INFRA_PORT_BLOCK', prefix: 'INFRA_PORT_BLOCK',
    verdictKnown: true, policyLabel: 'Confirmed drop', policyNote: 'Dropped by zone policy', rawLine: 'raw line'
  });
  const modal = getModal();
  assert.ok(modal, 'Details must call ui.showModal');
  assert.deepEqual(modal.classes, ['fw-modal', 'fw-details-modal']);
  assert.ok(walk(modal.content).some(node => node.attrs && node.attrs.class === 'fw-modal-actions'));
  const labels = walk(modal.content).filter(node => node.tag === 'dt').map(node => node.children[0]);
  assert.ok(labels.includes('Verdict source'), 'details must state whether the verdict was observed');
});

test('WAN watch settings expose mode, zone, IPv6 and the saved ports', async () => {
  const {obj, getModal} = await load(JSON.stringify({
    enabled: true, mode: 'verdict', wan_zone: 'wan', ipv6: 1, wan_interface: 'pppoe-wan',
    ports: '22 80 443', active_interface: 'pppoe-wan', installed: true, verdict: 'confirmed'
  }));
  await obj.openTrafficSettings();
  const modal = getModal();
  assert.equal(modal.title, 'WAN watch settings');
  assert.deepEqual(modal.classes, ['fw-modal', 'fw-wan-modal']);
  const nodes = walk(modal.content);
  const inputs = textInputs(nodes);
  assert.equal(inputs[0].value, 'wan', 'first field is the firewall zone');
  assert.equal(inputs[1].value, 'pppoe-wan', 'second field is the WAN device');
  const ports = textareas(nodes)[0];
  assert.equal(ports.value, '22 80 443');
  assert.equal(ports.attrs.class.includes('fw-port-list'), true);
  assert.ok(!nodes.some(node => node.value !== undefined && String(node.value).includes('undefined')));
  const mode = nodes.find(node => node.tag === 'select');
  assert.equal(mode.value, 'verdict');
});

test('missing WAN status falls back to the wan zone, auto device and an empty port list', async () => {
  const {obj, getModal} = await load('{}');
  await obj.openTrafficSettings();
  const nodes = walk(getModal().content);
  const inputs = textInputs(nodes);
  assert.equal(inputs[0].value, 'wan');
  assert.equal(inputs[1].value, 'auto');
  assert.equal(textareas(nodes)[0].value, '');
});

test('saving sends every setting in one validated command', async () => {
  const {obj, getModal, calls} = await load(JSON.stringify({
    enabled: true, mode: 'probe', wan_zone: 'wan', ipv6: 0, wan_interface: 'eth2',
    ports: '22', active_interface: 'eth2', installed: true
  }));
  await obj.openTrafficSettings();
  const nodes = walk(getModal().content);
  textareas(nodes)[0].value = '22 443';
  await buttonNamed(nodes, 'Save settings').attrs.click();
  const call = calls.find(([command]) => command === '/usr/sbin/infra-port-watch-config');
  assert.ok(call, 'the save must call the validated writer');
  assert.deepEqual(call[1], ['set', '1', 'probe', 'wan', 'eth2', '0', '0', '22 443']);
});

test('WAN watch saves reject invalid ports before calling the router', async () => {
  const {obj, getModal, calls} = await load(JSON.stringify({
    enabled: true, mode: 'verdict', wan_zone: 'wan', wan_interface: 'auto', ports: '22', installed: true
  }));
  await obj.openTrafficSettings();
  const nodes = walk(getModal().content);
  textareas(nodes)[0].value = '22 70000';
  await buttonNamed(nodes, 'Save settings').attrs.click();
  assert.equal(calls.filter(([command]) => command === '/usr/sbin/infra-port-watch-config').length, 0);
  assert.ok(nodes.some(node => node.attrs && node.attrs.class === 'fw-modal-error' && node.hidden === false));
});

test('retention settings include the in-memory ring size', async () => {
  const {obj, getModal, calls} = await load(JSON.stringify({
    count: 12, cap: 500, storage: 'tmpfs', persist_enabled: 0, persist_directory: '/srv/log-viewer',
    persist_days: 7, persist_max_mb: 32, persist_files: 0, persist_kb: 0
  }));
  await obj.openHistorySettings();
  const nodes = walk(getModal().content);
  const numbers = nodes.filter(node => node.tag === 'input' && node.attrs.type === 'number');
  assert.equal(numbers.length, 3, 'days, size and ring inputs');
  numbers[2].value = '800';
  await buttonNamed(nodes, 'Save history settings').attrs.click();
  const call = calls.find(([command, args]) => command === '/usr/sbin/log-viewer-history' && args[0] === 'configure');
  assert.deepEqual(call[1], ['configure', '0', '/srv/log-viewer', '7', '32', '800']);
});
