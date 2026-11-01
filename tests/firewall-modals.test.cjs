const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');

function makeE() {
  function E(tag, attrs, ...children) {
    const node = {tag, attrs: attrs || {}, children: [], value: attrs && attrs.value, checked: attrs && attrs.checked};
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
  const ui = {
    showModal(title, content, ...classes) {
      if (!classes.every(c => typeof c === 'string')) throw new Error('showModal classes must be strings');
      modal = {title, content, classes};
    },
    hideModal() {},
    addNotification() {}
  };
  const fsStub = {
    exec_direct: async () => watchJson,
    read: async () => '',
    exec: async () => ''
  };
  const rpc = {declare: () => async () => []};
  const view = {extend: obj => obj};
  const document = {createElement: tag => ({tag}), head: {appendChild() {}}, body: {}};
  const window = {};
  const localStorage = {getItem: () => null, setItem() {}};
  const _ = value => value;
  const factory = new Function('view', 'fs', 'rpc', 'ui', 'E', '_', 'document', 'window', 'localStorage',
    source + '\n//# sourceURL=firewall.js');
  return {obj: factory(view, fsStub, rpc, ui, makeE(), _, document, window, localStorage), getModal: () => modal};
}

test('Firewall event details open with actions in the modal content', async () => {
  const {obj, getModal} = await load('{}');
  obj.showEventDetails({
    id: 1, timestamp: 'Sun Nov 1 06:41:40 2026', kind: 'Blocked', source: '159.223.98.51',
    destination: '5.103.97.94', protocol: 'TCP', sport: '20668', dport: 23, service: 'Telnet',
    iface: 'eth2', ttl: '50', flags: 'SYN', marker: 'INFRA_PORT_HIT', prefix: 'INFRA_PORT_HIT',
    policyLabel: 'Default deny', policyNote: 'No allow', rawLine: 'raw line'
  });
  const modal = getModal();
  assert.ok(modal, 'Details must call ui.showModal');
  assert.deepEqual(modal.classes, ['fw-modal', 'fw-details-modal']);
  assert.ok(walk(modal.content).some(node => node.attrs && node.attrs.class === 'fw-modal-actions'));
});

test('WAN watch settings never render undefined values', async () => {
  const {obj, getModal} = await load(JSON.stringify({
    enabled: true, wan_interface: 'eth2', ports: '22 80 443', active_interface: 'eth2', installed: true
  }));
  await obj.openTrafficSettings();
  const modal = getModal();
  assert.equal(modal.title, 'WAN watch settings');
  assert.deepEqual(modal.classes, ['fw-modal', 'fw-wan-modal']);
  const nodes = walk(modal.content);
  const input = nodes.find(node => node.tag === 'input' && node.attrs.type === 'text');
  const areas = nodes.filter(node => node.tag === 'textarea');
  assert.equal(input.value, 'eth2');
  assert.equal(areas[0].value, '22 80 443');
  assert.ok(!areas.some(area => String(area.value).includes('undefined')));
});

test('missing WAN status falls back to auto and an empty port list', async () => {
  const {obj, getModal} = await load('{}');
  await obj.openTrafficSettings();
  const nodes = walk(getModal().content);
  const input = nodes.find(node => node.tag === 'input' && node.attrs.type === 'text');
  const area = nodes.find(node => node.tag === 'textarea');
  assert.equal(input.value, 'auto');
  assert.equal(area.value, '');
});

test('WAN watch saves reject invalid ports before calling the router', async () => {
  const {obj, getModal} = await load(JSON.stringify({
    enabled: true, wan_interface: 'auto', ports: '22', active_interface: 'eth2', installed: true
  }));
  await obj.openTrafficSettings();
  const nodes = walk(getModal().content);
  const area = nodes.find(node => node.tag === 'textarea');
  const buttons = nodes.filter(node => node.tag === 'button');
  const save = buttons.find(node => node.children.includes('Save settings'));
  area.value = '22 70000';
  await save.attrs.click();
  assert.ok(nodes.some(node => node.attrs && node.attrs.class === 'fw-modal-error' && node.hidden === false));
});
