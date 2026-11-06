'use strict';
'require view';
'require fs';
'require rpc';
'require ui';

const MAX_LINES = 1500;
const PAGE_SIZE = 100;
const WATCH_CONFIG_TTL_MS = 60000;
const GEO_MEMORY_MAX = 400;
const GEO_MEMORY_MS = 7 * 86400000;
const GEO_BATCH_BYTES = 900;

function geoBatchChunks(addresses, maxArgsBytes) {
  const chunks = [];
  let batch = [];
  let bytes = '--batch'.length;
  (addresses || []).forEach(ip => {
    const add = 1 + String(ip).length;
    if (batch.length && bytes + add > maxArgsBytes) {
      chunks.push(batch);
      batch = [];
      bytes = '--batch'.length;
    }
    batch.push(String(ip));
    bytes += add;
  });
  if (batch.length) chunks.push(batch);
  return chunks;
}

function readGeoMemory(raw, now, maxAgeMs) {
  let data;
  try { data = JSON.parse(raw || ''); }
  catch (e) { return {}; }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return {};
  const fresh = {};
  Object.keys(data).forEach(ip => {
    const row = data[ip];
    if (!row || typeof row !== 'object' || Array.isArray(row)) return;
    const at = Number(row.at || 0);
    if (!(at > 0) || now - at > maxAgeMs) return;
    fresh[ip] = {
      country_code: String(row.country_code || ''),
      country_name: String(row.country_name || ''),
      asn_organization: String(row.asn_organization || ''),
      at: at
    };
  });
  return fresh;
}

function writeGeoMemory(store, ip, record, now, maxEntries) {
  const next = Object.assign({}, store);
  next[ip] = {
    country_code: record && record.country_code || '',
    country_name: record && record.country_name || '',
    asn_organization: record && record.asn_organization || '',
    at: now
  };
  const keys = Object.keys(next).sort((a, b) => (next[a].at || 0) - (next[b].at || 0));
  while (keys.length > maxEntries) delete next[keys.shift()];
  return next;
}

function watchConfigIsFresh(syncedAt, now, ttlMs) {
  const at = Number(syncedAt) || 0;
  return at > 0 && Number(now) - at < Number(ttlMs);
}

function parseWatchConfig(raw) {
  try {
    const config = JSON.parse(raw || '{}');
    if (!config || typeof config !== 'object' || Array.isArray(config)) return null;
    return Object.keys(config).length ? config : null;
  }
  catch (e) {
    return null;
  }
}

function watchEnabled(config) {
  return !config || !(config.enabled === false || config.enabled === 0 || config.enabled === '0');
}

function watchInstalled(config) {
  return !!config && (config.installed === true || config.installed === 1 || config.installed === '1');
}

function insightFilterText(source, port, timeline) {
  const parts = [];
  if (source) parts.push(String(source));
  if (port != null && port !== '') parts.push('port ' + port);
  if (timeline && timeline.start != null) parts.push('time bar');
  return parts.join(' · ');
}

// Search supports `key:value` tokens next to free text. An unknown or invalid
// token stays free text, so typing a colon is never an error.
function parseQuery(text) {
  const windows = {'5m': 300000, '15m': 900000, '1h': 3600000, '6h': 21600000, '24h': 86400000};
  const kinds = ['blocked', 'probe', 'other', 'allowed', 'exposed', 'observed'];
  const query = {words: [], port: null, country: '', asn: '', proto: '', verdict: '', source: '', afterMs: 0};
  String(text || '').trim().toLowerCase().split(/\s+/).filter(Boolean).forEach(token => {
    const match = token.match(/^(port|country|asn|proto|verdict|src|source|after):(.+)$/);
    if (!match) { query.words.push(token); return; }
    const key = match[1];
    const value = match[2];
    if (key === 'port') {
      const port = Number(value);
      if (Number.isInteger(port) && port >= 1 && port <= 65535) { query.port = port; return; }
    }
    else if (key === 'country' && /^[a-z]{2}$/.test(value)) { query.country = value.toUpperCase(); return; }
    else if (key === 'asn' && value.length <= 60) { query.asn = value; return; }
    else if (key === 'proto' && ['tcp', 'udp', 'icmp'].includes(value)) { query.proto = value; return; }
    else if (key === 'verdict' && kinds.includes(value)) { query.verdict = value; return; }
    else if ((key === 'src' || key === 'source') && /^[0-9a-f:.]+$/.test(value)) { query.source = value; return; }
    else if (key === 'after' && windows[value]) { query.afterMs = windows[value]; return; }
    query.words.push(token);
  });
  return query;
}

function queryIsEmpty(query) {
  return query.port == null && !query.country && !query.asn && !query.proto &&
    !query.verdict && !query.source && !query.afterMs && !query.words.length;
}

function appendWatchPort(portsText, port) {
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535)
    return {ok: false, reason: 'invalid'};
  const existing = [];
  for (const token of String(portsText || '').split(/[\s,]+/)) {
    if (!token) continue;
    if (!/^\d{1,5}$/.test(token)) return {ok: false, reason: 'invalid'};
    const value = Number(token);
    if (value < 1 || value > 65535) return {ok: false, reason: 'invalid'};
    if (!existing.includes(value)) existing.push(value);
  }
  if (existing.includes(portNumber))
    return {ok: true, changed: false, ports: existing.join(',')};
  if (existing.length >= 256)
    return {ok: false, reason: 'full'};
  existing.push(portNumber);
  return {ok: true, changed: true, ports: existing.join(',')};
}

const DEFAULT_WATCH_PORTS = [21, 22, 23, 25, 53, 69, 80, 81, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 427, 443, 445, 465, 500, 502, 514, 515, 520, 548, 554, 587, 631, 636, 873, 902, 989, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 1883, 1900, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3306, 3389, 3690, 4444, 4500, 5000, 5001, 5060, 5061, 5432, 5555, 5601, 5672, 5900, 5985, 5986, 6379, 6443, 6667, 7001, 7070, 7443, 7547, 7777, 8000, 8008, 8080, 8081, 8088, 8291, 8443, 8883, 8888, 9000, 9042, 9090, 9200, 9300, 9418, 10000, 10250, 11211, 27017, 51820];

function mergeMissingDefaultPorts(portsText, defaults) {
  const existing = [];
  for (const token of String(portsText || '').split(/[\s,]+/)) {
    if (!token) continue;
    if (!/^\d{1,5}$/.test(token)) return {ok: false, reason: 'invalid'};
    const value = Number(token);
    if (value < 1 || value > 65535) return {ok: false, reason: 'invalid'};
    if (!existing.includes(value)) existing.push(value);
  }
  const added = [];
  for (const port of defaults) {
    const value = Number(port);
    if (!existing.includes(value)) added.push(value);
  }
  if (existing.length + added.length > 256)
    return {ok: false, reason: 'full', added: [], ports: existing.join(',')};
  return {ok: true, added, ports: existing.concat(added).join(',')};
}
const SERVICES = {
  21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',69:'TFTP',80:'HTTP',
  110:'POP3',123:'NTP',135:'MS RPC',139:'NetBIOS',143:'IMAP',161:'SNMP',
  389:'LDAP',443:'HTTPS',445:'SMB',500:'IKE',514:'Syslog',548:'AFP',554:'RTSP',
  587:'SMTP Submit',631:'IPP',873:'rsync',993:'IMAPS',995:'POP3S',1080:'SOCKS',
  1194:'OpenVPN',1433:'MS SQL',1521:'Oracle',1723:'PPTP',1883:'MQTT',1900:'SSDP',
  2049:'NFS',2222:'Alt SSH',2375:'Docker API',2376:'Docker TLS',3000:'Web UI',
  3306:'MySQL',3389:'RDP',4500:'IPsec NAT-T',5000:'Web/App',5001:'HTTPS/App',
  5060:'SIP',5061:'SIP TLS',5432:'PostgreSQL',5555:'ADB',5900:'VNC',
  5985:'WinRM',5986:'WinRM TLS',6379:'Redis',6443:'Kubernetes API',
  6667:'IRC',7001:'WebLogic',7443:'HTTPS Alt',7547:'TR-069',7777:'Game/Service',
  8000:'HTTP Alt',8008:'HTTP Alt',8080:'HTTP Proxy',8081:'HTTP Alt',
  8088:'HTTP Alt',8291:'MikroTik',8443:'HTTPS Alt',8883:'MQTT TLS',8888:'HTTP Alt',9000:'Web/App',
  9042:'Cassandra',9090:'Web/App',9200:'Elasticsearch',9300:'Elasticsearch',
  9418:'Git',10000:'Webmin',10250:'Kubelet',11211:'Memcached',27017:'MongoDB',51820:'WireGuard'
};

function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

function csvCell(value) {
  let text = String(value == null ? '' : value);
  if (/^[\t\r\n ]*[=+\-@]/.test(text)) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024) return Math.round(bytes / 1024) + ' KB';
  return bytes + ' B';
}

function isPublic(ip) {
  if (!ip || ip === '-' || ip === '0.0.0.0') return false;
  if (ip.indexOf(':') >= 0) return false;
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return !(p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127));
}

function parseFields(line) {
  const result = {};
  const re = /([A-Z][A-Z0-9_]*)=("[^"]*"|\S+)/g;
  let match;
  while ((match = re.exec(line)) !== null)
    result[match[1]] = match[2].replace(/^"|"$/g, '');
  return result;
}

function parseRouterTimestamp(timestamp, routerOffset) {
  const fields = String(timestamp || '').match(/^[A-Z][a-z]{2}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/);
  const offset = String(routerOffset || '').match(/^([+-])(\d{2})(\d{2})$/);
  if (!fields || !offset) return null;
  const months = {Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5, Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11};
  const month = months[fields[1]];
  if (month == null) return null;
  const wallTime = Date.UTC(Number(fields[6]), month, Number(fields[2]), Number(fields[3]), Number(fields[4]), Number(fields[5]));
  const minutesEast = (Number(offset[2]) * 60 + Number(offset[3])) * (offset[1] === '-' ? -1 : 1);
  return wallTime - minutesEast * 60000;
}

function formatLogreadTimestamp(epochMs, routerOffset) {
  const ms = Number(epochMs);
  const offset = String(routerOffset || '').match(/^([+-])(\d{2})(\d{2})$/);
  if (!Number.isFinite(ms) || ms <= 0 || !offset) return '';
  const minutesEast = (Number(offset[2]) * 60 + Number(offset[3])) * (offset[1] === '-' ? -1 : 1);
  const wall = new Date(ms + minutesEast * 60000);
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = n => String(n).padStart(2, '0');
  return days[wall.getUTCDay()] + ' ' + months[wall.getUTCMonth()] + ' ' + wall.getUTCDate() + ' ' +
    pad(wall.getUTCHours()) + ':' + pad(wall.getUTCMinutes()) + ':' + pad(wall.getUTCSeconds()) + ' ' +
    wall.getUTCFullYear();
}

function parseLine(line, index, routerOffset) {
  const otherHit = line.includes('INFRA_PORT_OTHER:');
  const confirmedHit = line.includes('INFRA_PORT_BLOCK:');
  const infraHit = line.includes('INFRA_PORT_HIT:');
  const hasPacketTuple = /SRC=\S+.*DPT=\d+/.test(line);
  const blockMarker = /\b(?:DROP|REJECT)\b/i.test(line) ||
    /(?:^|[\s:])[A-Z0-9_-]*(?:BLOCKED|BLOCK|DROP|REJECT):/i.test(line);
  const allowMarker =
    /(?:^|[\s:])[A-Z0-9_-]*(?:ALLOWED|ALLOW|ACCEPTED|ACCEPT|PASSED|PASS):/i.test(line);
  const markerMatch = line.match(/(?:^|\s)([A-Z][A-Z0-9_-]{1,39}):/);
  const marker = markerMatch ? markerMatch[1] : '';

  let prefix = '';
  let kind = '';
  let verdictKnown = false;
  if (otherHit) {
    prefix = 'INFRA_PORT_OTHER';
    kind = 'Other';
  }
  else if (confirmedHit) {
    // Emitted from a fw4 chain-post rule: the packet survived every user rule
    // and is about to be dropped by the zone policy.
    prefix = 'INFRA_PORT_BLOCK';
    kind = 'Blocked';
    verdictKnown = true;
  }
  else if (infraHit) {
    prefix = 'INFRA_PORT_HIT';
    kind = 'Probe';
  }
  else if (hasPacketTuple && blockMarker) {
    prefix = 'FIREWALL_BLOCK';
    kind = 'Blocked';
    verdictKnown = true;
  }
  else if (hasPacketTuple && allowMarker) {
    prefix = 'FIREWALL_ALLOW';
    kind = 'Allowed';
    verdictKnown = true;
  }
  else return null;

  const fields = parseFields(line);
  const port = Number(fields.DPT || 0);
  const timestamp = (line.match(/^([A-Z][a-z]{2}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})/) || ['', ''])[1];
  const routerTimestampMs = timestamp ? parseRouterTimestamp(timestamp, routerOffset) : null;
  const timestampMs = routerTimestampMs == null && timestamp ? Date.parse(timestamp) : routerTimestampMs;

  return {
    id: index,
    rawLine: line,
    timestamp: timestamp || 'Recent',
    timestampMs: Number.isFinite(timestampMs) ? timestampMs : null,
    kind: kind,
    source: fields.SRC || '',
    destination: fields.DST || '',
    dport: port,
    service: SERVICES[port] || 'Unknown service',
    protocol: (fields.PROTO || '?').toUpperCase(),
    sport: fields.SPT || '',
    iface: fields.IN || '',
    ttl: fields.TTL || '',
    flags: line.includes('SYN') ? 'SYN' : line.includes('RST') ? 'RST' :
      (fields.PROTO === 'UDP' ? 'UDP packet' : ''),
    prefix: prefix,
    marker: marker || prefix,
    verdictKnown: verdictKnown,
    policyLabel: '',
    policyNote: ''
  };
}

const BUNDLED_FLAGS = new Set('ae au be br ca ch cn cz de es fi fr gb hk id il in ir it jp kr mx my nl no ph pl pt ro ru sa se sg th tr tw ua us vn za'.split(' '));

function countryFlag(code) {
  if (!/^[A-Z]{2}$/.test(code || ''))
    return '<span class="fw-flag-fallback" title="Country unavailable">🌐</span>';
  if (!BUNDLED_FLAGS.has(code.toLowerCase()))
    return '<span class="fw-flag-fallback" title="Flag not bundled for ' + esc(code) + '">🌐</span>';

  // Flags are bundled locally. This avoids LuCI CSP restrictions on external image hosts.
  return '<img class="fw-flag-img" src="/luci-static/resources/log-viewer/flags/' +
    code.toLowerCase() + '.svg" alt="' + esc(code) +
    '" width="20" loading="lazy" decoding="async">';
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const link = E('a', {href: url, download: filename});
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText)
    return navigator.clipboard.writeText(String(text));
  return new Promise(function(resolve, reject) {
    const area = document.createElement('textarea');
    area.value = String(text);
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy') ? resolve() : reject(new Error('copy failed'));
    }
    catch (e) { reject(e); }
    finally { area.remove(); }
  });
}

const callLogRead = rpc.declare({
  object: 'log',
  method: 'read',
  params: ['lines', 'stream', 'oneshot'],
  expect: { log: [] }
});

let historyDatabasePromise = null;
function openHistoryDatabase() {
  if (!window.indexedDB) return Promise.reject(new Error('IndexedDB is unavailable in this browser'));
  if (historyDatabasePromise) return historyDatabasePromise;
  historyDatabasePromise = new Promise((resolve, reject) => {
    const request = indexedDB.open('reffix-firewall-log', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('events')) {
        const store = db.createObjectStore('events', {keyPath: 'key'});
        store.createIndex('timestampMs', 'timestampMs', {unique: false});
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Unable to open local event history'));
    request.onblocked = () => reject(new Error('Close other Firewall Log tabs to upgrade local history'));
  }).catch(error => {
    historyDatabasePromise = null;
    throw error;
  });
  return historyDatabasePromise;
}

function historyRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Local history request failed'));
  });
}

function historyTransactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error || new Error('Local history write failed'));
    transaction.onabort = () => reject(transaction.error || new Error('Local history write was cancelled'));
  });
}

return view.extend({
  handleSave: null,
  handleSaveApply: null,
  handleReset: null,
  viewName: 'firewall',
  title: _('Firewall Log'),
  events: [],
  eventById: null,
  geoCache: {},
  geoCacheAt: {},
  geoLookupInFlight: new Map(),
  kindFilter: 'known',
  protoFilter: 'all',
  timeFilter: 'all',
  sourceFilter: '',
  portFilter: null,
  countryFilter: '',
  asnFilter: '',
  sortBy: 'time-desc',
  paused: false,
  policyRules: [],
  policyRulesLoaded: false,
  trafficContextLoaded: false,
  watchConfig: null,
  watchConfigLoaded: false,
  routerClockAtSync: 0,
  routerClockSyncedAt: 0,
  wanInterfaces: [],
  exposedPorts: {},
  showAllPorts: false,
  maxEntries: 100,
  historyRetention: 'off',
  historyCache: null,
  historySeedPending: false,
  timelineRange: null,
  liveEvents: [],
  sourceLineCount: 0,
  logReadLimit: MAX_LINES,
  watchConfigRequest: 0,
  watchConfigSyncedAt: 0,
  geoMemory: {},
  routerHistorySyncedAt: 0,
  routerHistoryStatus: null,
  lastRingData: null,
  lastCollectedAt: 0,
  lastRawData: null,
  geoStatus: null,
  geoStatusCheckedAt: 0,
  showReputation: false,
  filterPresets: [],
  refreshGeneration: 0,

  getLogData: async function() {
    // ubus log.read is the OpenWrt 25.12 path. file.exec of logread is capped
    // at 256 KiB, which silently drops the newest lines of a 1,500-line tail.
    // OpenWrt also installs the binary as /usr/libexec/logread-ubox and only
    // optionally links /sbin/logread, so that path stays as a fallback.
    const offset = (this.watchConfig && this.watchConfig.router_offset) || '+0000';
    const formatEntries = (entries, limit) => {
      this.logReadLimit = limit;
      return entries.map(entry => {
        const msg = String(entry && entry.msg != null ? entry.msg : '').replace(/[\r\n]+/g, ' ').trim();
        if (!msg) return '';
        const stamp = formatLogreadTimestamp(entry && entry.time, offset);
        return stamp ? (stamp + ' ' + msg) : msg;
      }).filter(Boolean).join('\n');
    };
    const readEntries = async (limit) => {
      const entries = await callLogRead(limit, false, true);
      return Array.isArray(entries) ? entries : null;
    };

    try {
      const entries = await readEntries(MAX_LINES);
      if (entries) return formatEntries(entries, MAX_LINES);
    }
    catch (e) {
      try {
        const entries = await readEntries(400);
        if (entries) return formatEntries(entries, 400);
      }
      catch (e2) {}
    }

    this.logReadLimit = MAX_LINES;
    const commands = ['/sbin/logread', '/usr/sbin/logread', '/usr/libexec/logread-ubox'];
    let lastError = new Error('logread not found');
    for (let i = 0; i < commands.length; i++) {
      try {
        return await fs.exec_direct(commands[i], ['-l', String(MAX_LINES)], 'text');
      }
      catch (e) {
        lastError = e;
      }
    }
    throw lastError;
  },

  loadPolicyRules: async function() {
    if (this.policyRulesLoaded) return;
    this.policyRulesLoaded = true;
    try {
      const raw = await fs.read('/etc/log-viewer/policies.json');
      const config = JSON.parse(raw || '{}');
      this.policyRules = Array.isArray(config.policies) ? config.policies : [];
    }
    catch (e) {
      this.policyRules = [];
    }
  },

  loadWatchConfig: async function(force) {
    if (!force && this.watchConfigLoaded && watchConfigIsFresh(this.watchConfigSyncedAt, Date.now(), WATCH_CONFIG_TTL_MS))
      return;
    const request = ++this.watchConfigRequest;
    this.watchConfigLoaded = true;
    try {
      const raw = await fs.exec_direct('/usr/sbin/infra-port-watch', ['get'], 'text');
      if (request !== this.watchConfigRequest) return;
      const config = parseWatchConfig(raw);
      this.watchConfig = config;
      if (config) {
        this.routerClockAtSync = Number(config.router_time || 0) * 1000;
        this.routerClockSyncedAt = Date.now();
      }
      this.watchConfigSyncedAt = Date.now();
    }
    catch (e) {
      if (request !== this.watchConfigRequest) return;
      this.watchConfig = null;
      this.watchConfigSyncedAt = Date.now();
    }
  },

  loadTrafficContext: function() {
    if (!this.trafficContextLoaded) {
      this.trafficContextLoaded = true;
      // Use explicitly configured allow labels as useful defaults; the user can
      // edit these independently in this browser's traffic-context settings.
      this.exposedPorts = {};
      this.policyRules.forEach(rule => {
        if (!rule || !/_ALLOW$|_EXPOSED?$|_FORWARD$/i.test(String(rule.marker || '')) ||
            !Number.isInteger(Number(rule.port)) || Number(rule.port) < 1 || Number(rule.port) > 65535)
          return;
        this.exposedPorts[Number(rule.port)] = String(rule.label || ('Port ' + rule.port));
      });

      try {
        const saved = JSON.parse(localStorage.getItem('reffix-log-viewer.traffic-context') || 'null');
        if (saved && typeof saved === 'object' && saved.exposedPorts && typeof saved.exposedPorts === 'object')
          this.exposedPorts = Object.fromEntries(Object.entries(saved.exposedPorts)
            .filter(([port, label]) => /^\d{1,5}$/.test(port) && Number(port) > 0 && Number(port) <= 65535 && typeof label === 'string')
            .map(([port, label]) => [Number(port), label.trim() || ('Port ' + port)]));
      }
      catch (e) {}
    }
    const activeInterface = this.watchConfig && (this.watchConfig.active_interface ||
      (this.watchConfig.wan_interface !== 'auto' ? this.watchConfig.wan_interface : ''));
    if (activeInterface) this.wanInterfaces = [String(activeInterface).trim().toLowerCase()];
  },

  applyTrafficContext: function(event) {
    const other = event.prefix === 'INFRA_PORT_OTHER';
    const probe = event.prefix === 'INFRA_PORT_HIT';
    if (!other && !probe) return event;

    event.kind = other ? 'Other' : 'Probe';
    event.policyLabel = other ? _('Not on the watch list') : _('Probe');
    event.policyNote = other
      ? _('Low-rate sample of a port outside the watch list. The verdict was not observed.')
      : _('Probe seen before the firewall decides; probe mode does not observe the verdict.');

    const iface = String(event.iface || '').toLowerCase();
    const onWan = !this.wanInterfaces.length || this.wanInterfaces.includes(iface);
    if (!onWan) {
      event.kind = 'Observed';
      event.policyNote = _('Probe on an interface not configured as WAN. Set the WAN device in WAN watch settings.');
      return event;
    }
    if (this.exposedPorts[event.dport]) {
      event.kind = 'Exposed';
      event.policyLabel = this.exposedPorts[event.dport];
      event.policyNote = _('Port carries a local service label. Only probe mode can classify it this way.');
    }
    return event;
  },

  loadPreferences: function() {
    try {
      this.showReputation = localStorage.getItem('reffix-log-viewer.external-reputation') === 'true';
      const presets = JSON.parse(localStorage.getItem('reffix-log-viewer.filters') || '[]');
      this.filterPresets = Array.isArray(presets) ? presets.filter(p =>
        p && typeof p.name === 'string' && typeof p.query === 'string' &&
        ['known', 'all', 'blocked', 'probe', 'other', 'observed', 'allowed', 'exposed'].includes(p.kind) &&
        ['all', 'tcp', 'udp', 'icmp'].includes(p.proto) &&
        ['all', '5m', '15m', '1h', '6h', '24h'].includes(p.window)
      ).slice(0, 20) : [];
      this.historyRetention = ['off', '1', '7', '30'].includes(localStorage.getItem('reffix-log-viewer.history-days'))
        ? localStorage.getItem('reffix-log-viewer.history-days') : 'off';
      this.geoMemory = readGeoMemory(localStorage.getItem('reffix-log-viewer.geo-cache'), Date.now(), GEO_MEMORY_MS);
    }
    catch (e) {
      this.showReputation = false;
      this.filterPresets = [];
      this.historyRetention = 'off';
      this.geoMemory = {};
    }
  },

  // Filters live in the query string so a view can be bookmarked or pasted into
  // a forum post. Unknown values are ignored rather than trusted.
  loadUrlState: function() {
    let params;
    try { params = new URLSearchParams(location.search); }
    catch (e) { return; }
    const pick = (key, allowed, fallback) => {
      const value = params.get(key);
      return value && allowed.includes(value) ? value : fallback;
    };
    this.kindFilter = pick('kind', ['known', 'all', 'blocked', 'probe', 'other', 'allowed', 'exposed', 'observed'], this.kindFilter);
    this.protoFilter = pick('proto', ['all', 'tcp', 'udp', 'icmp'], this.protoFilter);
    this.timeFilter = pick('window', ['all', '5m', '15m', '1h', '6h', '24h'], this.timeFilter);
    this.sortBy = pick('sort', ['time-desc', 'time-asc', 'source-asc', 'country-asc', 'port-asc'], this.sortBy);
    this.initialQuery = params.get('q') || '';
    const port = Number(params.get('port'));
    if (Number.isInteger(port) && port >= 1 && port <= 65535) this.portFilter = port;
    const country = String(params.get('country') || '').toUpperCase();
    if (/^[A-Z]{2}$/.test(country)) this.countryFilter = country;
    const asn = params.get('asn');
    if (asn && asn.length <= 60) this.asnFilter = asn;
    const src = params.get('src');
    if (src && /^[0-9a-f:.]+$/i.test(src)) this.sourceFilter = src;
  },

  saveUrlState: function() {
    if (!this.search) return;
    try {
      const params = new URLSearchParams(location.search);
      const set = (key, value) => { if (value) params.set(key, value); else params.delete(key); };
      set('kind', this.kindFilter !== 'known' ? this.kindFilter : '');
      set('proto', this.protoFilter !== 'all' ? this.protoFilter : '');
      set('window', this.timeFilter !== 'all' ? this.timeFilter : '');
      set('sort', this.sortBy !== 'time-desc' ? this.sortBy : '');
      set('q', this.search.value.trim());
      set('port', this.portFilter != null ? String(this.portFilter) : '');
      set('country', this.countryFilter);
      set('asn', this.asnFilter);
      set('src', this.sourceFilter);
      const qs = params.toString();
      history.replaceState(null, '', location.pathname + (qs ? '?' + qs : '') + location.hash);
    }
    catch (e) {}
  },

  copyViewLink: function() {
    const url = location.href;
    copyToClipboard(url)
      .then(() => ui.addNotification(null, E('p', _('View link copied.')), 'info'))
      .catch(() => ui.addNotification(null, E('p', _('Could not copy the link.')), 'error'));
  },

  saveFilterPreset: function() {
    const name = prompt(_('Name this filter preset'));
    if (!name || !name.trim()) return;
    const preset = {
      name: name.trim().slice(0, 40),
      query: this.search.value || '',
      kind: this.kind.value,
      proto: this.proto.value,
      window: this.window.value
    };
    this.filterPresets = this.filterPresets.filter(p => p.name !== preset.name);
    this.filterPresets.unshift(preset);
    this.filterPresets = this.filterPresets.slice(0, 20);
    try {
      localStorage.setItem('reffix-log-viewer.filters', JSON.stringify(this.filterPresets));
      this.renderPresetOptions();
      this.presets.value = preset.name;
      if (this.deletePresetButton) this.deletePresetButton.disabled = false;
    }
    catch (e) {
      ui.addNotification(null, E('p', _('Unable to save filter presets in this browser.')), 'warning');
    }
  },

  renderPresetOptions: function() {
    if (!this.presets) return;
    this.presets.replaceChildren(E('option', {value: ''}, _('Choose a saved filter')));
    this.filterPresets.forEach(p => this.presets.appendChild(E('option', {value: p.name}, p.name)));
  },

  applyFilterPreset: function(name) {
    const preset = this.filterPresets.find(p => p.name === name);
    if (!preset) return;
    this.search.value = preset.query;
    this.kind.value = this.kindFilter = preset.kind;
    this.proto.value = this.protoFilter = preset.proto;
    this.window.value = this.timeFilter = preset.window;
    this.sourceFilter = '';
    this.countryFilter = '';
    this.asnFilter = '';
    this.portFilter = null;
    this.maxEntries = PAGE_SIZE;
    this.renderRows();
    this.renderInsightsPanel();
  },

  removeFilterPreset: function() {
    const name = this.presets.value;
    if (!name) return;
    this.filterPresets = this.filterPresets.filter(p => p.name !== name);
    try {
      localStorage.setItem('reffix-log-viewer.filters', JSON.stringify(this.filterPresets));
    }
    catch (e) {}
    this.renderPresetOptions();
    if (this.deletePresetButton) this.deletePresetButton.disabled = true;
  },

  loadGeoStatus: async function() {
    try {
      this.geoStatus = JSON.parse(await fs.exec_direct('/usr/bin/flint4-geoip', ['--status'], 'text'));
    }
    catch (e) {
      this.geoStatus = {available: false};
    }
  },

  applyPolicy: function(event) {
    const marker = String(event.marker || event.prefix || '').toUpperCase();
    const rule = this.policyRules.find(p =>
      p && String(p.marker || '').toUpperCase() === marker &&
      (p.port == null || Number(p.port) === Number(event.dport))
    );
    if (rule) {
      event.policyLabel = String(rule.label || marker);
      event.policyNote = String(rule.note || '');
    }
    event.baseKind = event.kind;
    event.basePolicyLabel = event.policyLabel;
    event.basePolicyNote = event.policyNote;
    return event;
  },

  routerNowMs: function() {
    return this.routerClockAtSync ? this.routerClockAtSync + (Date.now() - this.routerClockSyncedAt) : Date.now();
  },

  storeHistory: async function(events) {
    if (this.historyRetention === 'off' || !events.length) return;
    const db = await openHistoryDatabase();
    const tx = db.transaction('events', 'readwrite');
    const store = tx.objectStore('events');
    const now = this.routerNowMs();
    events.forEach(event => {
      if (event.rawLine) store.put({
        key: event.rawLine,
        rawLine: event.rawLine,
        timestampMs: event.timestampMs || now,
        routerOffset: this.watchConfig && this.watchConfig.router_offset || ''
      });
    });
    const cutoff = now - Number(this.historyRetention) * 86400000;
    let kept = 0;
    const cursorRequest = store.index('timestampMs').openCursor(null, 'prev');
    cursorRequest.onsuccess = () => {
      const cursor = cursorRequest.result;
      if (!cursor) return;
      if (cursor.value.timestampMs < cutoff || kept >= 10000) cursor.delete();
      else kept++;
      cursor.continue();
    };
    await historyTransactionDone(tx);
  },

  loadHistory: async function() {
    if (this.historyRetention === 'off') return [];
    const db = await openHistoryDatabase();
    const tx = db.transaction('events', 'readonly');
    const rows = await historyRequest(tx.objectStore('events').getAll());
    const cutoff = this.routerNowMs() - Number(this.historyRetention) * 86400000;
    return rows.filter(row => row.timestampMs >= cutoff).map((row, index) => {
      const event = parseLine(row.rawLine, index + 1, row.routerOffset);
      if (!event) return null;
      event.timestampMs = row.timestampMs;
      return this.applyTrafficContext(this.applyPolicy(event));
    }).filter(Boolean);
  },

  clearLocalHistory: async function() {
    const db = await openHistoryDatabase();
    const tx = db.transaction('events', 'readwrite');
    tx.objectStore('events').clear();
    await historyTransactionDone(tx);
    this.historyCache = new Map();
    this.historySeedPending = false;
    this.historyNeedsReload = true;
    this.historyStatusText.textContent = _('Browser-local history cleared.');
    this.historyRetentionSelect.value = this.historyRetention;
    this.refreshEvents().catch(() => {});
  },

  renderWatchStatus: function() {
    if (!this.watchStatusText) return;
    const config = this.watchConfig;
    if (!config) {
      this.watchStatusText.textContent = _('WAN watch status unavailable');
      return;
    }
    const count = String(config.ports || '').split(/[\s,]+/).filter(Boolean).length;
    const state = watchEnabled(config)
      ? (watchInstalled(config) ? _('active') : _('enabled · rules not detected'))
      : _('disabled');
    const family = config.address_family || 'IPv4';
    const scope = config.mode === 'probe'
      ? _('probes · verdict unverified') + (config.active_interface ? ' · ' + config.active_interface : '')
      : _('confirmed drops') + ' · ' + _('zone ') + (config.wan_zone || 'wan');
    const rate = config.log_rate ? ' · ' + config.log_rate : '';
    this.watchStatusText.textContent = _('WAN watch ') + state + ' · ' + scope + ' · ' + family + ' · ' + count + _(' ports') + rate;
  },

  exportSettings: async function() {
    await this.loadWatchConfig();
    const data = {
      schema: 'reffix-firewall-log-settings', version: 1,
      watcher: this.watchConfig ? {
        enabled: watchEnabled(this.watchConfig),
        mode: this.watchConfig.mode === 'probe' ? 'probe' : 'verdict',
        wan_zone: this.watchConfig.wan_zone || 'wan',
        wan_interface: this.watchConfig.wan_interface || 'auto',
        ipv6: this.watchConfig.ipv6 === 0 || this.watchConfig.ipv6 === '0' ? 0 : 1,
        ports: this.watchConfig.ports || '',
        log_other_ports: this.watchConfig.log_other_ports === 1 || this.watchConfig.log_other_ports === '1' ? 1 : 0
      } : null,
      browser: {
        exposedPorts: this.exposedPorts,
        filterPresets: this.filterPresets,
        showReputation: this.showReputation,
        historyRetention: this.historyRetention,
        insightsOpen: !!this.insightsDisclosure.open
      }
    };
    downloadBlob('reffix-firewall-log-settings.json', new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}));
  },

  importSettings: function(file) {
    const reader = new FileReader();
    reader.onerror = () => ui.addNotification(null, E('p', _('Could not read settings file.')), 'error');
    reader.onload = () => {
      let data;
      try { data = JSON.parse(String(reader.result || '')); }
      catch (e) { ui.addNotification(null, E('p', _('Settings file is not valid JSON.')), 'error'); return; }
      if (!data || data.schema !== 'reffix-firewall-log-settings' || data.version !== 1 || !data.browser || typeof data.browser !== 'object') {
        ui.addNotification(null, E('p', _('This is not a supported Firewall Log settings file.')), 'error'); return;
      }
      const browser = data.browser;
      const exposedPorts = {};
      if (browser.exposedPorts && typeof browser.exposedPorts === 'object' && !Array.isArray(browser.exposedPorts)) {
        for (const [port, label] of Object.entries(browser.exposedPorts)) {
          if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535 || typeof label !== 'string' || label.length > 60) {
            ui.addNotification(null, E('p', _('Settings contain an invalid exposed port label.')), 'error'); return;
          }
          exposedPorts[port] = label.trim() || ('Port ' + port);
        }
      }
      const presets = Array.isArray(browser.filterPresets) ? browser.filterPresets.filter(p =>
        p && typeof p.name === 'string' && typeof p.query === 'string' &&
        ['known', 'all', 'blocked', 'probe', 'other', 'observed', 'allowed', 'exposed'].includes(p.kind) &&
        ['all', 'tcp', 'udp', 'icmp'].includes(p.proto) && ['all', '5m', '15m', '1h', '6h', '24h'].includes(p.window)
      ).slice(0, 20) : [];
      const watcher = data.watcher;
      if (watcher && (typeof watcher.enabled !== 'boolean' || typeof watcher.wan_interface !== 'string' ||
          !/^(auto|[a-zA-Z0-9_.:-]{1,32})$/.test(watcher.wan_interface) || typeof watcher.ports !== 'string' ||
          watcher.ports.length > 4096 || /[^0-9,\s]/.test(watcher.ports) ||
          (watcher.mode != null && !['verdict', 'probe'].includes(watcher.mode)) ||
          (watcher.wan_zone != null && !/^[a-zA-Z0-9_]{1,16}$/.test(watcher.wan_zone)) ||
          (watcher.ipv6 != null && ![0, 1, '0', '1', true, false].includes(watcher.ipv6)))) {
        ui.addNotification(null, E('p', _('Settings contain invalid WAN watch configuration.')), 'error'); return;
      }
      const summary = E('ul', {}, [
        E('li', {}, Object.keys(exposedPorts).length + _(' exposed-service labels')),
        E('li', {}, presets.length + _(' saved filter presets')),
        E('li', {}, watcher ? _('Router WAN watch settings will also be updated.') : _('Router WAN watch settings are not included.'))
      ]);
      const buttons = E('div', {class: 'fw-modal-actions'}, [
        E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Cancel')),
        E('button', {class: 'cbi-button cbi-button-action important', type: 'button', click: async () => {
          try {
            if (watcher) {
              const raw = await fs.exec_direct('/usr/sbin/infra-port-watch-config', ['set', watcher.enabled ? '1' : '0',
                watcher.mode || 'verdict', watcher.wan_zone || 'wan', watcher.wan_interface,
                watcher.ipv6 === 0 || watcher.ipv6 === '0' || watcher.ipv6 === false ? '0' : '1',
                watcher.log_other_ports ? '1' : '0', watcher.ports], 'text');
              const imported = parseWatchConfig(raw);
              if (!imported) throw new Error(_('The router did not confirm the imported settings.'));
              this.watchConfig = imported;
              this.watchConfigLoaded = true;
              this.watchConfigSyncedAt = Date.now();
            }
          }
          catch (e) { ui.addNotification(null, E('p', _('Router settings were not applied: ') + (e.message || e)), 'error'); return; }
          this.exposedPorts = exposedPorts;
          this.filterPresets = presets;
          this.showReputation = browser.showReputation === true;
          this.historyRetention = ['off', '1', '7', '30'].includes(browser.historyRetention) ? browser.historyRetention : 'off';
          try {
            localStorage.setItem('reffix-log-viewer.traffic-context', JSON.stringify({exposedPorts}));
            localStorage.setItem('reffix-log-viewer.filters', JSON.stringify(presets));
            localStorage.setItem('reffix-log-viewer.external-reputation', String(this.showReputation));
            localStorage.setItem('reffix-log-viewer.history-days', this.historyRetention);
            localStorage.setItem('reffix-log-viewer.insights-open', String(browser.insightsOpen === true));
          }
          catch (e) { ui.addNotification(null, E('p', _('Some browser settings could not be stored.')), 'warning'); }
          ui.hideModal();
          location.reload();
        }}, _('Apply settings'))
      ]);
      ui.showModal(_('Review settings import'), [
        E('p', {}, _('Review the settings before applying them. Router settings will be written to this router; browser preferences stay local to this browser.')),
        summary,
        buttons
      ], 'fw-modal', 'fw-review-modal');
    };
    reader.readAsText(file);
  },

  importFirewallForwards: async function() {
    await this.loadWatchConfig(true);
    const redirects = this.watchConfig && Array.isArray(this.watchConfig.redirects) ? this.watchConfig.redirects : [];
    if (!redirects.length) {
      ui.addNotification(null, E('p', _('No enabled IPv4 port forwards were found in the firewall configuration.')), 'info');
      return;
    }
    const choices = redirects.map((item, index) => {
      const portSpec = String(item.source_ports || '').trim();
      const tokens = portSpec.split(/[\s,]+/).filter(Boolean);
      const ports = [];
      let valid = tokens.length > 0;
      tokens.forEach(token => {
        const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
        if (!match) { valid = false; return; }
        const from = Number(match[1]), to = Number(match[2] || match[1]);
        if (!from || to < from || to > 65535 || ports.length + to - from + 1 > 256) { valid = false; return; }
        for (let port = from; port <= to; port++) ports.push(port);
      });
      const check = E('input', {type: 'checkbox', disabled: !valid, checked: valid});
      const protocol = item.protocol || 'tcp';
      return {item, ports, check, label: E('label', {class: 'fw-settings-field fw-check-field'}, [check,
        E('span', {}, (item.name || _('Unnamed forward')) + ' · ' + (item.source_zone || '?') + ' · ' + portSpec + '/' + protocol +
          (item.destination_port ? ' → destination port ' + item.destination_port : ''))])};
    });
    const buttons = E('div', {class: 'fw-modal-actions'}, [
      E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Cancel')),
      E('button', {class: 'cbi-button cbi-button-action important', type: 'button', click: () => {
        const next = Object.assign({}, this.exposedPorts);
        choices.filter(choice => choice.check.checked).forEach(({item, ports}) => {
          const label = String(item.name || 'Exposed service').slice(0, 60);
          ports.forEach(port => { next[Number(port)] = label; });
        });
        this.exposedPorts = next;
        try { localStorage.setItem('reffix-log-viewer.traffic-context', JSON.stringify({exposedPorts: next})); }
        catch (e) { ui.addNotification(null, E('p', _('Could not save labels in this browser.')), 'warning'); }
        this.events.forEach(event => this.applyTrafficContext(event));
        this.historyNeedsReload = true;
        ui.hideModal();
        this.renderRows();
        this.renderInsightsPanel();
      }}, _('Import selected labels'))
    ]);
    ui.showModal(_('Review firewall forwards'), [
      E('p', {class: 'cbi-section-descr'}, _('Select which WAN-forward destination ports should receive exposed-service labels. This imports labels only; it does not read LAN hostnames or change firewall rules. Verify each entry before importing.')),
      ...choices.map(choice => choice.label),
      buttons
    ], 'fw-modal', 'fw-review-modal');
  },

  parseTrafficContext: function(interfacesText, portsText) {
    const interfaces = [...new Set(String(interfacesText || '').split(/[\s,]+/)
      .map(v => v.trim().toLowerCase()).filter(v => /^[a-z0-9_.:-]{1,32}$/.test(v)))];
    const ports = {};
    String(portsText || '').split(/\r?\n/).forEach(line => {
      const match = line.match(/^\s*(\d{1,5})\s*(?:=|:|\s)\s*(.*?)\s*$/);
      if (!match) return;
      const port = Number(match[1]);
      if (port > 0 && port <= 65535) ports[port] = match[2].slice(0, 60) || ('Port ' + port);
    });
    return {interfaces, ports};
  },

  openHistorySettings: async function() {
    let status = {};
    try { status = parseWatchConfig(await fs.exec_direct('/usr/sbin/log-viewer-history', ['status'], 'text')) || {}; }
    catch (e) {}
    const enabled = E('input', {type: 'checkbox'});
    enabled.checked = status.persist_enabled === 1;
    const directory = E('input', {class: 'cbi-input-text', type: 'text', value: status.persist_directory || '/srv/log-viewer'});
    const days = E('input', {class: 'cbi-input-text', type: 'number', min: 1, max: 3650, value: String(status.persist_days || 7)});
    const maxMb = E('input', {class: 'cbi-input-text', type: 'number', min: 1, max: 8192, value: String(status.persist_max_mb || 32)});
    const ring = E('input', {class: 'cbi-input-text', type: 'number', min: 100, max: 5000, value: String(status.cap || 500)});
    const error = E('p', {class: 'fw-modal-error', hidden: true, role: 'alert'});
    const stats = E('p', {class: 'fw-help'}, _('Router memory: ') + (status.count != null ? status.count : '—') +
      _(' of ') + (status.cap || 500) + _(' lines · ') +
      (status.persist_enabled === 1 ? (status.persist_files || 0) + _(' files, ') + (status.persist_kb || 0) + ' KB' : _('disk history off')));
    const save = E('button', {class: 'cbi-button cbi-button-action important', type: 'button', click: async () => {
      error.hidden = true;
      save.disabled = true;
      try {
        const raw = await fs.exec_direct('/usr/sbin/log-viewer-history', [
          'configure', enabled.checked ? '1' : '0', directory.value.trim(), days.value, maxMb.value, ring.value
        ], 'text');
        const savedHistory = parseWatchConfig(raw);
        if (!savedHistory) throw new Error(_('The router did not confirm the history settings.'));
        this.routerHistoryStatus = savedHistory;
        this.routerHistorySyncedAt = Date.now();
        if (this.routerHistoryText && this.routerHistoryStatus) {
          const count = this.routerHistoryStatus.count != null ? this.routerHistoryStatus.count : '—';
          const cap = this.routerHistoryStatus.cap || 500;
          this.routerHistoryText.textContent = _('Router memory: ') + count + _(' of ') + cap +
            _(' firewall lines') + (this.routerHistoryStatus.persist_enabled === 1
              ? _(' · disk history on, ') + (this.routerHistoryStatus.persist_files || 0) + _(' files')
              : _(' · disk history off'));
        }
        ui.hideModal();
        ui.addNotification(null, E('p', _('History settings saved. The collector restarted.')), 'info');
      }
      catch (e) {
        save.disabled = false;
        error.textContent = _('Could not save history settings: ') + (e.message || e);
        error.hidden = false;
      }
    }}, _('Save history settings'));
    ui.showModal(_('History settings'), [
      E('p', {class: 'cbi-section-descr'}, _('The router always keeps a small ring in RAM. Opt in to daily files on a mounted disk or USB path; use a mounted disk rather than internal flash.')),
      stats,
      E('label', {class: 'fw-settings-field fw-watch-toggle'}, [enabled, E('span', {}, _('Enable persistent disk history'))]),
      E('div', {class: 'fw-watch-grid'}, [
        E('label', {class: 'fw-settings-field'}, [
          E('span', {}, _('Directory')),
          directory,
          E('small', {}, _('Must be under /srv, /mnt, /media, /etc/log-viewer or /tmp.'))
        ]),
        E('label', {class: 'fw-settings-field'}, [
          E('span', {}, _('Retention (days)')),
          days,
          E('small', {}, _('Older daily files are pruned automatically.'))
        ])
      ]),
      E('div', {class: 'fw-watch-grid'}, [
        E('label', {class: 'fw-settings-field'}, [
          E('span', {}, _('Maximum size (MB)')),
          maxMb,
          E('small', {}, _('Oldest daily files are removed past this limit.'))
        ]),
        E('label', {class: 'fw-settings-field'}, [
          E('span', {}, _('Lines kept in RAM')),
          ring,
          E('small', {}, _('100-5000. The ring survives page reloads, not reboots.'))
        ])
      ]),
      error,
      E('div', {class: 'fw-modal-actions'}, [
        E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Cancel')),
        save
      ])
    ], 'fw-modal', 'fw-history-settings-modal');
  },

  openServerHistory: async function() {
    let status = null;
    try { status = parseWatchConfig(await fs.exec_direct('/usr/sbin/log-viewer-history', ['status'], 'text')); }
    catch (e) {}
    const state = {
      offset: 0, limit: 100, total: 0, events: [], sort: 'time', order: 'desc',
      verdict: 'all', protocol: 'all', port: '', source: '', search: '', days: 0
    };
    const search = E('input', {class: 'cbi-input-text', type: 'search', placeholder: _('Search stored lines…'), 'aria-label': _('Search router history')});
    const verdict = E('select', {class: 'cbi-input-select', 'aria-label': _('Filter stored events by verdict')}, [
      E('option', {value: 'all'}, _('All verdicts')),
      E('option', {value: 'blocked'}, _('Blocked')),
      E('option', {value: 'other'}, _('Other')),
      E('option', {value: 'allowed'}, _('Allowed'))
    ]);
    const protocol = E('select', {class: 'cbi-input-select', 'aria-label': _('Filter stored events by protocol')}, [
      E('option', {value: 'all'}, _('All protocols')),
      E('option', {value: 'tcp'}, 'TCP'),
      E('option', {value: 'udp'}, 'UDP')
    ]);
    const port = E('input', {class: 'cbi-input-text', type: 'number', min: 1, max: 65535, placeholder: _('Port'), 'aria-label': _('Filter stored events by port')});
    const days = E('select', {class: 'cbi-input-select', 'aria-label': _('Limit stored events by age')}, [
      E('option', {value: '0'}, _('All stored days')),
      E('option', {value: '1'}, _('Last 24 hours')),
      E('option', {value: '7'}, _('Last 7 days')),
      E('option', {value: '30'}, _('Last 30 days'))
    ]);
    const sort = E('select', {class: 'cbi-input-select', 'aria-label': _('Sort stored events')}, [
      E('option', {value: 'time'}, _('Time')),
      E('option', {value: 'source'}, _('Source')),
      E('option', {value: 'port'}, _('Port'))
    ]);
    const order = E('select', {class: 'cbi-input-select', 'aria-label': _('Sort direction')}, [
      E('option', {value: 'desc'}, _('Descending')),
      E('option', {value: 'asc'}, _('Ascending'))
    ]);
    const tbody = E('tbody');
    const table = E('table', {class: 'table fw-table fw-history-table'}, [
      E('thead', {}, E('tr', {class: 'tr table-titles'},
        ['Time', 'Source / GeoIP', 'Destination', 'Port / Protocol', 'Verdict', 'Packet', 'Details']
          .map(title => E('th', {class: 'th'}, _(title))))),
      tbody
    ]);
    const counter = E('span', {class: 'fw-muted'});
    const error = E('p', {class: 'fw-modal-error', hidden: true, role: 'alert'});
    const eventById = new Map();
    let searchTimer;
    const prev = E('button', {class: 'cbi-button', type: 'button', disabled: true, click: () => {
      state.offset = Math.max(0, state.offset - state.limit);
      load();
    }}, _('Previous'));
    const next = E('button', {class: 'cbi-button', type: 'button', disabled: true, click: () => {
      state.offset += state.limit;
      load();
    }}, _('Next'));
    const load = async () => {
      error.hidden = true;
      const args = ['--limit', String(state.limit), '--offset', String(state.offset),
        '--sort', state.sort, '--order', state.order, '--verdict', state.verdict,
        '--protocol', state.protocol];
      if (state.port) args.push('--port', state.port);
      if (state.source) args.push('--source', state.source);
      if (state.days) args.push('--days', String(state.days));
      if (state.search) args.push('--search', state.search);
      try {
        const raw = await fs.exec_direct('/usr/sbin/log-viewer-query', args, 'text');
        const data = JSON.parse(raw || '{}');
        state.total = Number(data.total) || 0;
        state.events = (Array.isArray(data.lines) ? data.lines : [])
          .map((line, index) => parseLine(line, index + 1, this.watchConfig && this.watchConfig.router_offset))
          .filter(Boolean);
        eventById.clear();
        state.events.forEach(event => eventById.set(String(event.id), event));
        const render = () => {
          tbody.innerHTML = state.events.map(event => this.renderEventRow(event)).join('') ||
            '<tr><td colspan="7" class="center">No stored events match these filters.</td></tr>';
        };
        render();
        counter.textContent = state.total
          ? _('Showing ') + (state.offset + 1) + '–' + Math.min(state.offset + state.events.length, state.total) +
            _(' of ') + state.total + (data.partial ? ' · ' + _('sorted the most recent 2,000 matches') : '')
          : _('No stored events match these filters.');
        prev.disabled = state.offset <= 0;
        next.disabled = state.offset + state.limit >= state.total;
        this.enrich(state.events).then(() => { if (tbody.isConnected) render(); }).catch(() => {});
      }
      catch (e) {
        error.textContent = _('Could not read router history: ') + (e.message || e);
        error.hidden = false;
        tbody.innerHTML = '';
      }
    };
    const reload = () => { state.offset = 0; load(); };
    search.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state.search = search.value.trim(); reload(); }, 150);
    });
    verdict.addEventListener('change', () => { state.verdict = verdict.value; reload(); });
    days.addEventListener('change', () => { state.days = Number(days.value) || 0; reload(); });
    protocol.addEventListener('change', () => { state.protocol = protocol.value; reload(); });
    port.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state.port = port.value.trim(); reload(); }, 150);
    });
    sort.addEventListener('change', () => { state.sort = sort.value; reload(); });
    order.addEventListener('change', () => { state.order = order.value; reload(); });
    tbody.addEventListener('click', ev => {
      const sourceLink = ev.target.closest('.fw-source-link');
      if (sourceLink) {
        this.openIpDrawer(sourceLink.getAttribute('data-source') || '', state.events);
        return;
      }
      const detailButton = ev.target.closest('.fw-event-details');
      if (detailButton) {
        const event = eventById.get(detailButton.getAttribute('data-id'));
        if (event) this.showEventDetails(event);
      }
    });
    const persistent = status && status.persist_enabled === 1;
    ui.showModal(_('Router history'), [
      E('p', {class: 'cbi-section-descr'}, _('Reads the router ring and opt-in disk history in pages. Filtering and sorting happen on the router, so large histories do not have to fit in the browser.')),
      E('p', {class: 'fw-help'}, persistent
        ? _('Disk history enabled · ') + (status.persist_files || 0) + _(' files · ') + (status.persist_kb || 0) + ' KB'
        : _('Disk history is off; this searches the router memory ring only.')),
      E('div', {class: 'fw-history-controls'}, [search, verdict, protocol, port, days, sort, order]),
      E('div', {class: 'fw-tablewrap fw-history-tablewrap'}, table),
      E('div', {class: 'fw-history-pager'}, [
        counter,
        E('div', {class: 'fw-history-pager-buttons'}, [prev, next])
      ]),
      error,
      E('div', {class: 'fw-modal-actions'}, [
        E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Close'))
      ])
    ], 'fw-modal', 'fw-history-modal');
    load();
  },

  openTrafficSettings: async function() {
    await this.loadWatchConfig(true);
    const config = this.watchConfig;
    const enabledValue = watchEnabled(config);
    const modeValue = config && config.mode === 'probe' ? 'probe' : 'verdict';
    const zoneValue = config && typeof config.wan_zone === 'string' && config.wan_zone ? config.wan_zone : 'wan';
    const wanValue = config && typeof config.wan_interface === 'string' && config.wan_interface ? config.wan_interface : 'auto';
    const portValue = config && typeof config.ports === 'string' ? config.ports : '';
    const ipv6Value = !config || !(config.ipv6 === false || config.ipv6 === 0 || config.ipv6 === '0');

    const watching = E('input', {type: 'checkbox'});
    watching.checked = enabledValue;
    const mode = E('select', {class: 'cbi-input-select', 'aria-label': _('What to log')}, [
      E('option', {value: 'verdict'}, _('Confirmed drops only')),
      E('option', {value: 'probe'}, _('Every probe (verdict unverified)'))
    ]);
    mode.value = modeValue;
    const zone = E('input', {class: 'cbi-input-text', type: 'text', value: zoneValue, placeholder: 'wan'});
    const interfaces = E('input', {class: 'cbi-input-text', type: 'text', value: wanValue, placeholder: _('auto or e.g. pppoe-wan')});
    const ipv6 = E('input', {type: 'checkbox'});
    ipv6.checked = ipv6Value;
    const otherSample = E('input', {type: 'checkbox'});
    otherSample.checked = !!(config && (config.log_other_ports === 1 || config.log_other_ports === '1' || config.log_other_ports === true));
    const watchPorts = E('textarea', {class: 'cbi-input-text fw-port-list', rows: 7, placeholder: _('One port per line, or separated by commas/spaces'), value: portValue});
    const ports = E('textarea', {class: 'cbi-input-text fw-port-list', rows: 5, placeholder: _('8096 = Jellyfin\n8920 = Jellyfin HTTPS')});
    ports.value = Object.entries(this.exposedPorts).map(([port, label]) => port + ' = ' + label).join('\n');
    const error = E('p', {class: 'fw-modal-error', hidden: true, role: 'alert'});
    const note = E('p', {class: 'fw-help', hidden: true, role: 'status'});
    const modeHint = E('p', {class: 'fw-help'});
    const updateHint = () => {
      modeHint.textContent = mode.value === 'verdict'
        ? _('Rows are logged after every allow rule: the firewall evaluated the packet and the zone policy drops it. This is the accurate mode and it needs no WAN device name.')
        : _('Rows are logged before filtering, so each one is a probe whose verdict is unknown. Useful to see attempts against forwarded ports.');
    };
    updateHint();
    mode.addEventListener('change', updateHint);

    const status = config
      ? (watchEnabled(config)
        ? _('Enabled on this router') +
          (config.mode === 'probe'
            ? (config.active_interface ? _(' · probe on ') + config.active_interface : _(' · probe mode'))
            : _(' · confirmed drops on zone ') + (config.wan_zone || 'wan')) +
          (watchInstalled(config) ? _(' · rules installed') : _(' · rules not detected')) +
          (config.verdict === 'unknown' ? _(' · verdicts not observed') : '')
        : _('Disabled on this router.'))
      : _('Current WAN watch status is unavailable. Saving will configure it.');

    const repair = E('button', {class: 'cbi-button', type: 'button', click: async () => {
      repair.disabled = true;
      try {
        const output = await fs.exec_direct('/usr/sbin/infra-port-watch', ['apply'], 'text', false, true);
        await this.loadWatchConfig(true);
        this.renderWatchStatus();
        if (!watchInstalled(this.watchConfig))
          throw new Error(String(output || '').trim() || _('The firewall did not load the new rules.'));
        ui.addNotification(null, E('p', _('Watch rules re-applied.')), 'info');
      }
      catch (e) { ui.addNotification(null, E('p', _('Could not re-apply the rules: ') + (e.message || e)), 'error'); }
      finally { repair.disabled = false; }
    }}, _('Re-apply rules'));

    const saveButton = E('button', {class: 'cbi-button cbi-button-action important', type: 'button', click: async () => {
      error.hidden = true;
      note.hidden = true;
      const wanZone = zone.value.trim() || 'wan';
      if (!/^[a-zA-Z0-9_]{1,16}$/.test(wanZone)) {
        error.textContent = _('Firewall zone names use letters, digits and underscores.');
        error.hidden = false;
        return;
      }
      const wan = interfaces.value.trim() || 'auto';
      if (!/^(auto|[a-zA-Z0-9_.:-]{1,32})$/.test(wan)) {
        error.textContent = _('WAN interface may contain only letters, digits, dot, colon, underscore or dash.');
        error.hidden = false;
        return;
      }
      const uniquePorts = new Set();
      for (const token of watchPorts.value.split(/[\s,]+/).filter(Boolean)) {
        if (!/^\d{1,5}$/.test(token)) {
          error.textContent = _('Invalid port: ') + token;
          error.hidden = false;
          return;
        }
        const port = Number(token);
        if (port < 1 || port > 65535) {
          error.textContent = _('Port out of range: ') + token;
          error.hidden = false;
          return;
        }
        uniquePorts.add(port);
      }
      if (!uniquePorts.size) {
        error.textContent = _('Add at least one port to the watch list.');
        error.hidden = false;
        return;
      }
      if (uniquePorts.size > 256) {
        error.textContent = _('The watch list is limited to 256 ports.');
        error.hidden = false;
        return;
      }
      saveButton.disabled = true;
      try {
        const raw = await fs.exec_direct('/usr/sbin/infra-port-watch-config', [
          'set', watching.checked ? '1' : '0', mode.value, wanZone, wan,
          ipv6.checked ? '1' : '0', otherSample.checked ? '1' : '0', watchPorts.value
        ], 'text');
        const savedConfig = parseWatchConfig(raw);
        if (!savedConfig) throw new Error(_('The router did not confirm the new settings.'));
        this.watchConfig = savedConfig;
        this.watchConfigLoaded = true;
        this.watchConfigSyncedAt = Date.now();
      }
      catch (e) {
        saveButton.disabled = false;
        error.textContent = _('Could not apply WAN watch settings: ') + (e.message || e);
        error.hidden = false;
        return;
      }
      const saved = this.watchConfig;
      const parsed = this.parseTrafficContext(wan, ports.value);
      const activeInterface = saved && (saved.active_interface ||
        (saved.wan_interface !== 'auto' ? saved.wan_interface : ''));
      this.wanInterfaces = activeInterface ? [String(activeInterface).toLowerCase()] : [];
      this.exposedPorts = parsed.ports;
      try { localStorage.setItem('reffix-log-viewer.traffic-context', JSON.stringify({exposedPorts: parsed.ports})); }
      catch (e) { ui.addNotification(null, E('p', _('Could not save settings in this browser.')), 'warning'); }
      this.events.forEach(event => this.applyTrafficContext(event));
      this.historyNeedsReload = true;
      ui.hideModal();
      this.renderWatchStatus();
      this.renderRows();
      this.renderInsightsPanel();
      ui.addNotification(null, E('p', _('WAN watch settings saved.')), 'info');
    }}, _('Save settings'));

    const addDefaults = E('button', {class: 'cbi-button', type: 'button', click: () => {
      const next = mergeMissingDefaultPorts(watchPorts.value, DEFAULT_WATCH_PORTS);
      if (!next.ok) {
        error.textContent = next.reason === 'full'
          ? _('Adding the missing default ports would pass 256 ports.')
          : _('The port list contains a value that cannot be kept.');
        error.hidden = false;
        return;
      }
      watchPorts.value = next.ports;
      error.hidden = true;
      note.textContent = next.added.length
        ? _('Added ') + next.added.length + _(' missing default ports. Save settings to apply them.')
        : _('Every default port is already in the list.');
      note.hidden = false;
    }}, _('Add missing default ports'));

    ui.showModal(_('WAN watch settings'), [
      E('p', {class: 'cbi-section-descr'}, _('The watch only logs, it never accepts or drops traffic. Each source address has its own log budget.')),
      E('div', {class: 'fw-watch-status'}, status),
      E('label', {class: 'fw-settings-field'}, [
        E('span', {}, _('What to log')),
        mode,
        modeHint
      ]),
      E('label', {class: 'fw-settings-field fw-watch-toggle'}, [watching, E('span', {}, _('Enable WAN port watch'))]),
      E('div', {class: 'fw-watch-grid'}, [
        E('label', {class: 'fw-settings-field'}, [
          E('span', {}, _('WAN firewall zone')),
          zone,
          E('small', {}, _('The zone whose input and forward chains are watched, usually wan.'))
        ]),
        E('label', {class: 'fw-settings-field'}, [
          E('span', {}, _('Ports to log')),
          watchPorts,
          E('small', {}, _('1-65535, separated by commas or spaces, up to 256 ports.'))
        ])
      ]),
      E('label', {class: 'fw-settings-field fw-watch-toggle'}, [ipv6, E('span', {}, _('Include IPv6'))]),
      E('label', {class: 'fw-settings-field fw-watch-toggle'}, [otherSample, E('span', {}, _('Also sample other ports (low rate)'))]),
      E('label', {class: 'fw-settings-field'}, [
        E('span', {}, _('WAN device (probe mode only)')),
        interfaces,
        E('small', {}, _('Use auto, or the device shown in IN= (for example pppoe-wan).'))
      ]),
      E('div', {class: 'fw-settings-actions'}, [addDefaults, repair]),
      note,
      E('h5', {class: 'fw-section-heading'}, _('Service labels')),
      E('p', {class: 'cbi-section-descr'}, _('Labels stay in this browser. In probe mode a labelled port is shown as Exposed instead of Probe.')),
      E('label', {class: 'fw-settings-field'}, [
        E('span', {}, _('Exposed destination ports')),
        ports,
        E('small', {}, _('One port = label per line.'))
      ]),
      error,
      E('div', {class: 'fw-modal-actions'}, [
        E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Cancel')),
        saveButton
      ])
    ], 'fw-modal', 'fw-wan-modal');
  },

  addWatchPort: async function(port) {
    await this.loadWatchConfig(true);
    const config = this.watchConfig;
    if (!config) {
      ui.addNotification(null, E('p', _('WAN watch status is unavailable, so the port was not added.')), 'error');
      return;
    }
    const next = appendWatchPort(config.ports || '', port);
    if (!next.ok) {
      ui.addNotification(null, E('p', next.reason === 'full'
        ? _('The watch list already has 256 ports.')
        : _('That port cannot be added.')), 'error');
      return;
    }
    if (!next.changed) {
      ui.addNotification(null, E('p', _('That port is already on the known list.')), 'info');
      ui.hideModal();
      return;
    }
    try {
      const enabled = watchEnabled(config) ? '1' : '0';
      const other = config.log_other_ports === 1 || config.log_other_ports === '1' ? '1' : '0';
      const raw = await fs.exec_direct('/usr/sbin/infra-port-watch-config', [
        'set', enabled, config.mode || 'verdict', config.wan_zone || 'wan',
        config.wan_interface || 'auto', config.ipv6 === 0 || config.ipv6 === '0' ? '0' : '1', other, next.ports
      ], 'text');
      const updated = parseWatchConfig(raw);
      if (!updated) throw new Error(_('The router did not confirm the port change.'));
      this.watchConfig = updated;
      this.watchConfigLoaded = true;
      this.watchConfigSyncedAt = Date.now();
    }
    catch (e) {
      ui.addNotification(null, E('p', _('Could not add the port: ') + (e.message || e)), 'error');
      return;
    }
    this.renderWatchStatus();
    ui.hideModal();
    ui.addNotification(null, E('p', _('Port ') + port + _(' is on the known list. Later hits use the full per-address budget.')), 'info');
  },

  updateGeoDatabases: async function() {
    if (this.geoUpdateButton) this.geoUpdateButton.disabled = true;
    if (this.geoStatusText) this.geoStatusText.textContent = _('Updating GeoIP databases…');
    const stateLine = E('p', {class: 'fw-geo-state'}, _('Starting GeoIP update…'));
    const detail = E('pre', {class: 'fw-raw-log fw-geo-log'}, '');
    const error = E('p', {class: 'fw-modal-error', hidden: true, role: 'alert'});
    let poll = null;
    let finished = false;
    let output = '';
    const close = E('button', {class: 'cbi-button', type: 'button', click: () => {
      if (poll) clearInterval(poll);
      ui.hideModal();
    }}, _('Close'));
    const readStatus = async () => {
      try { return parseWatchConfig(await fs.read('/tmp/log-viewer/geoip-update.status')); }
      catch (e) { return null; }
    };
    const updateStatus = async () => {
      const status = await readStatus();
      if (!status || finished) return;
      stateLine.textContent = status.message || status.state || '';
      const sizes = [];
      if (status.country_bytes) sizes.push(_('Country ') + formatBytes(status.country_bytes));
      if (status.asn_bytes) sizes.push(_('ASN ') + formatBytes(status.asn_bytes));
      if (sizes.length) detail.textContent = sizes.join(' · ');
      if (status.state === 'complete' || status.state === 'done' || status.state === 'error') {
        if (poll) { clearInterval(poll); poll = null; }
        close.disabled = false;
      }
    };
    ui.showModal(_('Update GeoIP databases'), [
      E('p', {class: 'cbi-section-descr'}, _('Downloads the GeoLite2 Country and ASN databases from GitHub, validates both with mmdblookup, then replaces the local copies. This can take a minute on a slow link.')),
      stateLine,
      detail,
      error,
      E('div', {class: 'fw-modal-actions'}, [close])
    ], 'fw-modal', 'fw-geo-modal');
    await updateStatus();
    poll = setInterval(updateStatus, 1000);
    try {
      // cgi-io always answers 200 for cgi-exec, so the exit status is not
      // visible here. The status file written by the updater is the source of
      // truth; never claim success from the promise alone.
      output = await fs.exec_direct('/usr/bin/flint4-geoip-update', [], 'text', false, true);
      const status = await readStatus();
      if (status && status.state === 'error')
        throw new Error(status.message || _('The updater reported an error.'));
      if (!status || (status.state !== 'complete' && status.state !== 'done'))
        throw new Error((status && status.message) || _('The update did not complete.'));
      await this.loadGeoStatus();
      this.renderGeoStatus();
      if (!this.geoStatus || !this.geoStatus.available)
        throw new Error(_('The update finished, but the databases are still unavailable.'));
      finished = true;
      const sizes = [];
      if (status.country_bytes) sizes.push(_('Country ') + formatBytes(status.country_bytes));
      if (status.asn_bytes) sizes.push(_('ASN ') + formatBytes(status.asn_bytes));
      stateLine.textContent = _('Applied. Databases are ready.');
      detail.textContent = sizes.join(' · ') || String(output || '').trim();
    }
    catch (e) {
      finished = true;
      const status = await readStatus();
      error.textContent = _('GeoIP databases were not updated: ') + (e.message || e);
      error.hidden = false;
      stateLine.textContent = (status && status.message) || _('Update failed.');
      if (String(output || '').trim()) detail.textContent = String(output).trim();
      try { await this.loadGeoStatus(); this.renderGeoStatus(); }
      catch (statusError) {}
    }
    finally {
      if (poll) clearInterval(poll);
      close.disabled = false;
      if (this.geoUpdateButton) this.geoUpdateButton.disabled = false;
    }
  },
  getTimeWindowMs: function() {
    return ({
      '5m': 5 * 60 * 1000,
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000
    })[this.timeFilter] || 0;
  },

  renderInsights: function(events) {
    const sources = new Map();
    const ports = new Map();
    const asns = new Map();

    events.forEach(e => {
      if (e.source) {
        if (!sources.has(e.source))
          sources.set(e.source, { source: e.source, count: 0, ports: new Set(), firstMs: e.timestampMs, lastMs: e.timestampMs, first: e.timestamp, last: e.timestamp });
        const s = sources.get(e.source);
        s.count++;
        if (e.dport) s.ports.add(e.dport);
        if (e.timestampMs && (!s.lastMs || e.timestampMs > s.lastMs)) {
          s.lastMs = e.timestampMs;
          s.last = e.timestamp;
        }
        if (e.timestampMs && (!s.firstMs || e.timestampMs < s.firstMs)) {
          s.firstMs = e.timestampMs;
          s.first = e.timestamp;
        }
      }

      if (e.dport) {
        const key = String(e.dport);
        if (!ports.has(key))
          ports.set(key, { port: e.dport, service: e.service, count: 0, tcp: 0, udp: 0 });
        const p = ports.get(key);
        p.count++;
        if (e.protocol === 'TCP') p.tcp++;
        if (e.protocol === 'UDP') p.udp++;
      }

      const geo = this.geoCache[e.source] || {};
      if (geo.asn_organization) {
        const key = geo.asn_organization;
        if (!asns.has(key)) asns.set(key, { name: key, count: 0, sources: new Set() });
        asns.get(key).count++;
        asns.get(key).sources.add(e.source);
      }
    });

    const top = (map, key, limit) => [...map.values()]
      .sort((a, b) => b.count - a.count || String(a[key]).localeCompare(String(b[key])))
      .slice(0, limit);
    const renderList = (items, render, empty) => items.length
      ? '<ul class="fw-insight-list">' + items.map(render).join('') + '</ul>'
      : '<p class="fw-muted">' + empty + '</p>';

    const topSources = renderList(top(sources, 'source', 5), item => {
      const geo = this.geoCache[item.source] || {};
      const label = geo.country_name || 'GeoIP pending';
      const countryCode = (geo.country_code || '').toUpperCase();
      const asn = geo.asn_organization ? ' · ' + geo.asn_organization : '';
      const firstSeen = item.firstMs ? new Date(item.firstMs).toLocaleString() : item.first;
      const lastSeen = item.lastMs ? new Date(item.lastMs).toLocaleString() : item.last;
      return '<li><button type="button" class="fw-insight-filter" data-source-filter="' + esc(item.source) + '"><span class="fw-insight-ip"><span class="fw-flag" title="' + esc(label) + '">' + countryFlag(countryCode) + '</span><code>' + esc(item.source) + '</code></span><span>' + item.count + ' events</span>' +
        '<small>' + esc(label + asn) + ' · ' + item.ports.size + ' ports</small><small>First ' + esc(firstSeen) + ' · Last ' + esc(lastSeen) + '</small></button></li>';
    }, 'No sources in this window.');

    const sortedPorts = [...ports.values()].sort((a, b) => b.count - a.count || a.port - b.port);
    const visiblePorts = this.showAllPorts ? sortedPorts : sortedPorts.slice(0, 5);
    const topPorts = renderList(visiblePorts, item =>
      '<li><button type="button" class="fw-insight-port" data-port-filter="' + item.port + '"><strong>' + esc(item.port) + ' · ' + esc(item.service) + '</strong><span>' + item.count + ' events</span>' +
      '<small>TCP ' + item.tcp + ' · UDP ' + item.udp + '</small></button></li>',
      'No destination ports in this window.');

    const topAsns = renderList(top(asns, 'name', 5), item =>
      '<li><strong>' + esc(item.name) + '</strong><span>' + item.count + ' events</span>' +
      '<small>' + item.sources.size + ' source IPs · based on local GeoIP matches</small></li>',
      'No ASN data yet. GeoIP enrichment currently checks up to 60 unique recent sources.');

    const timelineEvents = events.filter(event => Number.isFinite(event.timestampMs));
    const latestTime = this.routerNowMs();
    const earliestTime = timelineEvents.length ? Math.min(...timelineEvents.map(event => event.timestampMs)) : latestTime;
    const span = this.getTimeWindowMs() || Math.max(60000, latestTime - earliestTime + 30000);
    const bucketMs = Math.max(30000, Math.ceil(span / 24 / 30000) * 30000);
    const timelineEnd = Math.ceil(latestTime / bucketMs) * bucketMs;
    const timelineStart = timelineEnd - bucketMs * 24;
    const buckets = Array.from({length:24}, () => 0);
    timelineEvents.forEach(event => {
      const index = Math.floor((event.timestampMs - timelineStart) / bucketMs);
      if (index >= 0 && index < buckets.length) buckets[index]++;
    });
    const maxBucket = Math.max(1, ...buckets);
    const timelineHtml = '<div class="fw-timeline" role="group" aria-label="' + esc(_('Firewall events by time; select a bar to filter')) + '">' +
      buckets.map((count, index) => {
        const start = timelineStart + index * bucketMs;
        const end = start + bucketMs;
        const label = new Date(start).toLocaleString() + ' · ' + count + _(' events');
        const selected = this.timelineRange && this.timelineRange.start === start ? ' aria-pressed="true"' : ' aria-pressed="false"';
        const height = Math.max(count ? 7 : 2, Math.round(count / maxBucket * 100));
        return '<button type="button" class="fw-timeline-bin' + (count ? '' : ' empty') + '" style="--fw-bar-height:' + height + '%" data-timeline-start="' + start + '" data-timeline-end="' + end + '" title="' + esc(label) + '" aria-label="' + esc(label) + '"' + selected + '><span>' + (count || '') + '</span></button>';
      }).join('') + '</div><div class="fw-timeline-labels"><span>' + esc(new Date(timelineStart).toLocaleTimeString()) + '</span><span>' + esc(new Date(timelineEnd).toLocaleTimeString()) + '</span></div>';

    const scanMap = new Map();
    events.forEach(e => {
      if (!isPublic(e.source)) return;
      if (!scanMap.has(e.source))
        scanMap.set(e.source, { source: e.source, count: 0, ports: new Set(), destinations: new Set(), blocked: 0 });
      const s = scanMap.get(e.source);
      s.count++;
      if (e.dport) s.ports.add(e.dport);
      if (e.destination) s.destinations.add(e.destination);
      if (e.kind === 'Blocked') s.blocked++;
    });
    const signals = [...scanMap.values()].map(s => {
      const multiPort = s.ports.size >= 8;
      const burst = s.count >= 25;
      return Object.assign(s, {
        multiPort: multiPort,
        burst: burst,
        signal: multiPort && burst ? 'Multi-port + burst' :
          multiPort ? 'Multi-port pattern' : 'High-volume burst'
      });
    }).filter(s => s.multiPort || s.burst)
      .sort((a, b) => (b.ports.size * 2 + b.count) - (a.ports.size * 2 + a.count))
      .slice(0, 6);

    const scanHtml = renderList(signals, item => {
      const geo = this.geoCache[item.source] || {};
      const country = geo.country_name || 'GeoIP pending';
      const countryCode = (geo.country_code || '').toUpperCase();
      const details = item.ports.size + ' ports · ' + item.destinations.size + ' targets · ' +
        item.count + ' events';
      return '<li><button type="button" class="fw-insight-filter fw-scan-filter" data-source-filter="' + esc(item.source) + '"><span class="fw-insight-ip"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span><code>' + esc(item.source) + '</code></span><span class="fw-signal">' + esc(item.signal) + '</span>' +
        '<small>' + esc(details) + ' · ' + esc(country) + '</small></button></li>';
    }, 'No scan/burst thresholds triggered in this window.');

    const policyNotes = this.policyRules.length
      ? 'Local policy labels active: ' + this.policyRules.length
      : 'Optional policy labels: edit /etc/log-viewer/policies.json to name your rules.';
    return '<div class="fw-insight fw-insight-timeline"><h3>Activity timeline</h3>' + timelineHtml +
        (this.timelineRange ? '<button type="button" class="cbi-button fw-clear-timeline">' + _('Clear timeline filter') + '</button>' : '<p class="fw-muted">' + _('Select a time bar to filter the event table.') + '</p>') + '</div>' +
      '<div class="fw-insight"><h3>Top sources</h3>' + topSources + '</div>' +
      '<div class="fw-insight"><h3>Destination ports <small>(' + sortedPorts.length + ' total)</small></h3>' + topPorts +
        (sortedPorts.length > 5 ? '<button type="button" class="cbi-button fw-show-all-ports">' + (this.showAllPorts ? _('Show top five') : _('Show all ports')) + '</button>' : '') + '</div>' +
      '<div class="fw-insight"><h3>Top ASNs</h3>' + topAsns + '</div>' +
      '<div class="fw-insight"><h3>Scan / burst signals</h3><p class="fw-muted">Heuristic only: 8+ ports or 25+ events from one public source.</p>' + scanHtml + '</div>' +
      '<div class="fw-insight fw-insight-policy"><h3>Policy context</h3><p class="fw-muted">' + esc(policyNotes) + '</p>' +
      '<p class="fw-muted">Blocked means the firewall evaluated the packet and the zone policy dropped it. Probes are logged before filtering, so their verdict is unverified. Allowed appears only when an allow rule logs it.</p></div>';
  },



  rememberGeo: function(ip, record) {
    const hit = record && (record.country_code || record.country_name || record.asn_organization);
    this.geoCache[ip] = hit ? record : (record || {});
    this.geoCacheAt[ip] = Date.now();
    if (!hit) return;
    this.geoMemory = writeGeoMemory(this.geoMemory, ip, record, Date.now(), GEO_MEMORY_MAX);
    try { localStorage.setItem('reffix-log-viewer.geo-cache', JSON.stringify(this.geoMemory)); }
    catch (e) {}
  },

  enrich: async function(events) {
    const addresses = [...new Set(events.map(e => e.source).filter(isPublic))].slice(0, 60);
    const pending = [];
    addresses.forEach(ip => {
      const known = this.geoMemory[ip];
      if (known && (known.country_code || known.country_name || known.asn_organization)) {
        this.geoCache[ip] = known;
        this.geoCacheAt[ip] = known.at || Date.now();
        return;
      }
      if (Object.prototype.hasOwnProperty.call(this.geoCache, ip) &&
          (Object.keys(this.geoCache[ip]).length || Date.now() - (this.geoCacheAt[ip] || 0) < 5 * 60 * 1000))
        return;
      pending.push(ip);
    });
    const chunks = geoBatchChunks(pending, GEO_BATCH_BYTES);
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      try {
        const raw = await fs.exec_direct('/usr/bin/flint4-geoip', ['--batch'].concat(chunk), 'text');
        const byIp = new Map();
        const text = String(raw || '').trim();
        if (text.startsWith('{')) {
          // 3.x helper returned one JSON object keyed by address.
          const object = JSON.parse(text);
          Object.keys(object).forEach(ip => byIp.set(ip, object[ip]));
        }
        else {
          text.split('\n').filter(Boolean).forEach(line => {
            try {
              const row = JSON.parse(line);
              if (row && row.ip) byIp.set(String(row.ip), row);
            }
            catch (e) {}
          });
        }
        chunk.forEach(ip => {
          const row = byIp.get(ip);
          this.rememberGeo(ip, row && !row.error ? row : {});
        });
      }
      catch (e) {
        chunk.forEach(ip => this.rememberGeo(ip, {}));
      }
    }
  },

  readRouterRing: async function() {
    if (!watchConfigIsFresh(this.routerHistorySyncedAt, Date.now(), 20000)) {
      try {
        const raw = await fs.exec_direct('/usr/sbin/log-viewer-history', ['status'], 'text');
        this.routerHistoryStatus = parseWatchConfig(raw);
      }
      catch (e) {
        this.routerHistoryStatus = null;
      }
      this.routerHistorySyncedAt = Date.now();
    }
    try { return await fs.read('/tmp/log-viewer/events.ring'); }
    catch (e) { return ''; }
  },

  clearRouterHistory: async function() {
    const status = this.routerHistoryStatus;
    if (status && status.persist_enabled === 1) {
      ui.showModal(_('Clear router history?'), [
        E('p', {}, _('This deletes the router memory ring and every persistent history file in ') + (status.persist_directory || _('the configured directory')) + '.'),
        E('div', {class: 'fw-modal-actions'}, [
          E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Cancel')),
          E('button', {class: 'cbi-button cbi-button-negative important', type: 'button', click: () => {
            this.clearRouterHistoryNow().catch(e => ui.addNotification(null, E('p', e.message), 'error'));
          }}, _('Clear everything'))
        ])
      ], 'fw-modal');
      return;
    }
    await this.clearRouterHistoryNow();
  },

  clearRouterHistoryNow: async function() {
    const raw = await fs.exec_direct('/usr/sbin/log-viewer-history', ['clear'], 'text');
    const cleared = parseWatchConfig(raw);
    if (!cleared) throw new Error(_('The router did not confirm that history was cleared.'));
    this.routerHistoryStatus = cleared;
    this.routerHistorySyncedAt = Date.now();
    this.lastRingData = null;
    if (this.routerHistoryText)
      this.routerHistoryText.textContent = _('Router history cleared.');
    ui.hideModal();
    this.refreshEvents().catch(() => {});
  },

  refreshEvents: async function() {
    const generation = ++this.refreshGeneration;
    await this.loadPolicyRules();
    await this.loadWatchConfig(false);
    this.loadTrafficContext();
    const raw = await this.getLogData();
    if (generation !== this.refreshGeneration) return;
    const text = raw || '';
    this.sourceLineCount = text ? text.split('\n').filter(Boolean).length : 0;
    this.lastCollectedAt = Date.now();
    const changed = text !== this.lastRawData;
    if (changed) {
      this.lastRawData = text;
      const lines = text.trim() ? text.trim().split('\n') : [];
      this.liveEvents = lines.map((line, i) => parseLine(line, i + 1, this.watchConfig && this.watchConfig.router_offset))
        .filter(Boolean).map(e => this.applyTrafficContext(this.applyPolicy(e))).slice(-MAX_LINES).reverse();
      const previousKeys = this.liveEventKeys || new Set();
      this.newLiveEvents = this.liveEvents.filter(event => !previousKeys.has(event.rawLine));
      this.liveEventKeys = new Set(this.liveEvents.map(event => event.rawLine));
      this.historyNeedsReload = true;
    }
    this.liveEvents.forEach(event => this.applyTrafficContext(event));
    const ringText = await this.readRouterRing();
    if (generation !== this.refreshGeneration) return;
    const ringChanged = ringText !== this.lastRingData;
    this.lastRingData = ringText;
    const ringOffset = this.watchConfig && this.watchConfig.router_offset;
    const ringEvents = String(ringText || '').split('\n').filter(Boolean)
      .map((line, index) => parseLine(line, index + 1, ringOffset))
      .filter(Boolean)
      .map(event => this.applyTrafficContext(this.applyPolicy(event)));
    if (this.historyRetention !== 'off' && (changed || this.historyNeedsReload)) {
      try {
        const historyDelta = changed ? this.newLiveEvents : (this.historySeedPending ? this.liveEvents : []);
        await this.storeHistory(historyDelta);
        this.historySeedPending = false;
        if (!this.historyCache || this.historyNeedsReload) {
          const historical = await this.loadHistory();
          this.historyCache = new Map(historical.map(event => [event.rawLine, event]));
        }
        else if (changed) {
          this.newLiveEvents.forEach(event => this.historyCache.set(event.rawLine, event));
        }
        const cutoff = this.routerNowMs() - Number(this.historyRetention) * 86400000;
        const historical = [...this.historyCache.values()]
          .filter(event => event.timestampMs >= cutoff)
          .sort((a, b) => (b.timestampMs || 0) - (a.timestampMs || 0))
          .slice(0, 10000);
        this.historyCache = new Map(historical.map(event => [event.rawLine, event]));
        const merged = new Map();
        historical.concat(this.liveEvents).forEach((event, index) => {
          event.id = index + 1;
          merged.set(event.rawLine, event);
        });
        this.events = [...merged.values()].sort((a, b) => (b.timestampMs || 0) - (a.timestampMs || 0)).slice(0, 10000);
        this.historyStatusText.textContent = _('Browser-local history: ') + this.historyCache.size + _(' stored events · max 10,000');
        this.historyNeedsReload = false;
      }
      catch (error) {
        this.events = this.liveEvents;
        this.historyStatusText.textContent = _('Browser-local history unavailable: ') + (error.message || error);
      }
    }
    else this.events = this.liveEvents;
    if (ringEvents.length) {
      const merged = new Map();
      ringEvents.concat(this.events).forEach((event, index) => {
        if (!event || !event.rawLine) return;
        event.id = index + 1;
        merged.set(event.rawLine, event);
      });
      this.events = [...merged.values()].sort((a, b) => (b.timestampMs || 0) - (a.timestampMs || 0)).slice(0, 10000);
    }
    if (this.historyRetention === 'off')
      this.historyStatusText.textContent = _('Browser history is off. Shown events are the live log plus router memory.');
    if (this.routerHistoryText) {
      const status = this.routerHistoryStatus;
      const count = status && status.count != null ? status.count : '—';
      const cap = status && status.cap ? status.cap : 500;
      const disk = status && status.persist_enabled === 1
        ? _(' · disk history on, ') + (status.persist_files || 0) + _(' files, ') + (status.persist_kb || 0) + ' KB'
        : _(' · disk history off');
      this.routerHistoryText.textContent = _('Router memory: ') + count + _(' of ') + cap + _(' firewall lines · cleared on reboot') + disk;
    }
    this.statusText.textContent = this.paused
      ? _('Auto-refresh paused · manually refreshed at ') + (new Date()).toLocaleTimeString()
      : _('Live · updated ') + (new Date()).toLocaleTimeString();
    this.logStatus.textContent = _('Read ') + this.sourceLineCount + _(' of up to ') + this.logReadLimit +
      _(' most recent source lines · source limit · collected ') + new Date(this.lastCollectedAt).toLocaleString();
    this.renderWatchStatus();
    if (changed || ringChanged) {
      this.renderRows();
      this.renderInsightsPanel();
      // Draw the log immediately. GeoIP is checked before starting lookups so a missing database
      // does not spawn a failed mmdblookup process for every address on every refresh.
    }
    if (!this.geoStatusCheckedAt || Date.now() - this.geoStatusCheckedAt > 5 * 60 * 1000) {
      this.geoStatusCheckedAt = Date.now();
      this.loadGeoStatus().then(() => {
        if (generation !== this.refreshGeneration) return;
        this.renderGeoStatus();
        if ((changed || ringChanged) && this.geoStatus && this.geoStatus.available) this.enrichAndRender();
      });
    }
    else if ((changed || ringChanged) && this.geoStatus && this.geoStatus.available) this.enrichAndRender();
  },

  enrichAndRender: function() {
    if (!this.tbody || !this.tbody.isConnected) return;
    const generation = this.refreshGeneration;
    this.enrich(this.events.slice(0, 60)).then(() => {
      if (generation !== this.refreshGeneration || !this.tbody || !this.tbody.isConnected) return;
      this.renderRows();
      this.renderInsightsPanel();
    });
  },

  getWindowedEvents: function() {
    let events = this.getTimeFilteredEvents();
    if (this.timelineRange)
      events = events.filter(event => event.timestampMs >= this.timelineRange.start && event.timestampMs < this.timelineRange.end);
    return events;
  },

  getTimeFilteredEvents: function() {
    const windowMs = this.getTimeWindowMs();
    const now = this.routerNowMs();
    return this.events.filter(e => {
      if (!windowMs || !e.timestampMs) return true;
      const age = now - e.timestampMs;
      return age >= -60000 && age <= windowMs;
    });
  },

  getMatchingEvents: function(windowed) {
    const query = parseQuery(this.search.value || '');
    const now = this.routerNowMs();
    return (windowed || this.getWindowedEvents()).filter(e => {
      const geo = this.geoCache[e.source] || {};
      const searchable = [
        e.timestamp, e.kind, e.source, e.destination, e.dport, e.service,
        e.protocol, e.prefix, e.marker, e.policyLabel, e.policyNote,
        geo.country_name, geo.country_code, geo.asn_organization
      ].join(' ').toLowerCase();
      const kindMatches = this.kindFilter === 'all' ||
        (this.kindFilter === 'known'
          ? e.kind !== 'Other' && e.kind !== 'Observed'
          : e.kind.toLowerCase() === this.kindFilter);
      const textMatches = query.words.every(word => searchable.includes(word));
      const queryMatches =
        (query.port == null || Number(e.dport) === query.port) &&
        (!query.country || String(geo.country_code || '').toUpperCase() === query.country) &&
        (!query.asn || String(geo.asn_organization || '').toLowerCase().includes(query.asn)) &&
        (!query.proto || e.protocol.toLowerCase() === query.proto) &&
        (!query.verdict || e.kind.toLowerCase() === query.verdict) &&
        (!query.source || e.source === query.source) &&
        (!query.afterMs || (e.timestampMs && now - e.timestampMs <= query.afterMs));
      return kindMatches && textMatches && queryMatches &&
        (this.protoFilter === 'all' || e.protocol.toLowerCase() === this.protoFilter) &&
        (!this.sourceFilter || e.source === this.sourceFilter) &&
        (!this.countryFilter || String(geo.country_code || '').toUpperCase() === this.countryFilter) &&
        (!this.asnFilter || String(geo.asn_organization || '') === this.asnFilter) &&
        (this.portFilter == null || Number(e.dport) === Number(this.portFilter));
    });
  },

  sortEvents: function(events) {
    const sorted = events.slice();
    const ascending = this.sortBy.endsWith('-asc');
    const direction = ascending ? 1 : -1;
    const text = value => String(value || '').toLowerCase();
    if (this.sortBy.startsWith('time')) {
      sorted.sort((a, b) => direction * ((a.timestampMs || 0) - (b.timestampMs || 0)));
    }
    else if (this.sortBy === 'source-asc') {
      sorted.sort((a, b) => text(a.source).localeCompare(text(b.source)) || ((b.timestampMs || 0) - (a.timestampMs || 0)));
    }
    else if (this.sortBy === 'country-asc') {
      const country = event => text((this.geoCache[event.source] || {}).country_name || '~');
      sorted.sort((a, b) => country(a).localeCompare(country(b)) || text(a.source).localeCompare(text(b.source)));
    }
    else if (this.sortBy === 'port-asc') {
      sorted.sort((a, b) => Number(a.dport || 0) - Number(b.dport || 0) || ((b.timestampMs || 0) - (a.timestampMs || 0)));
    }
    return sorted;
  },

  renderEventRow: function(e) {
    const geo = this.geoCache[e.source] || {};
    const countryCode = (geo.country_code || '').toUpperCase();
    const country = geo.country_name || _('GeoIP unavailable');
    const asn = geo.asn_organization || '';
    const kindClass = e.kind === 'Blocked' ? 'blocked' :
      (e.kind === 'Probe' ? 'probe' :
      (e.kind === 'Allowed' ? 'allowed' :
      (e.kind === 'Exposed' ? 'exposed' :
      (e.kind === 'Other' ? 'other' : 'observed'))));
    const policyText = e.policyLabel || e.marker || e.prefix;
    const verdictNote = e.verdictKnown === false ? ' · ' + _('verdict not observed') : '';
    const title = [e.marker || e.prefix, e.policyNote].filter(Boolean).join(' · ') + verdictNote;
    return '<tr class="tr fw-' + kindClass + '" data-event-id="' + esc(e.id) + '">' +
      '<td class="td fw-time" data-label="' + esc(_('Time')) + '">' + esc(e.timestamp) + '</td>' +
      '<td class="td fw-source" data-label="' + esc(_('Source')) + '"><span class="fw-flag" title="' + esc(country) + '">' + countryFlag(countryCode) + '</span> ' +
        '<button type="button" class="fw-source-link" data-source="' + esc(e.source) + '" title="' + esc(_('Open source details')) + '"><code>' + esc(e.source) + '</code></button>' +
        '<small>' + esc(country) + (asn ? ' · ' + esc(asn) : '') + '</small></td>' +
      '<td class="td" data-label="' + esc(_('Destination')) + '"><code>' + esc(e.destination || '—') + '</code></td>' +
      '<td class="td fw-port" data-label="' + esc(_('Port')) + '"><strong>' + esc(e.dport || '—') + '</strong><small>' + esc(e.service) + ' · ' + esc(e.protocol) + '</small></td>' +
      '<td class="td" data-label="' + esc(_('Verdict')) + '"><span class="fw-badge ' + kindClass + '" title="' + esc(title) + '">' + esc(e.kind) + '</span><small class="fw-event-policy">' + esc(policyText || '—') + '</small></td>' +
      '<td class="td fw-detail" data-label="' + esc(_('Packet')) + '">SPT ' + esc(e.sport || '—') + ' · ' + esc(e.flags || '—') +
        '<small>' + esc(e.iface || '—') + (e.ttl ? ' · TTL ' + esc(e.ttl) : '') + '</small></td>' +
      '<td class="td" data-label="' + esc(_('Actions')) + '"><button type="button" class="cbi-button fw-event-details" data-id="' + esc(e.id) + '">' + esc(_('Details')) + '</button>' +
        (this.showReputation ? '<a class="fw-reputation" href="https://www.abuseipdb.com/check/' + encodeURIComponent(e.source) +
          '" target="_blank" rel="noreferrer" title="' + esc(_('Opens AbuseIPDB and shares this source IP with that service')) + '">' + esc(_('AbuseIPDB ↗')) + '</a>' : '') + '</td></tr>';
  },

  renderInsightsPanel: function() {
    if (!this.insights) return;
    const events = this.getTimeFilteredEvents();
    const scoped = this.kindFilter === 'known'
      ? events.filter(event => event.kind !== 'Other' && event.kind !== 'Observed')
      : events;
    this.insights.innerHTML = this.renderInsights(scoped);
  },

  renderGeoStatus: function() {
    if (!this.geoStatusText) return;
    if (!this.geoStatus || !this.geoStatus.available) {
      this.geoStatusText.textContent = _('GeoIP unavailable · country and ASN details hidden');
      return;
    }
    const age = this.geoStatus.age_days == null ? _('age unknown') : this.geoStatus.age_days + _(' days old');
    this.geoStatusText.textContent = _('Local GeoIP databases · oldest ') + age +
      (this.geoStatus.stale ? _(' · update recommended') : '');
  },

  renderRows: function() {
    if (!this.tbody) return;
    const windowed = this.getWindowedEvents();
    const matching = this.sortEvents(this.getMatchingEvents(windowed));
    this.filteredEvents = matching;
    const events = matching.slice(0, this.maxEntries);
    this.eventById = new Map(events.map(event => [String(event.id), event]));
    let blocked = 0, allowed = 0, exposed = 0, probe = 0;
    matching.forEach(e => {
      if (e.kind === 'Blocked') blocked++;
      else if (e.kind === 'Allowed') allowed++;
      else if (e.kind === 'Exposed') exposed++;
      else if (e.kind === 'Probe') probe++;
    });
    this.stats.innerHTML = [
      ['MATCHING EVENTS', matching.length],
      ['BLOCKED · CONFIRMED', blocked],
      ['PROBES · UNVERIFIED', probe],
      ['EXPOSED SERVICE HITS', exposed],
      ['ALLOWED · EXPLICIT LOGS', allowed]
    ].map(function(item) {
      return '<div class="fw-stat"><span>' + item[0] + '</span><strong>' + item[1] + '</strong></div>';
    }).join('');

    this.tbody.innerHTML = events.map(event => this.renderEventRow(event)).join('') ||
      '<tr><td colspan="7" class="center">No matching firewall events in the selected window.</td></tr>';
    this.counter.textContent = _('Showing ') + events.length + _(' of ') + matching.length + _(' matching events · ') +
      windowed.length + _(' in selected window · ') + this.events.length + _(' loaded');
    if (this.insightClear) {
      const label = insightFilterText(this.sourceFilter, this.portFilter, this.timelineRange);
      this.insightClear.hidden = !label;
      this.insightClear.textContent = label ? (_('Clear ') + label) : '';
    }
    this.loadMoreButton.hidden = events.length >= matching.length;
    this.loadMoreButton.textContent = _('Show ') + PAGE_SIZE + _(' more events · ') + (matching.length - events.length) + _(' remaining');
    this.renderChips(windowed);
    this.saveUrlState();
  },

  renderChips: function(events) {
    if (!this.chips) return;
    const countries = new Map();
    const asns = new Map();
    const ports = new Map();
    const verdicts = new Map();
    events.forEach(event => {
      const geo = this.geoCache[event.source] || {};
      const code = String(geo.country_code || '').toUpperCase();
      if (/^[A-Z]{2}$/.test(code)) {
        if (!countries.has(code)) countries.set(code, {code, name: geo.country_name || code, count: 0});
        countries.get(code).count++;
      }
      const asn = String(geo.asn_organization || '');
      if (asn) {
        if (!asns.has(asn)) asns.set(asn, {name: asn, count: 0});
        asns.get(asn).count++;
      }
      if (event.dport) {
        const port = Number(event.dport);
        if (port > 0) {
          if (!ports.has(port)) ports.set(port, {port, service: event.service || '', count: 0});
          ports.get(port).count++;
        }
      }
      verdicts.set(event.kind, (verdicts.get(event.kind) || 0) + 1);
    });
    const top = (map, limit) => [...map.values()].sort((a, b) => b.count - a.count).slice(0, limit);
    const chip = (label, active, attrs) => E('button', Object.assign({
      type: 'button',
      class: 'fw-chip' + (active ? ' active' : '')
    }, attrs), label);
    const items = [];
    const knownCount = (verdicts.get('Blocked') || 0) + (verdicts.get('Exposed') || 0) + (verdicts.get('Allowed') || 0);
    if (knownCount) items.push(chip(_('Known ports') + ' ' + knownCount, this.kindFilter === 'known', {
      'data-chip': 'kind', 'data-value': 'known'
    }));
    ['Blocked', 'Probe', 'Other', 'Exposed', 'Allowed', 'Observed'].forEach(kind => {
      if ((kind === 'Other' || kind === 'Observed') && this.kindFilter === 'known') return;
      const count = verdicts.get(kind) || 0;
      if (count) items.push(chip(kind + ' ' + count, this.kindFilter === kind.toLowerCase(), {
        'data-chip': 'kind', 'data-value': kind.toLowerCase()
      }));
    });
    top(countries, 4).forEach(item => items.push(chip(item.code + ' ' + item.count, this.countryFilter === item.code, {
      'data-chip': 'country', 'data-value': item.code, title: item.name
    })));
    top(asns, 3).forEach(item => items.push(chip(item.name + ' ' + item.count, this.asnFilter === item.name, {
      'data-chip': 'asn', 'data-value': item.name
    })));
    top(ports, 4).forEach(item => items.push(chip(':' + item.port + ' ' + item.count, this.portFilter === item.port, {
      'data-chip': 'port', 'data-value': String(item.port), title: item.service
    })));
    if (this.kindFilter !== 'all' || this.countryFilter || this.asnFilter || this.portFilter != null || this.sourceFilter)
      items.push(chip(_('Clear filters'), false, {'data-chip': 'clear'}));
    this.chips.replaceChildren(...items);
    this.chips.hidden = !items.length;
  },

  render: function() {
    this.loadPreferences();
    this.loadUrlState();
    if (!document.getElementById('reffix-firewall-log-style')) {
      document.head.appendChild(E('link', {
        id: 'reffix-firewall-log-style',
        rel: 'stylesheet',
        type: 'text/css',
        href: L.resource('log-viewer/firewall.css')
      }));
    }

    this.stats = E('div', {class: 'fw-stats'});
    this.search = E('input', {class: 'cbi-input-text', type: 'search', value: this.initialQuery || '', placeholder: _('Search, or try port:22 country:CN verdict:blocked'), 'aria-label': _('Search firewall events')});
    this.kind = E('select', {class: 'cbi-input-select', 'aria-label': _('Filter by verdict')}, [
      E('option', {value: 'known'}, _('Known ports only')),
      E('option', {value: 'all'}, _('All verdict types')),
      E('option', {value: 'blocked'}, _('Blocked · confirmed drop')),
      E('option', {value: 'probe'}, _('Probes · verdict unverified')),
      E('option', {value: 'other'}, _('Other ports')),
      E('option', {value: 'exposed'}, _('Exposed service hits')),
      E('option', {value: 'observed'}, _('Other interface / unclassified')),
      E('option', {value: 'allowed'}, _('Allowed · explicit logs only'))
    ]);
    this.kind.value = this.kindFilter;
    this.proto = E('select', {class: 'cbi-input-select', 'aria-label': _('Filter by protocol')}, [
      E('option', {value: 'all'}, _('All protocols')),
      E('option', {value: 'tcp'}, 'TCP'),
      E('option', {value: 'udp'}, 'UDP'),
      E('option', {value: 'icmp'}, 'ICMP')
    ]);
    this.proto.value = this.protoFilter;
    this.window = E('select', {class: 'cbi-input-select', title: _('Filter events by log timestamp'), 'aria-label': _('Filter by time window')}, [
      E('option', {value: 'all'}, _('All loaded')),
      E('option', {value: '5m'}, _('Last 5 minutes')),
      E('option', {value: '15m'}, _('Last 15 minutes')),
      E('option', {value: '1h'}, _('Last hour')),
      E('option', {value: '6h'}, _('Last 6 hours')),
      E('option', {value: '24h'}, _('Last 24 hours'))
    ]);
    this.window.value = this.timeFilter;
    this.presets = E('select', {class: 'cbi-input-select', title: _('Apply a filter you saved in this browser'), 'aria-label': _('Saved filter presets')});
    this.sort = E('select', {class: 'cbi-input-select', title: _('Sort the event table'), 'aria-label': _('Sort events')}, [
      E('option', {value: 'time-desc'}, _('Newest first')),
      E('option', {value: 'time-asc'}, _('Oldest first')),
      E('option', {value: 'source-asc'}, _('Source A–Z')),
      E('option', {value: 'country-asc'}, _('Country A–Z')),
      E('option', {value: 'port-asc'}, _('Destination port'))
    ]);
    this.chips = E('div', {class: 'fw-chips', 'aria-label': _('Quick filters')});
    this.sort.value = this.sortBy;
    this.renderPresetOptions();
    this.counter = E('span', {class: 'right'});
    this.statusText = E('span', {class: 'fw-muted'});
    this.logStatus = E('span', {class: 'fw-muted'});
    this.geoStatusText = E('span', {class: 'fw-muted'});
    this.watchStatusText = E('span', {class: 'fw-muted'});
    this.historyStatusText = E('span', {class: 'fw-muted'});
    this.historyRetentionSelect = E('select', {class: 'cbi-input-select', 'aria-label': _('How long this browser keeps events')}, [
      E('option', {value: 'off'}, _('Do not keep browser history')),
      E('option', {value: '1'}, _('Keep 24 hours in this browser')),
      E('option', {value: '7'}, _('Keep 7 days in this browser')),
      E('option', {value: '30'}, _('Keep 30 days in this browser'))
    ]);
    this.historyRetentionSelect.value = this.historyRetention;
    this.reputationCheckbox = E('input', {type: 'checkbox', change: ev => {
        this.showReputation = ev.target.checked;
        try { localStorage.setItem('reffix-log-viewer.external-reputation', String(this.showReputation)); } catch (e) {}
        this.renderRows();
      }});
    this.reputationCheckbox.checked = this.showReputation;
    this.reputationToggle = E('label', {class: 'fw-privacy'}, [
      this.reputationCheckbox,
      E('span', {}, _('Show AbuseIPDB links (opening one shares its source IP with that service)'))
    ]);
    this.loadMoreButton = E('button', {class: 'cbi-button fw-load-more', hidden: true, click: () => {
      this.maxEntries += PAGE_SIZE;
      this.renderRows();
    }}, _('Show ') + PAGE_SIZE + _(' more events'));
    this.pauseButton = E('button', {class: 'cbi-button fw-pause-button', click: () => {
      this.paused = !this.paused;
      this.pauseButton.textContent = this.paused ? _('Resume live') : _('Pause live');
      this.statusText.textContent = this.paused ? _('Auto-refresh paused') : _('Auto-refresh every 15s');
    }}, _('Pause live'));
    this.tbody = E('tbody');
    this.insights = E('div', {class: 'fw-insights'});
    this.insightsDisclosure = E('details', {class: 'fw-insights-disclosure'}, [
      E('summary', {}, _('Insights · sources, ports, ASNs and scan patterns')),
      this.insights
    ]);
    try { this.insightsDisclosure.open = localStorage.getItem('reffix-log-viewer.insights-open') === 'true'; } catch (e) {}

    const table = E('table', {class: 'table fw-table'}, [
      E('thead', {}, E('tr', {class: 'tr table-titles'},
        ['Time', 'Source / GeoIP', 'Destination', 'Port / Protocol', 'Verdict', 'Packet', 'Details']
          .map(t => E('th', {class: 'th'}, _(t))))),
      this.tbody
    ]);

    this.deletePresetButton = E('button', {class: 'cbi-button', disabled: !this.presets.value, click: () => this.removeFilterPreset()}, _('Delete saved filter'));
    this.insightClear = E('button', {class: 'cbi-button fw-insight-clear', hidden: true, click: () => {
      this.sourceFilter = '';
      this.portFilter = null;
      this.countryFilter = '';
      this.asnFilter = '';
      this.timelineRange = null;
      this.maxEntries = PAGE_SIZE;
      this.renderRows();
      this.renderInsightsPanel();
    }}, '');
    this.routerHistoryText = E('span', {class: 'fw-muted'});
    const settingsFile = E('input', {type: 'file', accept: 'application/json,.json', 'aria-label': _('Upload Firewall Log settings file'), change: ev => {
      const file = ev.target.files && ev.target.files[0];
      if (file) this.importSettings(file);
      ev.target.value = '';
    }});
    this.settingsFile = settingsFile;
    const advancedActions = E('details', {class: 'fw-more-actions'}, [
      E('summary', {}, _('Settings')),
      E('div', {class: 'fw-more-content'}, [
        E('section', {class: 'fw-settings-section fw-settings-watch'}, [
          E('h3', {}, _('WAN watch')),
          E('p', {class: 'fw-muted'}, _('Choose the WAN device and the known ports to log at the full per-address budget. Only ports on this list are logged by default; the optional other-port sample is off. Forwarded ports use a smaller budget. The watch never accepts or drops traffic.')),
          E('div', {class: 'fw-settings-actions'}, [
            E('button', {class: 'cbi-button cbi-button-action', type: 'button', click: () => this.openTrafficSettings()}, _('WAN watch settings'))
          ]),
          this.watchStatusText
        ]),
        E('section', {class: 'fw-settings-section fw-settings-labels'}, [
          E('h3', {}, _('Exposed service labels')),
          E('p', {class: 'fw-muted'}, _('A label renames a watch hit on that port from Blocked to Exposed. Labels stay in this browser. Copying them from port forwards does not change the firewall.')),
          E('div', {class: 'fw-settings-actions'}, [
            E('button', {class: 'cbi-button', click: () => this.importFirewallForwards()}, _('Copy labels from port forwards'))
          ])
        ]),
        E('section', {class: 'fw-settings-section fw-settings-history'}, [
          E('h3', {}, _('History')),
          E('p', {class: 'fw-muted'}, _('Browser history stays on this computer, up to 10,000 events. Router history is a memory ring of firewall lines on this router, cleared on reboot. Persistent disk history is opt-in and writes daily files to a mounted path.')),
          E('div', {class: 'fw-settings-actions'}, [
            E('label', {class: 'fw-history-control'}, [E('span', {}, _('This browser')), this.historyRetentionSelect]),
            E('button', {class: 'cbi-button cbi-button-action', type: 'button', click: () => this.openServerHistory()}, _('Browse router history')),
            E('button', {class: 'cbi-button', type: 'button', click: () => this.openHistorySettings()}, _('Persistent history settings')),
            E('button', {class: 'cbi-button', click: () => this.clearLocalHistory().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Clear browser history')),
            E('button', {class: 'cbi-button', click: () => this.clearRouterHistory().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Clear router history'))
          ]),
          this.historyStatusText,
          this.routerHistoryText
        ]),
        E('section', {class: 'fw-settings-section fw-settings-files'}, [
          E('h3', {}, _('Files')),
          E('p', {class: 'fw-muted'}, _('Export downloads the events currently in memory. A settings file carries labels, saved filters, and the WAN watch. Uploading a file that includes the watch writes it to this router.')),
          E('div', {class: 'fw-settings-actions'}, [
            E('button', {class: 'cbi-button', click: () => this.exportCSV(true)}, _('Export all loaded events')),
            E('button', {class: 'cbi-button', click: () => this.exportSettings()}, _('Download settings')),
            E('label', {class: 'fw-file-import'}, [E('span', {}, _('Upload settings')), settingsFile]),
            (this.geoUpdateButton = E('button', {class: 'cbi-button', click: () => {
              this.updateGeoDatabases().catch(e => ui.addNotification(null, E('p', e.message || e), 'error'));
            }}, _('Update GeoIP databases')))
          ]),
          this.logStatus,
          this.geoStatusText
        ]),
        E('section', {class: 'fw-settings-section fw-settings-privacy'}, [
          E('h3', {}, _('External lookup')),
          this.reputationToggle
        ])
      ])
    ]);

    const result = E('div', {class: 'fw-shell'}, [
      E('header', {class: 'fw-header'}, [
        E('img', {class: 'fw-logo', src: L.resource('log-viewer/logo.svg'), alt: '', width: 40, height: 40}),
        E('div', {}, [
          E('h1', {class: 'fw-title'}, _('Firewall Log')),
          E('p', {class: 'fw-description'}, _('Blocked WAN traffic as the firewall actually decided it, with local GeoIP enrichment. Probes are listed separately and marked unverified. Nothing leaves the router.'))
        ])
      ]),
      this.stats,
      E('div', {class: 'fw-toolbar fw-primary-toolbar'}, [
        this.search, this.kind, this.proto, this.window, this.sort,
        this.presets,
        E('button', {class: 'cbi-button', click: () => this.saveFilterPreset()}, _('Save filter')),
        this.deletePresetButton,
        E('button', {class: 'cbi-button cbi-button-action', click: () => this.refreshEvents().catch(e => ui.addNotification(null, E('p', e.message), 'error'))}, _('Refresh')),
        this.pauseButton,
        E('button', {class: 'cbi-button', click: () => this.copyViewLink()}, _('Copy view link')),
        E('button', {class: 'cbi-button cbi-button-action fw-export-button', click: () => this.exportCSV(false)}, _('Export filtered CSV'))
      ]),
      this.chips,
      E('div', {class: 'fw-results-meta'}, [this.counter, this.statusText, this.insightClear]),
      this.insightsDisclosure,
      E('div', {class: 'fw-tablewrap'}, table),
      this.loadMoreButton,
      advancedActions
    ]);

    this.tbody.addEventListener('click', ev => {
      const sourceLink = ev.target.closest('.fw-source-link');
      if (sourceLink) {
        this.openIpDrawer(sourceLink.getAttribute('data-source') || '');
        return;
      }
      const detailButton = ev.target.closest('.fw-event-details');
      if (detailButton) {
        const event = (this.eventById && this.eventById.get(detailButton.getAttribute('data-id'))) ||
          this.events.find(item => String(item.id) === detailButton.getAttribute('data-id'));
        if (event) this.showEventDetails(event);
      }
    });
    this.insights.addEventListener('click', ev => {
      const timelineButton = ev.target.closest('.fw-timeline-bin');
      if (timelineButton) {
        const start = Number(timelineButton.getAttribute('data-timeline-start'));
        this.timelineRange = {start, end: Number(timelineButton.getAttribute('data-timeline-end'))};
        this.maxEntries = PAGE_SIZE;
        this.renderRows();
        this.renderInsightsPanel();
        return;
      }
      if (ev.target.closest('.fw-clear-timeline')) {
        this.timelineRange = null;
        this.maxEntries = PAGE_SIZE;
        this.renderRows();
        this.renderInsightsPanel();
        return;
      }
      const portButton = ev.target.closest('.fw-insight-port');
      const sourceButton = ev.target.closest('.fw-insight-filter');
      if (portButton) {
        this.portFilter = Number(portButton.getAttribute('data-port-filter'));
        this.sourceFilter = '';
        this.countryFilter = '';
        this.asnFilter = '';
      }
      else if (sourceButton) {
        this.sourceFilter = sourceButton.getAttribute('data-source-filter') || '';
        this.portFilter = null;
        this.countryFilter = '';
        this.asnFilter = '';
      }
      else {
        const allPorts = ev.target.closest('.fw-show-all-ports');
        if (!allPorts) return;
        this.showAllPorts = !this.showAllPorts;
        this.renderInsightsPanel();
        return;
      }
      this.search.value = '';
      this.maxEntries = PAGE_SIZE;
      this.renderRows();
      this.insightsDisclosure.open = false;
    });
    this.insightsDisclosure.addEventListener('toggle', () => {
      try { localStorage.setItem('reffix-log-viewer.insights-open', String(this.insightsDisclosure.open)); } catch (e) {}
    });
    this.search.addEventListener('input', () => {
      clearTimeout(this.searchTimer);
      this.searchTimer = setTimeout(() => {
        this.maxEntries = PAGE_SIZE;
        this.renderRows();
      }, 120);
    });
    this.kind.addEventListener('change', () => { this.kindFilter = this.kind.value; this.maxEntries = PAGE_SIZE; this.renderRows(); });
    this.proto.addEventListener('change', () => { this.protoFilter = this.proto.value; this.maxEntries = PAGE_SIZE; this.renderRows(); });
    this.sort.addEventListener('change', () => { this.sortBy = this.sort.value; this.maxEntries = PAGE_SIZE; this.renderRows(); });
    this.chips.addEventListener('click', ev => {
      const chip = ev.target.closest('.fw-chip');
      if (!chip) return;
      const type = chip.getAttribute('data-chip');
      const value = chip.getAttribute('data-value') || '';
      if (type === 'kind')
        this.kindFilter = this.kindFilter === value ? 'all' : value;
      else if (type === 'country')
        this.countryFilter = this.countryFilter === value ? '' : value;
      else if (type === 'asn')
        this.asnFilter = this.asnFilter === value ? '' : value;
      else if (type === 'port')
        this.portFilter = this.portFilter === Number(value) ? null : Number(value);
      else if (type === 'clear') {
        this.kindFilter = 'known';
        this.countryFilter = '';
        this.asnFilter = '';
        this.portFilter = null;
        this.sourceFilter = '';
      }
      this.kind.value = this.kindFilter;
      this.maxEntries = PAGE_SIZE;
      this.renderRows();
    });
    this.window.addEventListener('change', () => {
      this.timeFilter = this.window.value;
      this.timelineRange = null;
      this.maxEntries = PAGE_SIZE;
      this.renderRows();
      this.renderInsightsPanel();
    });
    this.presets.addEventListener('change', () => {
      this.deletePresetButton.disabled = !this.presets.value;
      this.applyFilterPreset(this.presets.value);
    });
    this.historyRetentionSelect.addEventListener('change', () => {
      const wasDisabled = this.historyRetention === 'off';
      this.historyRetention = this.historyRetentionSelect.value;
      this.historyNeedsReload = true;
      this.historySeedPending = wasDisabled && this.historyRetention !== 'off';
      try { localStorage.setItem('reffix-log-viewer.history-days', this.historyRetention); }
      catch (e) { this.historyStatusText.textContent = _('Browser storage is unavailable.'); }
      this.refreshEvents().catch(e => { this.historyStatusText.textContent = _('History update failed: ') + (e.message || e); });
    });
    this.statusText.textContent = _('Auto-refresh every 15s');
    this.refreshEvents().catch(e => ui.addNotification(null, E('p', _('Unable to load firewall events: ') + e.message), 'error'));
    this.timer = setInterval(() => {
      if (!this.paused && document.visibilityState === 'visible')
        this.refreshEvents().catch(() => {});
    }, 15000);
    return result;
  },

  showEventDetails: function(event) {
    const geo = this.geoCache[event.source] || {};
    const rows = [
      ['Time', event.timestamp], ['Verdict', event.kind],
      ['Verdict source', event.verdictKnown === true
        ? _('Confirmed by the firewall')
        : _('Not observed (probe mode)')],
      ['Source IP', event.source],
      ['Country', geo.country_name || _('GeoIP unavailable')], ['ASN', geo.asn_organization || '—'],
      ['Destination IP', event.destination], ['Protocol', event.protocol],
      ['Source port', event.sport], ['Destination port', event.dport], ['Service', event.service],
      ['Interface', event.iface], ['TTL', event.ttl], ['Flags', event.flags],
      ['Log marker', event.marker], ['Event prefix', event.prefix],
      ['Policy label', event.policyLabel], ['Policy note', event.policyNote]
    ];
    const buttons = [E('button', {class: 'cbi-button cbi-button-action important', type: 'button', click: ui.hideModal}, _('Close'))];
    const destinationPort = Number(event.dport);
    if (event.kind === 'Other' && Number.isInteger(destinationPort) && destinationPort >= 1 && destinationPort <= 65535)
      buttons.unshift(E('button', {class: 'cbi-button', type: 'button', click: () => {
        this.addWatchPort(destinationPort).catch(e => ui.addNotification(null, E('p', e.message || e), 'error'));
      }}, _('Log this port at the full budget')));
    const metaRows = [];
    rows.forEach(row => metaRows.push(
      E('dt', {}, _(row[0])),
      E('dd', {}, String(row[1] == null || row[1] === '' ? '—' : row[1]))
    ));
    ui.showModal(_('Firewall event details'), [
      E('dl', {class: 'fw-event-meta'}, metaRows),
      E('h3', {}, _('Original log line')),
      E('pre', {class: 'fw-raw-log'}, event.rawLine || ''),
      E('div', {class: 'fw-modal-actions'}, buttons)
    ], 'fw-modal', 'fw-details-modal');
  },

  openIpDrawer: function(ip, sourceEvents) {
    ip = String(ip || '').trim();
    if (!ip) return;
    const events = (sourceEvents || this.events).filter(event => event.source === ip)
      .sort((a, b) => (b.timestampMs || 0) - (a.timestampMs || 0));
    const geo = this.geoCache[ip] || {};
    const portCounts = new Map();
    const verdicts = new Map();
    events.forEach(event => {
      const port = Number(event.dport);
      if (port > 0) portCounts.set(port, (portCounts.get(port) || 0) + 1);
      verdicts.set(event.kind, (verdicts.get(event.kind) || 0) + 1);
    });
    const first = events.length ? events[events.length - 1] : null;
    const last = events.length ? events[0] : null;
    const ptr = E('dd', {class: 'fw-drawer-ptr'}, _('Resolving…'));
    const kindClass = event => event.kind === 'Blocked' ? 'blocked' :
      (event.kind === 'Allowed' ? 'allowed' : (event.kind === 'Exposed' ? 'exposed' :
      (event.kind === 'Other' ? 'other' : 'observed')));
    const portButtons = [...portCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([port, count]) => E('button', {class: 'fw-chip', type: 'button', click: () => {
        this.addWatchPort(Number(port)).catch(e => ui.addNotification(null, E('p', e.message || e), 'error'));
      }}, ':' + port + ' · ' + count));
    const recent = events.slice(0, 12).map(event => E('button', {
      class: 'fw-drawer-event', type: 'button', click: () => this.showEventDetails(event)
    }, [
      E('span', {class: 'fw-drawer-event-time'}, event.timestamp),
      E('span', {}, ':' + (event.dport || '—') + ' · ' + event.protocol),
      E('span', {class: 'fw-badge ' + kindClass(event)}, event.kind)
    ]));
    const content = [
      E('div', {class: 'fw-drawer-summary'}, [
        E('div', {}, [E('strong', {}, String(events.length)), E('span', {}, _(' events in this view'))]),
        E('div', {}, [E('strong', {}, String(portCounts.size)), E('span', {}, _(' ports'))]),
        E('div', {}, [E('strong', {}, first ? first.timestamp : '—'), E('span', {}, _(' first seen'))]),
        E('div', {}, [E('strong', {}, last ? last.timestamp : '—'), E('span', {}, _(' last seen'))])
      ]),
      E('dl', {class: 'fw-event-meta fw-drawer-meta'}, [
        E('dt', {}, _('Country')), E('dd', {}, geo.country_name || _('GeoIP unavailable')),
        E('dt', {}, _('ASN')), E('dd', {}, geo.asn_organization || '—'),
        E('dt', {}, _('Reverse DNS')), ptr,
        E('dt', {}, _('Verdicts')), E('dd', {},
          [...verdicts.entries()].map(item => item[0] + ' ' + item[1]).join(' · ') || '—')
      ]),
      E('div', {class: 'fw-drawer-actions'}, [
        E('button', {class: 'cbi-button', type: 'button', click: () => {
          copyToClipboard(ip)
            .then(() => ui.addNotification(null, E('p', _('Source IP copied.')), 'info'))
            .catch(() => ui.addNotification(null, E('p', _('Could not copy the source IP.')), 'error'));
        }}, _('Copy IP')),
        E('button', {class: 'cbi-button', type: 'button', disabled: !last, click: () => {
          copyToClipboard(last ? last.rawLine : '')
            .then(() => ui.addNotification(null, E('p', _('Log line copied.')), 'info'))
            .catch(() => ui.addNotification(null, E('p', _('Could not copy the log line.')), 'error'));
        }}, _('Copy latest log line')),
        E('button', {class: 'cbi-button', type: 'button', click: () => {
          this.sourceFilter = ip;
          this.countryFilter = '';
          this.asnFilter = '';
          this.portFilter = null;
          this.maxEntries = PAGE_SIZE;
          ui.hideModal();
          this.renderRows();
          this.insightsDisclosure.open = false;
        }}, _('Filter live table to this IP'))
      ]),
      E('h5', {class: 'fw-section-heading'}, _('Ports and watch actions')),
      E('div', {class: 'fw-chips'}, portButtons.length ? portButtons : [E('span', {class: 'fw-muted'}, _('No ports in this view.'))]),
      E('h5', {class: 'fw-section-heading'}, _('Recent events')),
      E('div', {class: 'fw-drawer-events'}, recent.length ? recent : [E('p', {class: 'fw-muted'}, _('No events in the current loaded view.'))]),
      E('div', {class: 'fw-modal-actions'}, [
        E('button', {class: 'cbi-button', type: 'button', click: ui.hideModal}, _('Close'))
      ])
    ];
    ui.showModal(_('Source ') + ip, content, 'fw-modal', 'fw-drawer-modal');
    fs.exec_direct('/usr/sbin/log-viewer-ip', ['reverse', ip], 'text')
      .then(raw => {
        let data = {};
        try { data = JSON.parse(raw || '{}'); } catch (e) {}
        ptr.textContent = data.name || _('No PTR record');
      })
      .catch(() => { ptr.textContent = _('Reverse DNS unavailable'); });
  },

  exportCSV: function(allLoaded) {
    const rows = [['Time','Source IP','Country','ASN','Destination IP','Destination Port','Service','Protocol','Verdict','Log Marker','Policy Label','Policy Note','Source Port','Interface']];
    const events = allLoaded ? this.events : this.getMatchingEvents();
    events.forEach(e => {
      const geo = this.geoCache[e.source] || {};
      rows.push([e.timestamp,e.source,geo.country_name || '',geo.asn_organization || '',e.destination,e.dport,e.service,e.protocol,e.kind,e.marker || e.prefix,e.policyLabel || '',e.policyNote || '',e.sport,e.iface]);
    });
    const csv = rows.map(r => r.map(csvCell).join(',')).join('\r\n');
    downloadBlob(allLoaded ? 'firewall-log-all-loaded.csv' : 'firewall-log-filtered.csv',
      new Blob([csv], {type: 'text/csv;charset=utf-8'}));
  },

  remove: function() {
    if (this.timer) clearInterval(this.timer);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.refreshGeneration++;
    this.tbody = null;
    this.eventById = null;
    this.insights = null;
  }
});
