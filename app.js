(() => {
  'use strict';

  const ENTITY_TYPES = {
    Device: { color: '#38bdf8', glyph: 'D' },
    Account: { color: '#a78bfa', glyph: 'A' },
    IP: { color: '#fb923c', glyph: 'IP' },
    Process: { color: '#22d3ee', glyph: 'P' },
    File: { color: '#facc15', glyph: 'F' },
    Hash: { color: '#94a3b8', glyph: '#' },
    URL: { color: '#f97316', glyph: '↗' },
    Domain: { color: '#f59e0b', glyph: 'W' },
    Alert: { color: '#fb7185', glyph: '!' },
    Email: { color: '#34d399', glyph: '@' },
    CloudResource: { color: '#c084fc', glyph: 'C' },
    Event: { color: '#64748b', glyph: 'E' },
    Other: { color: '#94a3b8', glyph: '•' }
  };

  const RISK_COLORS = {
    unknown: '#64748b', informational: '#38bdf8', low: '#22c55e', medium: '#fbbf24',
    high: '#fb923c', malicious: '#fb7185', benign: '#34d399'
  };
  const RISK_RANK = { unknown: 0, informational: 1, benign: 1, low: 2, medium: 3, high: 4, malicious: 5 };

  const FIELD_RULES = [
    { keys: ['devicename','computer','computername','hostname','host','sourcehostname','destinationhostname'], type: 'Device', kind: 'DeviceName' },
    { keys: ['deviceid','azureaddeviceid','aaddeviceid'], type: 'Device', kind: 'DeviceId' },
    { keys: ['accountupn','userprincipalname','upn','initiatingprocessaccountupn'], type: 'Account', kind: 'AccountUPN' },
    { keys: ['accountdisplayname','userdisplayname','displayname'], type: 'Account', kind: 'AccountDisplayName' },
    { keys: ['accountid','accountobjectid','userid','userobjectid','sid','accountsid'], type: 'Account', kind: 'AccountId' },
    { keys: ['accountname','username','user','initiatingprocessaccountname','subjectusername','targetusername'], type: 'Account', kind: 'AccountName' },
    { keys: ['remoteip','destinationip','dstip','destinationaddress','ipaddress'], type: 'IP', kind: 'RemoteIP' },
    { keys: ['localip','sourceip','srcip','sourceaddress','clientip'], type: 'IP', kind: 'LocalIP' },
    { keys: ['initiatingprocessfilename','processname','image','parentprocessname','newprocessname'], type: 'Process', kind: 'ProcessName' },
    { keys: ['filename','targetfilename','folderpath'], type: 'File', kind: 'FileName' },
    { keys: ['sha256','initiatingprocesssha256'], type: 'Hash', kind: 'SHA256' },
    { keys: ['sha1','initiatingprocesssha1'], type: 'Hash', kind: 'SHA1' },
    { keys: ['md5','initiatingprocessmd5'], type: 'Hash', kind: 'MD5' },
    { keys: ['url','remoteurl','requesturl','clickurl'], type: 'URL', kind: 'URL' },
    { keys: ['domain','domainname','remotedomain','dnsquery'], type: 'Domain', kind: 'Domain' },
    { keys: ['alertid','systemalertid','incidentid','incidentnumber','title','alertname'], type: 'Alert', kind: 'Alert' },
    { keys: ['senderfromaddress','senderaddress','recipientemailaddress','recipientaddress','emailaddress'], type: 'Email', kind: 'EmailAddress' },
    { keys: ['resourceid','azureResourceId','cloudresource','serviceprincipalid','applicationid'], type: 'CloudResource', kind: 'ResourceId' }
  ];

  const state = {
    format: 'EntityGraph Investigation v2',
    metadata: { title: 'Untitled investigation', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), importedFiles: [] },
    nodes: new Map(), edges: new Map(), evidence: new Map(), resolutionMap: new Map(),
    selectedNodes: new Set(), selectedEdge: null, hiddenNodes: new Set(), activeTypes: new Set(),
    undoStack: [], highlightedPath: { nodes: new Set(), edges: new Set() },
    timeMin: null, timeMax: null, timeStart: null, timeEnd: null,
    transform: { x: 0, y: 0, k: 1 }, dirty: false
  };

  const $ = (id) => document.getElementById(id);
  const canvas = $('graphCanvas');
  const ctx = canvas.getContext('2d');
  const stage = $('graphStage');
  let dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  let pointer = { down: false, moved: false, startX: 0, startY: 0, tx: 0, ty: 0, nodeId: null, nodeX: 0, nodeY: 0 };
  let editNodeId = null;

  function esc(value) {
    return String(value ?? '').replace(/[&<>'"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
  }
  function normalize(value) { return String(value ?? '').trim().toLowerCase().replace(/\s+/g, ' '); }
  function normalizedKey(value) { return normalize(value).replace(/[^a-z0-9]/g, ''); }
  function cleanValue(value) {
    const v = String(value ?? '').trim();
    return /^(null|undefined|n\/a|na|-)?$/i.test(v) ? '' : v;
  }
  function unique(values) { return [...new Set(values.filter(v => v !== undefined && v !== null && v !== ''))]; }
  function deepClone(value) { return typeof structuredClone === 'function' ? structuredClone(value) : JSON.parse(JSON.stringify(value)); }
  function safeDate(value) {
    if (!value) return null;
    const n = Date.parse(value);
    return Number.isFinite(n) ? new Date(n).toISOString() : null;
  }
  function minDate(a, b) { if (!a) return b; if (!b) return a; return Date.parse(a) <= Date.parse(b) ? a : b; }
  function maxDate(a, b) { if (!a) return b; if (!b) return a; return Date.parse(a) >= Date.parse(b) ? a : b; }
  function riskFromRow(row) {
    const raw = row.Severity || row.severity || row.Risk || row.risk || row.ThreatLevel || 'Unknown';
    const key = normalize(raw);
    if (key.includes('malicious') || key.includes('critical')) return 'Malicious';
    if (key.includes('high')) return 'High';
    if (key.includes('medium') || key.includes('moderate')) return 'Medium';
    if (key.includes('low')) return 'Low';
    if (key.includes('benign')) return 'Benign';
    if (key.includes('info')) return 'Informational';
    return 'Unknown';
  }
  function higherRisk(a = 'Unknown', b = 'Unknown') {
    return (RISK_RANK[normalize(a)] || 0) >= (RISK_RANK[normalize(b)] || 0) ? a : b;
  }
  function mergeValue(a, b) {
    if (a === undefined || a === null || a === '') return deepClone(b);
    if (b === undefined || b === null || b === '') return deepClone(a);
    const values = unique([...(Array.isArray(a) ? a : [a]), ...(Array.isArray(b) ? b : [b])].map(v => typeof v === 'object' ? JSON.stringify(v) : v));
    const decoded = values.map(v => typeof v === 'string' && /^[\[{]/.test(v) ? (() => { try { return JSON.parse(v); } catch { return v; } })() : v);
    return decoded.length === 1 ? decoded[0] : decoded;
  }
  function setProperty(target, key, value) { if (cleanValue(value)) target[key] = mergeValue(target[key], cleanValue(value)); }
  function hashCode(text) { let h = 2166136261; for (let i=0;i<text.length;i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
  function idFor(type, kind, value) { return `${type.toLowerCase()}:${kind.toLowerCase()}:${normalize(value)}`; }
  function resolveId(id) {
    let current = id, guard = 0;
    while (state.resolutionMap.has(current) && state.resolutionMap.get(current) !== current && guard++ < 50) current = state.resolutionMap.get(current);
    return current;
  }
  function entityDef(type) { return ENTITY_TYPES[type] || ENTITY_TYPES.Other; }
  function displayDate(iso) { if (!iso) return '—'; return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); }
  function formatProperty(value) { return Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : String(value ?? ''); }
  function markDirty() { state.dirty = true; state.metadata.updatedAt = new Date().toISOString(); $('saveState').textContent = 'Unsaved changes'; }
  function toast(message, kind = '') {
    const el = document.createElement('div'); el.className = `toast ${kind}`; el.textContent = message; $('toastRegion').appendChild(el);
    setTimeout(() => el.remove(), 3400);
  }

  function parseCSV(text) {
    const rows = []; let row = [], field = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) {
        if (c === '"' && text[i+1] === '"') { field += '"'; i++; }
        else if (c === '"') quoted = false;
        else field += c;
      } else if (c === '"') quoted = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n') { row.push(field.replace(/\r$/, '')); if (row.some(v => v.trim())) rows.push(row); row = []; field = ''; }
      else field += c;
    }
    if (field.length || row.length) { row.push(field.replace(/\r$/, '')); if (row.some(v => v.trim())) rows.push(row); }
    if (!rows.length) return [];
    const headers = rows[0].map((h, i) => cleanValue(h) || `Column${i+1}`);
    return rows.slice(1).map(cells => Object.fromEntries(headers.map((h, i) => [h, cells[i] ?? ''])));
  }

  function findTimestamp(row) {
    const keys = Object.keys(row);
    const preferred = ['timestamp','timegenerated','eventtime','datetime','createddatetime','eventtimestamp'];
    const key = preferred.map(p => keys.find(k => normalizedKey(k) === p)).find(Boolean);
    return safeDate(key ? row[key] : null);
  }
  function findRule(header) {
    const k = normalizedKey(header);
    return FIELD_RULES.find(rule => rule.keys.some(x => normalizedKey(x) === k)) || null;
  }
  function relationshipName(row, fallback) {
    return cleanValue(row.Relationship || row.relationship || row.ActionType || row.EventType || row.OperationName) || fallback;
  }

  function addNode(candidate, evidenceId) {
    const originalId = idFor(candidate.type, candidate.kind, candidate.label);
    const canonicalId = resolveId(originalId);
    let node = state.nodes.get(canonicalId);
    if (!node) {
      node = {
        id: canonicalId, label: candidate.label, type: candidate.type, kind: candidate.kind,
        risk: candidate.risk || 'Unknown', status: 'Unreviewed', notes: '', properties: {}, aliases: [],
        firstSeen: candidate.timestamp, lastSeen: candidate.timestamp, sourceTables: [], evidenceIds: [],
        x: 0, y: 0, pinned: false
      };
      state.nodes.set(canonicalId, node);
    }
    node.firstSeen = minDate(node.firstSeen, candidate.timestamp);
    node.lastSeen = maxDate(node.lastSeen, candidate.timestamp);
    node.risk = higherRisk(node.risk, candidate.risk);
    node.sourceTables = unique([...node.sourceTables, candidate.source]);
    node.evidenceIds = unique([...node.evidenceIds, evidenceId]);
    setProperty(node.properties, candidate.kind, candidate.label);
    if (canonicalId !== originalId) {
      node.aliases = uniqueAliases([...node.aliases, { id: originalId, label: candidate.label, type: candidate.type, kind: candidate.kind }]);
    }
    return node;
  }
  function uniqueAliases(aliases) {
    const seen = new Set();
    return aliases.filter(a => { const k = `${a.id}|${a.label}|${a.kind}`; if (seen.has(k)) return false; seen.add(k); return true; });
  }
  function addEdge(sourceId, targetId, relationship, evidenceId, timestamp, sourceTable, properties = {}) {
    sourceId = resolveId(sourceId); targetId = resolveId(targetId);
    if (sourceId === targetId || !state.nodes.has(sourceId) || !state.nodes.has(targetId)) return null;
    const rel = String(relationship || 'RELATED_TO').trim().replace(/\s+/g, '_').toUpperCase();
    const id = `${sourceId}→${rel}→${targetId}`;
    let edge = state.edges.get(id);
    if (!edge) {
      edge = { id, source: sourceId, target: targetId, relationship: rel, count: 0, firstSeen: timestamp, lastSeen: timestamp, sourceTables: [], properties: {}, evidenceIds: [] };
      state.edges.set(id, edge);
    }
    edge.count += 1;
    edge.firstSeen = minDate(edge.firstSeen, timestamp);
    edge.lastSeen = maxDate(edge.lastSeen, timestamp);
    edge.sourceTables = unique([...edge.sourceTables, sourceTable]);
    edge.evidenceIds = unique([...edge.evidenceIds, evidenceId]);
    Object.entries(properties).forEach(([k,v]) => setProperty(edge.properties, k, v));
    return edge;
  }

  function importRows(rows, fileName) {
    if (!rows.length) throw new Error('No data rows were found.');
    const source = fileName.replace(/\.[^.]+$/, '');
    let recognized = 0;
    rows.forEach((row, index) => {
      const timestamp = findTimestamp(row);
      const evidenceId = `${fileName}:${index + 2}:${hashCode(JSON.stringify(row)).toString(16)}`;
      state.evidence.set(evidenceId, { id: evidenceId, sourceFile: fileName, rowNumber: index + 2, timestamp, record: row });
      const candidates = [];
      Object.entries(row).forEach(([header, raw]) => {
        const value = cleanValue(raw); const rule = findRule(header);
        if (!value || !rule) return;
        const node = addNode({ label: value, type: rule.type, kind: rule.kind, risk: riskFromRow(row), timestamp, source }, evidenceId);
        candidates.push({ node, rule, header }); recognized++;
      });
      buildRelationships(candidates, row, evidenceId, timestamp, source);
    });
    if (!recognized) throw new Error('No supported entity fields were detected in this file.');
    state.metadata.importedFiles.push({ name: fileName, rows: rows.length, importedAt: new Date().toISOString() });
    state.undoStack = [];
    return rows.length;
  }

  function buildRelationships(items, row, evidenceId, timestamp, source) {
    const byType = type => items.filter(i => i.node.type === type);
    const byKind = kind => items.filter(i => i.rule.kind === kind);
    const link = (from, to, rel, props = {}) => from.forEach(a => to.forEach(b => addEdge(a.node.id, b.node.id, rel, evidenceId, timestamp, source, props)));
    const ports = { RemotePort: row.RemotePort || row.DestinationPort || row.dstPort || '', Protocol: row.Protocol || row.TransportProtocol || '', ActionType: row.ActionType || '' };
    link(byKind('AccountUPN'), [...byKind('AccountDisplayName'), ...byKind('AccountId'), ...byKind('AccountName')], 'IDENTIFIED_AS');
    link(byKind('AccountDisplayName'), byKind('AccountId'), 'IDENTIFIED_AS');
    link(byKind('DeviceName'), byKind('DeviceId'), 'IDENTIFIED_AS');
    link(byType('Account'), byKind('DeviceName'), 'LOGGED_ON_TO');
    link(byKind('DeviceName'), byKind('RemoteIP'), relationshipName(row, 'CONNECTED_TO'), ports);
    link(byKind('DeviceName'), byKind('LocalIP'), 'HAS_ADDRESS');
    link(byType('Process'), byKind('DeviceName'), 'EXECUTED_ON');
    link(byType('Process'), byKind('RemoteIP'), relationshipName(row, 'CONNECTED_TO'), ports);
    link(byType('File'), byKind('DeviceName'), 'OBSERVED_ON');
    link(byType('Process'), byType('Hash'), 'HAS_HASH');
    link(byType('File'), byType('Hash'), 'HAS_HASH');
    link(byType('URL'), byType('Domain'), 'HOSTED_BY');
    link(byType('Alert'), items.filter(i => i.node.type !== 'Alert'), 'INVOLVES');
    link(byType('Email'), byType('URL'), 'CONTAINS_URL');
    const before = state.edges.size;
    if (items.length > 1 && !hasKnownPair(items)) {
      const [first, ...rest] = items;
      rest.forEach(item => addEdge(first.node.id, item.node.id, relationshipName(row, 'RELATED_TO'), evidenceId, timestamp, source));
    }
    return state.edges.size - before;
  }
  function hasKnownPair(items) {
    const types = new Set(items.map(i => i.node.type));
    return ['Device','Account','Process','File','Hash','Alert','URL','Email'].some(t => types.has(t)) || items.some(i => ['RemoteIP','LocalIP'].includes(i.rule.kind));
  }

  function graphPayload() {
    return {
      format: state.format,
      metadata: { ...state.metadata, title: $('caseTitle').value.trim() || 'Untitled investigation', updatedAt: new Date().toISOString() },
      nodes: [...state.nodes.values()].map(n => ({ ...n })),
      edges: [...state.edges.values()].map(e => ({ ...e })),
      evidence: [...state.evidence.values()],
      resolutionMap: Object.fromEntries(state.resolutionMap)
    };
  }
  function restorePayload(data) {
    if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.edges)) throw new Error('This is not a valid EntityGraph investigation file.');
    state.metadata = { createdAt: new Date().toISOString(), importedFiles: [], ...data.metadata };
    state.nodes = new Map(data.nodes.map(n => [n.id, { risk:'Unknown', status:'Unreviewed', notes:'', properties:{}, aliases:[], sourceTables:[], evidenceIds:[], pinned:false, ...n }]));
    state.edges = new Map(data.edges.map(e => [e.id, { count:1, sourceTables:[], properties:{}, evidenceIds:[], ...e }]));
    state.evidence = new Map((data.evidence || []).map(e => [e.id, e]));
    state.resolutionMap = new Map(Object.entries(data.resolutionMap || {}));
    state.selectedNodes.clear(); state.selectedEdge = null; state.hiddenNodes.clear(); state.undoStack = []; clearPath();
    $('caseTitle').value = state.metadata.title || 'Untitled investigation';
    markDirty(); refreshAll(true);
  }

  async function handleFiles(files) {
    const list = [...files]; if (!list.length) return;
    let importedRows = 0, importedFiles = 0;
    for (const file of list) {
      try {
        const text = await file.text();
        if (/\.json$/i.test(file.name)) {
          const data = JSON.parse(text); restorePayload(data); importedFiles++; toast(`Opened ${file.name}`);
        } else {
          importedRows += importRows(parseCSV(text), file.name); importedFiles++;
        }
      } catch (error) { toast(`${file.name}: ${error.message}`, 'error'); }
    }
    if (importedRows) {
      markDirty(); refreshAll(true); toast(`Imported ${importedRows.toLocaleString()} events from ${importedFiles} file${importedFiles === 1 ? '' : 's'}.`);
    }
    $('fileInput').value = '';
  }

  function snapshotForUndo() {
    state.undoStack.push(graphPayload());
    if (state.undoStack.length > 20) state.undoStack.shift();
  }
  function mergeSelected(canonicalId, label, type) {
    const selected = [...state.selectedNodes].filter(id => state.nodes.has(id));
    if (selected.length < 2 || !selected.includes(canonicalId)) return;
    snapshotForUndo();
    const canonical = state.nodes.get(canonicalId);
    const selectedSet = new Set(selected);
    const internal = [];
    selected.forEach(id => {
      const node = state.nodes.get(id); if (!node || id === canonicalId) return;
      canonical.aliases = uniqueAliases([...canonical.aliases, { id: node.id, label: node.label, type: node.type, kind: node.kind }, ...node.aliases]);
      Object.entries(node.properties || {}).forEach(([k,v]) => { canonical.properties[k] = mergeValue(canonical.properties[k], v); });
      canonical.firstSeen = minDate(canonical.firstSeen, node.firstSeen);
      canonical.lastSeen = maxDate(canonical.lastSeen, node.lastSeen);
      canonical.sourceTables = unique([...canonical.sourceTables, ...(node.sourceTables || [])]);
      canonical.evidenceIds = unique([...canonical.evidenceIds, ...(node.evidenceIds || [])]);
      canonical.risk = higherRisk(canonical.risk, node.risk);
      canonical.notes = unique([canonical.notes, node.notes]).join('\n\n');
      state.resolutionMap.set(node.id, canonicalId);
      (node.aliases || []).forEach(alias => state.resolutionMap.set(alias.id, canonicalId));
      state.nodes.delete(id); state.hiddenNodes.delete(id);
    });
    canonical.aliases = uniqueAliases([{ id: canonical.id, label: canonical.label, type: canonical.type, kind: canonical.kind }, ...canonical.aliases]);
    canonical.label = label.trim(); canonical.type = type;

    const rebuilt = new Map();
    [...state.edges.values()].forEach(edge => {
      const oldSource = edge.source, oldTarget = edge.target;
      const source = selectedSet.has(oldSource) ? canonicalId : resolveId(oldSource);
      const target = selectedSet.has(oldTarget) ? canonicalId : resolveId(oldTarget);
      if (source === target) {
        if (selectedSet.has(oldSource) && selectedSet.has(oldTarget)) internal.push(`${edge.relationship}: ${state.nodes.get(oldSource)?.label || oldSource} → ${state.nodes.get(oldTarget)?.label || oldTarget}`);
        return;
      }
      const id = `${source}→${edge.relationship}→${target}`;
      const current = rebuilt.get(id);
      if (!current) rebuilt.set(id, { ...edge, id, source, target, properties: deepClone(edge.properties || {}), evidenceIds: [...(edge.evidenceIds || [])], sourceTables: [...(edge.sourceTables || [])] });
      else {
        current.count += edge.count || 1;
        current.firstSeen = minDate(current.firstSeen, edge.firstSeen); current.lastSeen = maxDate(current.lastSeen, edge.lastSeen);
        current.evidenceIds = unique([...current.evidenceIds, ...(edge.evidenceIds || [])]);
        current.sourceTables = unique([...current.sourceTables, ...(edge.sourceTables || [])]);
        Object.entries(edge.properties || {}).forEach(([k,v]) => { current.properties[k] = mergeValue(current.properties[k], v); });
      }
    });
    state.edges = rebuilt;
    if (internal.length) canonical.properties['Retained internal relationships'] = mergeValue(canonical.properties['Retained internal relationships'], internal);
    state.selectedNodes = new Set([canonicalId]); state.selectedEdge = null; clearPath();
    markDirty(); refreshAll(true); toast(`Resolved ${selected.length} identities as ${canonical.label}.`);
  }
  function undoMerge() {
    const payload = state.undoStack.pop(); if (!payload) return;
    const remaining = state.undoStack;
    restorePayload(payload); state.undoStack = remaining;
    markDirty(); refreshAll(false); toast('Merge reversed.');
  }

  function nodeWithinTime(node) {
    if (state.timeMin === null || (node.firstSeen === null && node.lastSeen === null)) return true;
    const first = Date.parse(node.firstSeen || node.lastSeen), last = Date.parse(node.lastSeen || node.firstSeen);
    return last >= state.timeStart && first <= state.timeEnd;
  }
  function edgeWithinTime(edge) {
    if (state.timeMin === null || (!edge.firstSeen && !edge.lastSeen)) return true;
    const first = Date.parse(edge.firstSeen || edge.lastSeen), last = Date.parse(edge.lastSeen || edge.firstSeen);
    return last >= state.timeStart && first <= state.timeEnd;
  }
  function visibleNodes() {
    return [...state.nodes.values()].filter(n => !state.hiddenNodes.has(n.id) && (state.activeTypes.size === 0 || state.activeTypes.has(n.type)) && nodeWithinTime(n));
  }
  function visibleEdges(nodes = visibleNodes()) {
    const ids = new Set(nodes.map(n => n.id));
    return [...state.edges.values()].filter(e => ids.has(e.source) && ids.has(e.target) && edgeWithinTime(e));
  }

  function calculateTimeRange() {
    const times = [];
    state.nodes.forEach(n => { if (n.firstSeen) times.push(Date.parse(n.firstSeen)); if (n.lastSeen) times.push(Date.parse(n.lastSeen)); });
    const valid = times.filter(Number.isFinite);
    if (!valid.length) { state.timeMin = state.timeMax = state.timeStart = state.timeEnd = null; $('timelineSection').classList.add('hidden'); return; }
    state.timeMin = Math.min(...valid); state.timeMax = Math.max(...valid);
    if (state.timeStart === null || state.timeStart < state.timeMin) state.timeStart = state.timeMin;
    if (state.timeEnd === null || state.timeEnd > state.timeMax) state.timeEnd = state.timeMax;
    $('timelineSection').classList.remove('hidden'); updateTimelineLabels();
  }
  function updateTimelineLabels() {
    if (state.timeMin === null) return;
    $('timeStartLabel').textContent = new Date(state.timeStart).toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
    $('timeEndLabel').textContent = new Date(state.timeEnd).toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
  }

  function layoutGraph(mode = $('layoutSelect').value) {
    const nodes = visibleNodes(), edges = visibleEdges(nodes); if (!nodes.length) return;
    const width = Math.max(720, stage.clientWidth / Math.max(state.transform.k, .3));
    const height = Math.max(520, stage.clientHeight / Math.max(state.transform.k, .3));
    if (mode === 'grid' || (mode === 'force' && nodes.length > 350)) {
      const cols = Math.ceil(Math.sqrt(nodes.length * width / height)); const gapX = Math.max(105, width / Math.max(cols,1)); const rows = Math.ceil(nodes.length / cols); const gapY = Math.max(90, height / Math.max(rows,1));
      nodes.forEach((n,i) => { if (!n.pinned) { n.x = (i % cols) * gapX; n.y = Math.floor(i / cols) * gapY; } });
    } else if (mode === 'radial') {
      const degree = new Map(nodes.map(n => [n.id, 0])); edges.forEach(e => { degree.set(e.source, (degree.get(e.source)||0)+1); degree.set(e.target, (degree.get(e.target)||0)+1); });
      const sorted = [...nodes].sort((a,b) => degree.get(b.id)-degree.get(a.id)); const center = sorted[0];
      if (!center.pinned) { center.x = 0; center.y = 0; }
      sorted.slice(1).forEach((n,i) => { const ring = 1 + Math.floor(i / 12); const inRing = Math.min(12 * ring, sorted.length - 1); const angle = (i % (12*ring)) / inRing * Math.PI * 2; if (!n.pinned) { n.x = Math.cos(angle) * ring * 155; n.y = Math.sin(angle) * ring * 120; } });
    } else {
      nodes.forEach((n,i) => { if (!Number.isFinite(n.x) || (!n.x && !n.y)) { const a = (hashCode(n.id)%360) * Math.PI/180; const r = 100 + (hashCode(n.id+'r')%360); n.x = Math.cos(a)*r; n.y = Math.sin(a)*r; } });
      const nodeMap = new Map(nodes.map(n => [n.id,n]));
      for (let iter=0; iter<150; iter++) {
        const forces = new Map(nodes.map(n => [n.id,{x:0,y:0}]));
        if (nodes.length <= 350) {
          for (let i=0;i<nodes.length;i++) for (let j=i+1;j<nodes.length;j++) {
            const a=nodes[i],b=nodes[j], dx=a.x-b.x||.1, dy=a.y-b.y||.1, d2=Math.max(100,dx*dx+dy*dy), f=Math.min(12,12000/d2), d=Math.sqrt(d2);
            forces.get(a.id).x += dx/d*f; forces.get(a.id).y += dy/d*f; forces.get(b.id).x -= dx/d*f; forces.get(b.id).y -= dy/d*f;
          }
        }
        edges.forEach(e => { const a=nodeMap.get(e.source),b=nodeMap.get(e.target); if(!a||!b)return; const dx=b.x-a.x,dy=b.y-a.y,d=Math.max(1,Math.hypot(dx,dy)),f=(d-185)*.007; forces.get(a.id).x+=dx/d*f; forces.get(a.id).y+=dy/d*f; forces.get(b.id).x-=dx/d*f; forces.get(b.id).y-=dy/d*f; });
        nodes.forEach(n => { if(n.pinned)return; const f=forces.get(n.id); n.x += Math.max(-8,Math.min(8,f.x - n.x*.0008)); n.y += Math.max(-8,Math.min(8,f.y - n.y*.0008)); });
      }
    }
    fitGraph(); draw();
  }

  function resizeCanvas() {
    dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    const rect = stage.getBoundingClientRect(); canvas.width = Math.round(rect.width*dpr); canvas.height = Math.round(rect.height*dpr); canvas.style.width = `${rect.width}px`; canvas.style.height = `${rect.height}px`; draw();
  }
  function worldToScreen(x,y) { return { x: x*state.transform.k+state.transform.x, y: y*state.transform.k+state.transform.y }; }
  function screenToWorld(x,y) { return { x:(x-state.transform.x)/state.transform.k, y:(y-state.transform.y)/state.transform.k }; }
  function fitGraph() {
    const nodes=visibleNodes(); if(!nodes.length){state.transform={x:stage.clientWidth/2,y:stage.clientHeight/2,k:1};draw();return;}
    const xs=nodes.map(n=>n.x),ys=nodes.map(n=>n.y),minX=Math.min(...xs)-70,maxX=Math.max(...xs)+70,minY=Math.min(...ys)-70,maxY=Math.max(...ys)+90;
    const k=Math.max(.15,Math.min(1.6,Math.min((stage.clientWidth-70)/(maxX-minX||1),(stage.clientHeight-70)/(maxY-minY||1))));
    state.transform={k,x:(stage.clientWidth-(minX+maxX)*k)/2,y:(stage.clientHeight-(minY+maxY)*k)/2}; draw();
  }

  function draw() {
    const width=canvas.width/dpr,height=canvas.height/dpr; ctx.setTransform(dpr,0,0,dpr,0,0); ctx.clearRect(0,0,width,height); ctx.fillStyle='#080d19'; ctx.fillRect(0,0,width,height);
    const nodes=visibleNodes(), edges=visibleEdges(nodes), map=new Map(nodes.map(n=>[n.id,n]));
    edges.forEach(edge => {
      const a=map.get(edge.source),b=map.get(edge.target); if(!a||!b)return; const p1=worldToScreen(a.x,a.y),p2=worldToScreen(b.x,b.y); const dx=p2.x-p1.x,dy=p2.y-p1.y,d=Math.max(1,Math.hypot(dx,dy)),ux=dx/d,uy=dy/d,r=24*state.transform.k;
      const selected=state.selectedEdge===edge.id, highlighted=state.highlightedPath.edges.has(edge.id);
      ctx.strokeStyle=selected?'#f8fafc':highlighted?'#67e8f9':'#3a4967'; ctx.lineWidth=selected||highlighted?2.2:1; ctx.globalAlpha=selected||highlighted?1:.72;
      ctx.beginPath();ctx.moveTo(p1.x+ux*r,p1.y+uy*r);ctx.lineTo(p2.x-ux*r,p2.y-uy*r);ctx.stroke();
      const ex=p2.x-ux*(r+1),ey=p2.y-uy*(r+1);ctx.fillStyle=ctx.strokeStyle;ctx.beginPath();ctx.moveTo(ex,ey);ctx.lineTo(ex-ux*8-uy*4,ey-uy*8+ux*4);ctx.lineTo(ex-ux*8+uy*4,ey-uy*8-ux*4);ctx.closePath();ctx.fill();
      if (selected || highlighted || (state.transform.k>.78 && nodes.length<100)) {
        const text=`${edge.relationship.replaceAll('_',' ')}${edge.count>1?` · ${edge.count}`:''}`;ctx.font='9px Inter, system-ui';const tw=ctx.measureText(text).width;const mx=(p1.x+p2.x)/2,my=(p1.y+p2.y)/2;
        ctx.globalAlpha=.94;ctx.fillStyle='#0b1222';ctx.fillRect(mx-tw/2-4,my-7,tw+8,14);ctx.fillStyle=selected?'#fff':'#9fb0c8';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(text,mx,my);
      }
      ctx.globalAlpha=1;
    });
    nodes.forEach(node => {
      const p=worldToScreen(node.x,node.y),selected=state.selectedNodes.has(node.id),highlighted=state.highlightedPath.nodes.has(node.id),def=entityDef(node.type),radius=(selected?27:23)*Math.max(.72,Math.min(1.18,state.transform.k));
      ctx.save(); if(selected||highlighted){ctx.shadowColor=selected?'#67e8f9':'#a78bfa';ctx.shadowBlur=18;}
      ctx.fillStyle='#111a2e';ctx.strokeStyle=RISK_COLORS[normalize(node.risk)]||def.color;ctx.lineWidth=selected?3:2;ctx.beginPath();ctx.arc(p.x,p.y,radius,0,Math.PI*2);ctx.fill();ctx.stroke();ctx.restore();
      ctx.fillStyle=def.color;ctx.font=`${def.glyph.length>1?'bold 10px':'bold 14px'} Inter, system-ui`;ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(def.glyph,p.x,p.y);
      if(node.pinned){ctx.fillStyle='#fbbf24';ctx.font='10px sans-serif';ctx.fillText('◆',p.x+radius-2,p.y-radius+4);}
      const max=22,label=node.label.length>max?`${node.label.slice(0,max-1)}…`:node.label;ctx.font='11px Inter, system-ui';const tw=ctx.measureText(label).width;ctx.fillStyle='rgba(8,13,25,.91)';ctx.fillRect(p.x-tw/2-4,p.y+radius+7,tw+8,16);ctx.fillStyle='#e2e8f0';ctx.textBaseline='middle';ctx.fillText(label,p.x,p.y+radius+15);
      ctx.font='8px Inter, system-ui';ctx.fillStyle='#71809a';ctx.fillText(node.type,p.x,p.y+radius+27);
    });
  }

  function hitNode(x,y) {
    const nodes=visibleNodes(); for(let i=nodes.length-1;i>=0;i--){const n=nodes[i],p=worldToScreen(n.x,n.y);if(Math.hypot(x-p.x,y-p.y)<=30)return n;} return null;
  }
  function pointSegmentDistance(px,py,x1,y1,x2,y2){const dx=x2-x1,dy=y2-y1,l2=dx*dx+dy*dy;if(!l2)return Math.hypot(px-x1,py-y1);let t=((px-x1)*dx+(py-y1)*dy)/l2;t=Math.max(0,Math.min(1,t));return Math.hypot(px-(x1+t*dx),py-(y1+t*dy));}
  function hitEdge(x,y){const nodes=new Map(visibleNodes().map(n=>[n.id,n]));let best=null,dist=9;visibleEdges([...nodes.values()]).forEach(e=>{const a=nodes.get(e.source),b=nodes.get(e.target);if(!a||!b)return;const p1=worldToScreen(a.x,a.y),p2=worldToScreen(b.x,b.y),d=pointSegmentDistance(x,y,p1.x,p1.y,p2.x,p2.y);if(d<dist){dist=d;best=e;}});return best;}

  function selectNode(node, additive=false) {
    if(!additive) state.selectedNodes.clear();
    if(additive && state.selectedNodes.has(node.id)) state.selectedNodes.delete(node.id); else state.selectedNodes.add(node.id);
    state.selectedEdge=null; clearPath(false); updateSelectionUI(); draw();
  }
  function selectEdge(edge){state.selectedNodes.clear();state.selectedEdge=edge.id;clearPath(false);updateSelectionUI();draw();}
  function clearSelection(){state.selectedNodes.clear();state.selectedEdge=null;clearPath(false);updateSelectionUI();draw();}
  function clearPath(redraw=true){state.highlightedPath={nodes:new Set(),edges:new Set()};if(redraw)draw();}
  function focusNeighbors(nodeId){const keep=new Set([nodeId]);state.edges.forEach(e=>{if(e.source===nodeId)keep.add(e.target);if(e.target===nodeId)keep.add(e.source);});state.nodes.forEach((_,id)=>{if(!keep.has(id))state.hiddenNodes.add(id);});refreshAll(false);fitGraph();}

  function shortestPath() {
    const ids=[...state.selectedNodes]; if(ids.length!==2)return; const [start,end]=ids,queue=[start],prev=new Map([[start,null]]),prevEdge=new Map();
    while(queue.length){const id=queue.shift();if(id===end)break;state.edges.forEach(e=>{let next=null;if(e.source===id)next=e.target;else if(e.target===id)next=e.source;if(next&&!prev.has(next)){prev.set(next,id);prevEdge.set(next,e.id);queue.push(next);}});}
    if(!prev.has(end)){toast('No path connects the selected entities.','error');return;}
    const nodePath=new Set(),edgePath=new Set();let cur=end;while(cur!==null){nodePath.add(cur);if(prevEdge.has(cur))edgePath.add(prevEdge.get(cur));cur=prev.get(cur);}
    state.highlightedPath={nodes:nodePath,edges:edgePath};draw();toast(`Shortest path: ${Math.max(0,nodePath.size-1)} hop${nodePath.size===2?'':'s'}.`);
  }

  function updateSelectionUI() {
    const count=state.selectedNodes.size;$('mergeBtn').disabled=count<2;$('pathBtn').disabled=count!==2;$('undoBtn').disabled=!state.undoStack.length;
    $('selectionHelp').textContent=count>1?`${count} entities selected`:'Shift-click to select multiple entities';
    $('inspector').classList.toggle('has-selection',count>0||!!state.selectedEdge);
    renderInspector();
  }

  function renderInspector() {
    const content=$('inspectorContent'),empty=$('inspectorEmpty');
    if(state.selectedNodes.size===1){const node=state.nodes.get([...state.selectedNodes][0]);if(!node){clearSelection();return;}empty.classList.add('hidden');content.classList.remove('hidden');content.innerHTML=nodeInspectorHTML(node);wireNodeInspector(node);return;}
    if(state.selectedNodes.size>1){empty.classList.add('hidden');content.classList.remove('hidden');content.innerHTML=multiInspectorHTML();return;}
    if(state.selectedEdge){const edge=state.edges.get(state.selectedEdge);if(!edge){clearSelection();return;}empty.classList.add('hidden');content.classList.remove('hidden');content.innerHTML=edgeInspectorHTML(edge);return;}
    content.classList.add('hidden');empty.classList.remove('hidden');
  }
  function riskStyle(risk){return `color:${RISK_COLORS[normalize(risk)]||RISK_COLORS.unknown}`;}
  function nodeInspectorHTML(node) {
    const props=Object.entries(node.properties||{}).map(([k,v])=>`<div class="property-row"><dt>${esc(k)}</dt><dd>${esc(formatProperty(v))}</dd></div>`).join('')||'<div class="empty-small">No properties recorded.</div>';
    const aliases=(node.aliases||[]).map(a=>`<span class="chip" title="${esc(a.kind||a.type)}">${esc(a.label)}</span>`).join('')||'<span class="empty-small">No resolved aliases.</span>';
    const evidence=(node.evidenceIds||[]).slice(0,100).map(id=>evidenceHTML(state.evidence.get(id))).join('')||'<div class="empty-small">No source record attached.</div>';
    return `<div class="inspector-head"><div class="inspector-kicker"><span class="dot" style="background:${entityDef(node.type).color}"></span>${esc(node.type)}</div><h2>${esc(node.label)}</h2><div class="inspector-sub">${esc(node.kind||'Entity')} · ${(node.evidenceIds||[]).length} evidence record${(node.evidenceIds||[]).length===1?'':'s'}</div><div class="inspector-actions"><button class="btn compact" id="editSelectedBtn">Edit</button><button class="btn compact" id="focusSelectedBtn">Focus neighbors</button><button class="btn compact" id="pinSelectedBtn">${node.pinned?'Unpin':'Pin'}</button></div></div>
      <div class="inspector-block"><h3>Assessment</h3><div class="property-list"><div class="property-row"><dt>Risk</dt><dd><span class="risk-pill" style="${riskStyle(node.risk)}">${esc(node.risk)}</span></dd></div><div class="property-row"><dt>Status</dt><dd>${esc(node.status)}</dd></div><div class="property-row"><dt>First seen</dt><dd>${esc(displayDate(node.firstSeen))}</dd></div><div class="property-row"><dt>Last seen</dt><dd>${esc(displayDate(node.lastSeen))}</dd></div><div class="property-row"><dt>Sources</dt><dd>${esc((node.sourceTables||[]).join(', ')||'Manual')}</dd></div></div></div>
      <div class="inspector-block"><h3>Properties</h3><dl class="property-list">${props}</dl></div>
      <div class="inspector-block"><h3>Identifiers & aliases</h3><div class="chips"><span class="chip">Canonical: ${esc(node.label)}</span>${aliases}</div></div>
      <div class="inspector-block"><h3>Analyst notes</h3><textarea class="notes-box" id="nodeNotes">${esc(node.notes||'')}</textarea><button class="btn compact" id="saveNotesBtn" style="margin-top:7px">Save notes</button></div>
      <div class="inspector-block"><h3>Supporting evidence (${(node.evidenceIds||[]).length})</h3>${evidence}${(node.evidenceIds||[]).length>100?'<div class="empty-small">Showing the first 100 records.</div>':''}</div>`;
  }
  function multiInspectorHTML(){const nodes=[...state.selectedNodes].map(id=>state.nodes.get(id)).filter(Boolean);return `<div class="inspector-head"><div class="inspector-kicker">Selection</div><h2>${nodes.length} entities selected</h2><div class="inspector-sub">Resolve identifiers that represent the same real-world entity, or calculate the path between two entities.</div><div class="inspector-actions"><button class="btn compact" onclick="document.getElementById('mergeBtn').click()" ${nodes.length<2?'disabled':''}>Resolve same entity</button><button class="btn compact" onclick="document.getElementById('pathBtn').click()" ${nodes.length!==2?'disabled':''}>Shortest path</button></div></div><div class="inspector-block"><h3>Selected identities</h3><div class="chips">${nodes.map(n=>`<span class="chip">${esc(n.type)} · ${esc(n.label)}</span>`).join('')}</div></div>`;}
  function edgeInspectorHTML(edge){const source=state.nodes.get(edge.source),target=state.nodes.get(edge.target);const props=Object.entries(edge.properties||{}).map(([k,v])=>`<div class="property-row"><dt>${esc(k)}</dt><dd>${esc(formatProperty(v))}</dd></div>`).join('')||'<div class="empty-small">No additional properties.</div>';const evidence=(edge.evidenceIds||[]).slice(0,100).map(id=>evidenceHTML(state.evidence.get(id))).join('')||'<div class="empty-small">No source record attached.</div>';return `<div class="inspector-head"><div class="inspector-kicker">Relationship</div><h2>${esc(edge.relationship.replaceAll('_',' '))}</h2><div class="inspector-sub">${esc(source?.label||edge.source)} → ${esc(target?.label||edge.target)}</div></div><div class="inspector-block"><h3>Summary</h3><div class="property-list"><div class="property-row"><dt>Event count</dt><dd>${edge.count||1}</dd></div><div class="property-row"><dt>First seen</dt><dd>${esc(displayDate(edge.firstSeen))}</dd></div><div class="property-row"><dt>Last seen</dt><dd>${esc(displayDate(edge.lastSeen))}</dd></div><div class="property-row"><dt>Sources</dt><dd>${esc((edge.sourceTables||[]).join(', ')||'Manual')}</dd></div></div></div><div class="inspector-block"><h3>Properties</h3><div class="property-list">${props}</div></div><div class="inspector-block"><h3>Supporting evidence (${(edge.evidenceIds||[]).length})</h3>${evidence}</div>`;}
  function evidenceHTML(e){if(!e)return'';return `<details class="evidence-row"><summary>${esc(e.sourceFile||'Manual evidence')} · row ${esc(e.rowNumber||'—')}${e.timestamp?` · ${esc(displayDate(e.timestamp))}`:''}</summary><pre>${esc(JSON.stringify(e.record||e,null,2))}</pre></details>`;}
  function wireNodeInspector(node){$('editSelectedBtn').onclick=()=>openEntityDialog(node);$('focusSelectedBtn').onclick=()=>focusNeighbors(node.id);$('pinSelectedBtn').onclick=()=>{node.pinned=!node.pinned;markDirty();renderInspector();draw();};$('saveNotesBtn').onclick=()=>{node.notes=$('nodeNotes').value;markDirty();toast('Notes saved.');};}

  function refreshAll(doLayout=false) {
    calculateTimeRange(); updateFilters(); updateLegend(); updateCounts(); updateSelectionUI();
    $('emptyState').classList.toggle('hidden',state.nodes.size>0); $('importCount').textContent=`${state.metadata.importedFiles.length} file${state.metadata.importedFiles.length===1?'':'s'}`;
    if(doLayout && state.nodes.size) layoutGraph(); else draw();
  }
  function updateCounts(){const nodes=visibleNodes(),edges=visibleEdges(nodes);$('graphStatus').textContent=`${nodes.length.toLocaleString()} of ${state.nodes.size.toLocaleString()} entities · ${edges.length.toLocaleString()} of ${state.edges.size.toLocaleString()} relationships`;}
  function updateFilters(){const counts={};state.nodes.forEach(n=>counts[n.type]=(counts[n.type]||0)+1);if(!state.activeTypes.size)Object.keys(counts).forEach(t=>state.activeTypes.add(t));$('typeFilters').innerHTML=Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([type,count])=>`<label class="filter-item"><input type="checkbox" data-type="${esc(type)}" ${state.activeTypes.has(type)?'checked':''}><span class="dot" style="background:${entityDef(type).color}"></span><span>${esc(type)}</span><span class="count">${count}</span></label>`).join('')||'<div class="empty-small">Import data to build filters.</div>';$('typeFilters').querySelectorAll('input').forEach(input=>input.onchange=()=>{input.checked?state.activeTypes.add(input.dataset.type):state.activeTypes.delete(input.dataset.type);updateCounts();draw();});}
  function updateLegend(){const types=unique(visibleNodes().map(n=>n.type));$('legend').innerHTML=types.map(type=>`<span class="legend-item"><span class="dot" style="background:${entityDef(type).color}"></span>${esc(type)}</span>`).join('');}

  function searchNodes(query){const q=normalize(query);if(!q)return[];return [...state.nodes.values()].map(n=>{const hay=[n.label,n.type,n.kind,n.notes,JSON.stringify(n.properties),...(n.aliases||[]).flatMap(a=>[a.label,a.id,a.kind])].join(' ').toLowerCase();return {node:n,score:normalize(n.label).startsWith(q)?3:normalize(n.label).includes(q)?2:hay.includes(q)?1:0};}).filter(r=>r.score).sort((a,b)=>b.score-a.score||a.node.label.localeCompare(b.node.label)).slice(0,25).map(r=>r.node);}
  function renderSearch(){const q=$('searchInput').value,results=searchNodes(q),box=$('searchResults');if(!q){box.classList.add('hidden');box.innerHTML='';return;}box.classList.remove('hidden');box.innerHTML=results.length?results.map(n=>`<button class="search-result" data-id="${esc(n.id)}"><span class="dot" style="background:${entityDef(n.type).color}"></span><span><strong>${esc(n.label)}</strong><small>${esc(n.type)}${n.aliases?.length?` · ${n.aliases.length} aliases`:''}</small></span></button>`).join(''):'<div class="empty-small" style="padding:9px">No matching entities.</div>';box.querySelectorAll('button').forEach(btn=>btn.onclick=()=>{const n=state.nodes.get(btn.dataset.id);if(n){state.hiddenNodes.delete(n.id);selectNode(n);state.transform.x=stage.clientWidth/2-n.x*state.transform.k;state.transform.y=stage.clientHeight/2-n.y*state.transform.k;draw();box.classList.add('hidden');}});}

  function fillTypeSelect(select,selected='Other'){select.innerHTML=Object.keys(ENTITY_TYPES).map(t=>`<option ${t===selected?'selected':''}>${t}</option>`).join('');}
  function openEntityDialog(node=null){editNodeId=node?.id||null;$('entityDialogTitle').textContent=node?'Edit entity':'Add entity';$('entityLabel').value=node?.label||'';fillTypeSelect($('entityType'),node?.type||'Other');$('entityRisk').value=node?.risk||'Unknown';$('entityStatus').value=node?.status||'Unreviewed';$('entityNotes').value=node?.notes||'';$('entityDialog').showModal();setTimeout(()=>$('entityLabel').focus(),30);}
  function saveEntity(){const label=$('entityLabel').value.trim();if(!label)return;let node=editNodeId?state.nodes.get(editNodeId):null;if(node){node.label=label;node.type=$('entityType').value;node.risk=$('entityRisk').value;node.status=$('entityStatus').value;node.notes=$('entityNotes').value;}else{let id=`manual:${normalize(label)}:${Date.now().toString(36)}`;node={id,label,type:$('entityType').value,kind:'Manual',risk:$('entityRisk').value,status:$('entityStatus').value,notes:$('entityNotes').value,properties:{},aliases:[],firstSeen:null,lastSeen:null,sourceTables:['Manual'],evidenceIds:[],x:0,y:0,pinned:false};state.nodes.set(id,node);state.selectedNodes=new Set([id]);}markDirty();refreshAll(!editNodeId);toast(editNodeId?'Entity updated.':'Entity added.');}
  function fillRelationSelects(){const options=[...state.nodes.values()].sort((a,b)=>a.label.localeCompare(b.label)).map(n=>`<option value="${esc(n.id)}">${esc(n.label)} · ${esc(n.type)}</option>`).join('');$('relationSource').innerHTML=options;$('relationTarget').innerHTML=options;const selected=[...state.selectedNodes];if(selected[0])$('relationSource').value=selected[0];if(selected[1])$('relationTarget').value=selected[1];}
  function addManualRelation(){const source=$('relationSource').value,target=$('relationTarget').value;if(!source||!target||source===target){toast('Choose two different entities.','error');return;}const id=`manual:${Date.now().toString(36)}`,notes=$('relationNotes').value.trim();state.evidence.set(id,{id,sourceFile:'Manual evidence',rowNumber:'—',timestamp:new Date().toISOString(),record:{notes}});addEdge(source,target,$('relationName').value||'RELATED_TO',id,new Date().toISOString(),'Manual',{Notes:notes});markDirty();refreshAll(false);toast('Relationship added.');}
  function openMergeDialog(){const nodes=[...state.selectedNodes].map(id=>state.nodes.get(id)).filter(Boolean);if(nodes.length<2)return;const options=nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.label)} · ${esc(n.kind||n.type)}</option>`).join('');$('mergeCanonical').innerHTML=options;$('mergeLabel').value=nodes[0].label;fillTypeSelect($('mergeType'),nodes[0].type);$('mergeSummary').innerHTML=`<strong>${nodes.length} identities will be combined.</strong><br>${nodes.map(n=>esc(`${n.label} (${n.kind||n.type})`)).join('<br>')}`;$('mergeCanonical').onchange=()=>{const n=state.nodes.get($('mergeCanonical').value);if(n){$('mergeLabel').value=n.label;$('mergeType').value=n.type;}};$('mergeDialog').showModal();}

  function downloadBlob(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function safeFileName(ext){const base=($('caseTitle').value||'EntityGraph-investigation').replace(/[^a-z0-9_-]+/gi,'-').replace(/^-|-$/g,'')||'EntityGraph-investigation';return `${base}.${ext}`;}
  function exportJSON(){downloadBlob(new Blob([JSON.stringify(graphPayload(),null,2)],{type:'application/json'}),safeFileName('json'));toast('Investigation JSON exported.');}
  function csvCell(v){const s=String(v??'');return /[",\n]/.test(s)?`"${s.replaceAll('"','""')}"`:s;}
  function exportNodesCSV(){const headers=['Id','Label','Type','Kind','Risk','Status','FirstSeen','LastSeen','Sources','Aliases','Notes','Properties'];const rows=[headers,...[...state.nodes.values()].map(n=>[n.id,n.label,n.type,n.kind,n.risk,n.status,n.firstSeen,n.lastSeen,(n.sourceTables||[]).join(';'),(n.aliases||[]).map(a=>a.label).join(';'),n.notes,JSON.stringify(n.properties||{})])];downloadBlob(new Blob([rows.map(r=>r.map(csvCell).join(',')).join('\n')],{type:'text/csv'}),safeFileName('entities.csv'));}
  function exportEdgesCSV(){const headers=['Id','Source','Relationship','Target','Count','FirstSeen','LastSeen','Sources','Properties','EvidenceIds'];const rows=[headers,...[...state.edges.values()].map(e=>[e.id,e.source,e.relationship,e.target,e.count,e.firstSeen,e.lastSeen,(e.sourceTables||[]).join(';'),JSON.stringify(e.properties||{}),(e.evidenceIds||[]).join(';')])];downloadBlob(new Blob([rows.map(r=>r.map(csvCell).join(',')).join('\n')],{type:'text/csv'}),safeFileName('relationships.csv'));}
  function exportPNG(){draw();canvas.toBlob(blob=>{if(blob)downloadBlob(blob,safeFileName('png'));},'image/png');}

  function saveLocal(){try{localStorage.setItem('entitygraph-investigation',JSON.stringify(graphPayload()));state.dirty=false;$('saveState').textContent=`Saved ${new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}`;toast('Investigation saved in this browser.');}catch(e){toast(`Could not save locally: ${e.message}`,'error');}}
  function loadLocal(){const raw=localStorage.getItem('entitygraph-investigation');if(!raw){toast('No browser save was found.','error');return;}try{restorePayload(JSON.parse(raw));state.dirty=false;$('saveState').textContent='Loaded browser save';toast('Investigation opened.');}catch(e){toast(`Could not open save: ${e.message}`,'error');}}
  function clearInvestigation(){if(state.nodes.size&&!confirm('Clear this investigation? Export or save it first if you need to keep the data.'))return;state.nodes.clear();state.edges.clear();state.evidence.clear();state.resolutionMap.clear();state.selectedNodes.clear();state.selectedEdge=null;state.hiddenNodes.clear();state.activeTypes.clear();state.undoStack=[];state.metadata={title:'Untitled investigation',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),importedFiles:[]};$('caseTitle').value=state.metadata.title;state.timeMin=state.timeMax=state.timeStart=state.timeEnd=null;clearPath(false);markDirty();refreshAll(false);}

  function canvasPoint(event){const r=canvas.getBoundingClientRect();return{x:event.clientX-r.left,y:event.clientY-r.top};}
  function zoomAt(factor,x=stage.clientWidth/2,y=stage.clientHeight/2){const old=state.transform.k,next=Math.max(.12,Math.min(4,old*factor)),wx=(x-state.transform.x)/old,wy=(y-state.transform.y)/old;state.transform.k=next;state.transform.x=x-wx*next;state.transform.y=y-wy*next;draw();}

  function initEvents(){
    $('fileInput').addEventListener('change',e=>handleFiles(e.target.files));$('emptyImportBtn').onclick=()=>$('fileInput').click();
    ['dragenter','dragover'].forEach(name=>stage.addEventListener(name,e=>{e.preventDefault();$('importDrop').classList.add('drag');}));['dragleave','drop'].forEach(name=>stage.addEventListener(name,e=>{e.preventDefault();$('importDrop').classList.remove('drag');}));stage.addEventListener('drop',e=>handleFiles(e.dataTransfer.files));
    $('searchInput').addEventListener('input',renderSearch);$('clearSearch').onclick=()=>{$('searchInput').value='';renderSearch();};document.addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='TEXTAREA'){e.preventDefault();$('searchInput').focus();}if(e.key==='Escape')clearSelection();});
    $('fitBtn').onclick=fitGraph;$('centerBtn').onclick=fitGraph;$('relayoutBtn').onclick=()=>layoutGraph();$('layoutSelect').onchange=()=>layoutGraph();$('zoomInBtn').onclick=()=>zoomAt(1.2);$('zoomOutBtn').onclick=()=>zoomAt(1/1.2);
    $('showAllBtn').onclick=()=>{state.hiddenNodes.clear();state.activeTypes=new Set([...state.nodes.values()].map(n=>n.type));refreshAll(false);fitGraph();};$('hideBtn').onclick=()=>{state.selectedNodes.forEach(id=>state.hiddenNodes.add(id));clearSelection();refreshAll(false);};$('typesAllBtn').onclick=()=>{state.activeTypes=new Set([...state.nodes.values()].map(n=>n.type));refreshAll(false);};
    $('addEntityBtn').onclick=()=>openEntityDialog();$('addRelationBtn').onclick=()=>{if(state.nodes.size<2){toast('Add or import at least two entities first.','error');return;}fillRelationSelects();$('relationNotes').value='';$('relationDialog').showModal();};$('mergeBtn').onclick=openMergeDialog;$('pathBtn').onclick=shortestPath;$('undoBtn').onclick=undoMerge;
    $('entitySubmit').onclick=e=>{e.preventDefault();saveEntity();$('entityDialog').close();};$('relationSubmit').onclick=e=>{e.preventDefault();addManualRelation();$('relationDialog').close();};$('mergeSubmit').onclick=e=>{e.preventDefault();mergeSelected($('mergeCanonical').value,$('mergeLabel').value,$('mergeType').value);$('mergeDialog').close();};
    $('mergeCanonical').addEventListener('change',()=>{});
    $('exportMenuBtn').onclick=()=>{const menu=$('exportMenu'),hidden=menu.classList.toggle('hidden');$('exportMenuBtn').setAttribute('aria-expanded',String(!hidden));};$('exportMenu').querySelectorAll('button').forEach(b=>b.onclick=()=>{({json:exportJSON,png:exportPNG,nodes:exportNodesCSV,edges:exportEdgesCSV}[b.dataset.export])();$('exportMenu').classList.add('hidden');});
    $('saveLocalBtn').onclick=saveLocal;$('loadLocalBtn').onclick=loadLocal;$('clearBtn').onclick=clearInvestigation;$('caseTitle').addEventListener('input',()=>{state.metadata.title=$('caseTitle').value;markDirty();});
    $('resetTimeBtn').onclick=()=>{$('timeStart').value=0;$('timeEnd').value=100;state.timeStart=state.timeMin;state.timeEnd=state.timeMax;updateTimelineLabels();updateCounts();draw();};
    const timeChange=()=>{let a=+$('timeStart').value,b=+$('timeEnd').value;if(a>b-1){if(document.activeElement===$('timeStart'))a=b-1;else b=a+1;$('timeStart').value=Math.max(0,a);$('timeEnd').value=Math.min(100,b);}const span=state.timeMax-state.timeMin;state.timeStart=state.timeMin+span*(+$('timeStart').value/100);state.timeEnd=state.timeMin+span*(+$('timeEnd').value/100);updateTimelineLabels();updateCounts();draw();};$('timeStart').oninput=timeChange;$('timeEnd').oninput=timeChange;

    canvas.addEventListener('mousedown',e=>{const p=canvasPoint(e),node=hitNode(p.x,p.y);pointer={down:true,moved:false,startX:p.x,startY:p.y,tx:state.transform.x,ty:state.transform.y,nodeId:node?.id||null,nodeX:node?.x||0,nodeY:node?.y||0};canvas.classList.add('dragging');});
    window.addEventListener('mousemove',e=>{if(!pointer.down)return;const r=canvas.getBoundingClientRect(),p={x:e.clientX-r.left,y:e.clientY-r.top},dx=p.x-pointer.startX,dy=p.y-pointer.startY;if(Math.hypot(dx,dy)>3)pointer.moved=true;if(pointer.nodeId){const n=state.nodes.get(pointer.nodeId);if(n){n.x=pointer.nodeX+dx/state.transform.k;n.y=pointer.nodeY+dy/state.transform.k;}}else{state.transform.x=pointer.tx+dx;state.transform.y=pointer.ty+dy;}draw();});
    window.addEventListener('mouseup',e=>{if(!pointer.down)return;const r=canvas.getBoundingClientRect(),p={x:e.clientX-r.left,y:e.clientY-r.top};canvas.classList.remove('dragging');if(!pointer.moved){const node=hitNode(p.x,p.y),edge=!node&&hitEdge(p.x,p.y);if(node)selectNode(node,e.shiftKey);else if(edge)selectEdge(edge);else clearSelection();}else if(pointer.nodeId)markDirty();pointer.down=false;});
    canvas.addEventListener('dblclick',e=>{const p=canvasPoint(e),node=hitNode(p.x,p.y);if(node)focusNeighbors(node.id);});canvas.addEventListener('wheel',e=>{e.preventDefault();const p=canvasPoint(e);zoomAt(e.deltaY<0?1.12:1/1.12,p.x,p.y);},{passive:false});
    window.addEventListener('resize',resizeCanvas);window.addEventListener('beforeunload',e=>{if(state.dirty){e.preventDefault();e.returnValue='';}});
  }

  function init(){fillTypeSelect($('entityType'));fillTypeSelect($('mergeType'));initEvents();resizeCanvas();refreshAll(false);state.transform={x:stage.clientWidth/2,y:stage.clientHeight/2,k:1};draw();}
  window.EntityGraphCore={parseCSV,normalize,findRule,idFor};
  init();
})();
