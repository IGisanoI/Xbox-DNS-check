/* DNS Checker anonymous feedback receiver for a bound or standalone Apps Script project.
 * Script Properties: SHEET_ID and INGEST_TOKEN. Never put the token in this source file.
 *
 * Stage 3 (2026-11-23): read-only stats endpoint in doGet (token-protected).
 * Privacy hard rule: a combination with fewer than MIN_GROUP reports is never returned.
 */
const HEADERS = [
  'report_id', 'received_at', 'created_at', 'run_id', 'outcome', 'error_code',
  'applied', 'dns1', 'dns2', 'network_type', 'network_label', 'network_org',
  'verdict', 'app_version', 'schema_version'
];
const FIELDS = [
  'schema_version', 'report_id', 'created_at', 'run_id', 'outcome', 'error_code',
  'applied', 'dns1', 'dns2', 'network_type', 'network_label', 'network_org',
  'verdict', 'app_version'
];
const LIMITS = {error_code: 40, network_label: 80, network_org: 120, verdict: 160, app_version: 20};
const OUTCOMES = ['worked', 'same_error', 'different_error', 'unknown'];
const MIN_GROUP = 3;              // privacy: smaller groups are never reported
const STATS_CACHE_SEC = 300;      // 5 minutes: the sheet is read at most ~12 times/hour
const STATS_TOP = 100;            // cap list sizes

function doGet(e) {
  try {
    const token = (e && e.parameter && String(e.parameter.token || '')) || '';
    const expected = PropertiesService.getScriptProperties().getProperty('INGEST_TOKEN') || '';
    if (!expected || token !== expected) throw new Error('unauthorized');
    const cache = CacheService.getScriptCache();
    const cached = cache.get('stats_v1');
    if (cached) return json_({ok: true, cached: true, stats: JSON.parse(cached)});
    const stats = buildStats_();
    cache.put('stats_v1', JSON.stringify(stats), STATS_CACHE_SEC);
    return json_({ok: true, cached: false, stats: stats});
  } catch (error) {
    return json_({ok: false, error: String(error.message || error).slice(0, 160)});
  }
}

function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents || '{}');
    const expected = PropertiesService.getScriptProperties().getProperty('INGEST_TOKEN') || '';
    if (!expected || body.token !== expected) throw new Error('unauthorized');
    const report = validateReport_(body.report);
    const duplicate = appendReport_(report);
    // The sheet changed: drop cached aggregates.
    try { CacheService.getScriptCache().remove('stats_v1'); } catch (ignore) {}
    return json_({ok: true, duplicate: duplicate});
  } catch (error) {
    return json_({ok: false, error: String(error.message || error).slice(0, 160)});
  }
}

function validateReport_(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('invalid report');
  const keys = Object.keys(report).sort();
  if (JSON.stringify(keys) !== JSON.stringify(FIELDS.slice().sort())) throw new Error('invalid fields');
  if (report.schema_version !== 1) throw new Error('invalid schema');
  if (!/^[0-9a-f]{32}$/.test(report.report_id)) throw new Error('invalid report id');
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(report.run_id)) throw new Error('invalid run id');
  if (isNaN(Date.parse(report.created_at))) throw new Error('invalid timestamp');
  if (['worked', 'same_error', 'different_error', 'unknown'].indexOf(report.outcome) < 0) {
    throw new Error('invalid outcome');
  }
  if (['console', 'router', 'both', 'unknown'].indexOf(report.applied) < 0) {
    throw new Error('invalid applied value');
  }
  if (['office', 'home', 'vpn', 'other'].indexOf(report.network_type) < 0) {
    throw new Error('invalid network type');
  }
  validateIp_(report.dns1, true);   // веб-отчёты не знают DNS консоли: оба адреса необязательны
  validateIp_(report.dns2, true);
  const clean = {};
  FIELDS.forEach(function(key) {
    const value = key === 'schema_version' ? 1 : text_(report[key], LIMITS[key] || 160);
    clean[key] = value;
  });
  if (!clean.network_label) throw new Error('invalid network label');
  return clean;
}

function validateIp_(value, optional) {
  const text = String(value || '').trim();
  if (!text && optional) return;
  if (!text || text.length > 64 || /[\s;='"@]/.test(text)) throw new Error('invalid DNS address');
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(text);
  if (ipv4 && text.split('.').some(function(part) { return Number(part) > 255; })) {
    throw new Error('invalid DNS address');
  }
  if (!ipv4 && !/^[0-9A-Fa-f:]+$/.test(text)) throw new Error('invalid DNS address');
}

function appendReport_(report) {
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const sheet = reportsSheet_();
    if (sheet.getLastRow() === 0) sheet.appendRow(HEADERS);
    const found = sheet.getRange(1, 1, sheet.getLastRow(), 1)
      .createTextFinder(report.report_id).matchEntireCell(true).findNext();
    if (found) return true;
    const row = [
      report.report_id, new Date().toISOString(), report.created_at, report.run_id,
      report.outcome, report.error_code, report.applied, report.dns1, report.dns2,
      report.network_type, report.network_label, report.network_org,
      report.verdict, report.app_version, report.schema_version
    ];
    sheet.getRange(sheet.getLastRow() + 1, 1, 1, row.length)
      .setNumberFormat('@').setValues([row]);
    return false;
  } finally {
    lock.releaseLock();
  }
}

function reportsSheet_() {
  const sheetId = PropertiesService.getScriptProperties().getProperty('SHEET_ID');
  if (!sheetId) throw new Error('SHEET_ID is not configured');
  const book = SpreadsheetApp.openById(sheetId);
  return book.getSheetByName('Reports') || book.insertSheet('Reports');
}

function text_(value, limit) {
  let text = String(value === undefined || value === null ? '' : value)
    .replace(/[\r\n\t]/g, ' ').trim().slice(0, limit);
  if (/^[=+\-@]/.test(text)) text = "'" + text;
  return text;
}

function json_(value) {
  return ContentService.createTextOutput(JSON.stringify(value))
    .setMimeType(ContentService.MimeType.JSON);
}

/* --- Stage 3: read-only aggregates ---------------------------------------
 * Only numbers, enums and group-level dates. Combinations with fewer than
 * MIN_GROUP reports are dropped entirely: one support call must not be
 * traceable through statistics. Single-report timestamps never leave here.
 * ------------------------------------------------------------------------ */

function buildStats_() {
  const rows = readReports_();
  const now = Date.now();
  const d30 = now - 30 * 86400000;
  const d90 = now - 90 * 86400000;

  const totals = {reports: 0, worked: 0, same_error: 0, different_error: 0,
    unknown: 0, success_rate: 0, active_networks: 0};
  const networks = {};
  const byOutcome = {}, byApplied = {}, byType = {};
  const dnsGroups = {};      // key: dns address
  const comboGroups = {};    // key: dns address + org

  rows.forEach(function(r) {
    const outcome = OUTCOMES.indexOf(r.outcome) >= 0 ? r.outcome : 'unknown';
    const created = Date.parse(r.created_at) || 0;
    bump_(totals, outcome);
    bump_(byOutcome, outcome);
    bump_(byApplied, String(r.applied || 'unknown'));
    bump_(byType, String(r.network_type || 'other'));
    const org = String(r.network_org || '').trim();
    if (org) networks[org] = true;

    const seen = {};
    [r.dns1, r.dns2].forEach(function(addr) {
      const dns = String(addr || '').trim();
      if (!dns || seen[dns]) return;   // one report counts once per address
      seen[dns] = true;
      const g = group_(dnsGroups, dns);
      bump_(g, outcome);
      if (created >= d30) { g.reports_30d++; if (outcome === 'worked') g.worked_30d++; }
      if (created >= d90) { g.reports_90d++; if (outcome === 'worked') g.worked_90d++; }
      if (created > g._last) g._last = created;
      if (org) {
        const c = group_(comboGroups, dns + '' + org);
        bump_(c, outcome);
      }
    });
  });

  const known = totals.reports - totals.unknown;
  totals.success_rate = rate_(totals.worked, known);
  totals.active_networks = Object.keys(networks).length;

  return {
    generated_at: new Date(now).toISOString(),
    min_group: MIN_GROUP,
    totals: totals,
    by_outcome: byOutcome,
    by_applied: byApplied,
    by_network_type: byType,
    by_dns: emitGroups_(dnsGroups, true),
    by_dns_org: emitGroups_(comboGroups, false)
  };
}

function readReports_() {
  const sheet = reportsSheet_();
  const last = sheet.getLastRow();
  if (last < 2) return [];
  const values = sheet.getRange(2, 1, last - 1, HEADERS.length).getValues();
  return values.map(function(row) {
    const o = {};
    HEADERS.forEach(function(h, i) { o[h] = row[i]; });
    return o;
  });
}

function group_(map, key) {
  if (!map[key]) {
    map[key] = {reports: 0, worked: 0, same_error: 0, different_error: 0, unknown: 0,
      reports_30d: 0, worked_30d: 0, reports_90d: 0, worked_90d: 0, _last: 0};
  }
  return map[key];
}

function bump_(obj, outcome) {
  obj.reports = (obj.reports || 0) + 1;
  obj[outcome] = (obj[outcome] || 0) + 1;
}

function rate_(worked, known) {
  return known > 0 ? Math.round(worked / known * 1000) / 1000 : 0;
}

function emitGroups_(map, withWindows) {
  const out = [];
  Object.keys(map).forEach(function(key) {
    const g = map[key];
    if (g.reports < MIN_GROUP) return;   // the privacy hard rule
    const item = withWindows
      ? {dns: key}
      : {dns: key.split('')[0], org: key.split('').slice(1).join('')};
    item.reports = g.reports;
    item.worked = g.worked;
    item.same_error = g.same_error;
    item.different_error = g.different_error;
    item.unknown = g.unknown;
    item.success_rate = rate_(g.worked, g.reports - g.unknown);
    if (withWindows) {
      item.reports_30d = g.reports_30d;
      item.worked_30d = g.worked_30d;
      item.reports_90d = g.reports_90d;
      item.worked_90d = g.worked_90d;
    }
    item.last_report = new Date(g._last).toISOString().slice(0, 10);
    out.push(item);
  });
  out.sort(function(a, b) { return b.reports - a.reports; });
  return out.slice(0, STATS_TOP);
}
