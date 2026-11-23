/* DNS Checker anonymous feedback receiver for a bound or standalone Apps Script project.
 * Script Properties: SHEET_ID and INGEST_TOKEN. Never put the token in this source file.
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

function doGet() {
  return json_({ok: true, service: 'dns-checker-feedback'});
}

function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents || '{}');
    const expected = PropertiesService.getScriptProperties().getProperty('INGEST_TOKEN') || '';
    if (!expected || body.token !== expected) throw new Error('unauthorized');
    const report = validateReport_(body.report);
    const duplicate = appendReport_(report);
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
  if (!text || text.length > 64 || /[\s;='"+@]/.test(text)) throw new Error('invalid DNS address');
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
    const sheetId = PropertiesService.getScriptProperties().getProperty('SHEET_ID');
    if (!sheetId) throw new Error('SHEET_ID is not configured');
    const book = SpreadsheetApp.openById(sheetId);
    const sheet = book.getSheetByName('Reports') || book.insertSheet('Reports');
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
