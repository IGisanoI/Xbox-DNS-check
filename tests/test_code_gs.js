/*
 * Тесты для Code.gs (Stage 3 + 4) в node: Apps Script рантайм подменяется заглушками,
 * лист — массивом строк в памяти. Запуск: node test_code_gs.js
 *
 * Фикстуры (11 отчётов), ручной подсчёт:
 *   E1 same_error  dns 1.1.1.1  ISP One   12д  ошибка 0x80a40401
 *   E2 different   dns 1.1.1.1  ISP One   15д  ошибка 0X80A40401
 *   E3 worked      dns 1.1.1.1  ISP One   19д  ошибка "free text"
 *   A1 worked      1.1.1.1+1.0.0.1 ISP One  5д
 *   A2 worked      1.1.1.1      ISP One   40д
 *   A3 same_error  1.1.1.1      ISP One   80д
 *   B1 worked      2.2.2.2      ISP Two    3д
 *   B2 unknown     2.2.2.2      ""        10д
 *   C1 worked      3.3.3.3      ISP Three  2д
 *   C2 worked      3.3.3.3      ISP Three 20д
 *   C3 different   3.3.3.3      ISP Three 60д
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const sheetRows = [];
let cacheStore = {};

function makeSheet() {
  return {
    getLastRow: () => sheetRows.length,
    appendRow: (row) => sheetRows.push(row.map(String)),
    getRange: (r1, c1, rows, cols) => ({
      getValues: () => sheetRows.slice(r1 - 1, r1 - 1 + rows).map(r => r.slice(c1 - 1, c1 - 1 + cols)),
      createTextFinder: (q) => ({
        matchEntireCell: () => ({ findNext: () => sheetRows.some(r => r[0] === q) ? { getRow: () => 1 } : null }),
      }),
      setNumberFormat: () => ({ setValues: (vals) => { vals[0].forEach((v, i) => { sheetRows[sheetRows.length - 1][c1 - 1 + i] = String(v); }); } }),
    }),
  };
}

const sandbox = {
  PropertiesService: { getScriptProperties: () => ({ getProperty: (k) => ({ SHEET_ID: "x", INGEST_TOKEN: "tok" })[k] }) },
  SpreadsheetApp: { openById: () => ({ getSheetByName: () => makeSheet(), insertSheet: () => makeSheet() }) },
  LockService: { getScriptLock: () => ({ waitLock: () => {}, releaseLock: () => {} }) },
  CacheService: { getScriptCache: () => ({
    get: (k) => cacheStore[k] || null,
    put: (k, v) => { cacheStore[k] = v; },
    remove: (k) => { delete cacheStore[k]; },
  }) },
  ContentService: { MimeType: { JSON: "JSON" }, createTextOutput: (s) => ({ getContent: () => s, setMimeType: function() { return this; } }) },
  console,
};
sandbox.global = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "cloud", "Code.gs"), "utf8"), sandbox);

const H = ["report_id","received_at","created_at","run_id","outcome","error_code","applied","dns1","dns2","network_type","network_label","network_org","verdict","app_version","schema_version"];
const NOW = Date.now();
const day = 86400000;
let n = 0;
function row(outcome, dns1, dns2, org, daysAgo, errorCode) {
  n++;
  const created = new Date(NOW - daysAgo * day).toISOString();
  const r = {};
  H.forEach(h => r[h] = "");
  r.report_id = n.toString(16).padStart(32, "0");
  r.created_at = created;
  r.run_id = "run" + n;
  r.outcome = outcome;
  r.error_code = errorCode || "";
  r.applied = "console";
  r.dns1 = dns1; r.dns2 = dns2;
  r.network_type = "home";
  r.network_label = "Тест";
  r.network_org = org;
  r.app_version = "4.1";
  r.schema_version = "1";
  return H.map(h => r[h]);
}

sheetRows.push(H);
sheetRows.push(row("same_error", "1.1.1.1", "", "ISP One", 12, "0x80a40401"));
sheetRows.push(row("different_error", "1.1.1.1", "", "ISP One", 15, "0X80A40401"));
sheetRows.push(row("worked", "1.1.1.1", "", "ISP One", 19, "позвоните мне 8999"));
sheetRows.push(row("worked", "1.1.1.1", "1.0.0.1", "ISP One", 5));
sheetRows.push(row("worked", "1.1.1.1", "", "ISP One", 40));
sheetRows.push(row("same_error", "1.1.1.1", "", "ISP One", 80));
sheetRows.push(row("worked", "2.2.2.2", "", "ISP Two", 3));
sheetRows.push(row("unknown", "2.2.2.2", "", "", 10));
sheetRows.push(row("worked", "3.3.3.3", "", "ISP Three", 2));
sheetRows.push(row("worked", "3.3.3.3", "", "ISP Three", 20));
sheetRows.push(row("different_error", "3.3.3.3", "", "ISP Three", 60));

const { doGet, doPost } = sandbox;

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log("ok   -", name); }
  else { failed++; console.log("FAIL -", name); }
}
function get(token) {
  return JSON.parse(doGet({ parameter: { token } }).getContent());
}

let r = get("");
check("без токена -> ok:false unauthorized", r.ok === false && /unauthorized/.test(r.error));
r = get("wrong");
check("плохой токен -> отказ", r.ok === false);
r = get("tok");
check("с токеном -> ok:true", r.ok === true);
check("кэш-флаг присутствует", r.cached === false);

const s = r.stats;
check("totals.reports = 11", s.totals.reports === 11);
check("totals.worked = 6", s.totals.worked === 6);
check("totals.same_error = 2", s.totals.same_error === 2);
check("totals.different_error = 2", s.totals.different_error === 2);
check("totals.unknown = 1", s.totals.unknown === 1);
check("success_rate = 6/10 = 0.6", Math.abs(s.totals.success_rate - 0.6) < 0.001);
check("totals 30d: 8 отчётов, 5 worked", s.totals.reports_30d === 8 && s.totals.worked_30d === 5);
check("active_networks = 3", s.totals.active_networks === 3);

const errCount = s.by_error_code["0X80A40401"];
check("error_code 0X80A40401 посчитан (2, регистр слит)", errCount === 2);
check("free-text ошибка отброшена (все ключи — коды или 'reports')",
  Object.keys(s.by_error_code).every(k => k === "reports" || /^0X[0-9A-F]{4,12}$/.test(k)));
check("by_week: каждая неделя проходит порог >=3",
  Array.isArray(s.by_week) && s.by_week.every(w => w.reports >= 3 && w.worked <= w.reports));
check("by_week: сумма недель не превышает totals",
  s.by_week.reduce((a, w) => a + w.reports, 0) <= s.totals.reports);

const dnsA = s.by_dns.find(g => g.dns === "1.1.1.1");
check("dns A: reports=6, worked=3", !!dnsA && dnsA.reports === 6 && dnsA.worked === 3);
check("dns A: success = 0.5", dnsA && dnsA.success_rate === 0.5);
check("dns A: 30d = 4/2", dnsA && dnsA.reports_30d === 4 && dnsA.worked_30d === 2);
check("dns A: 90d = 6/3", dnsA && dnsA.reports_90d === 6 && dnsA.worked_90d === 3);
check("dns A: last_report = дата без времени", dnsA && /^\d{4}-\d{2}-\d{2}$/.test(dnsA.last_report));
check("1.0.0.1 скрыт (1 отчёт)", !s.by_dns.some(g => g.dns === "1.0.0.1"));
check("dns B скрыт (2 отчёта)", !s.by_dns.some(g => g.dns === "2.2.2.2"));
const dnsC = s.by_dns.find(g => g.dns === "3.3.3.3");
check("dns C: 3 отчёта, success ≈ 2/3", !!dnsC && dnsC.reports === 3 && Math.abs(dnsC.success_rate - 2 / 3) < 0.001);

check("комбо A+ISP One: 6 отчётов", s.by_dns_org.some(g => g.dns === "1.1.1.1" && g.org === "ISP One" && g.reports === 6));
check("комбо B+ISP Two скрыто (1)", !s.by_dns_org.some(g => g.dns === "2.2.2.2"));
check("пустой org не создаёт комбо", !s.by_dns_org.some(g => !g.org));

check("кэш после doGet: cached=true", get("tok").cached === true);

// doPost сбрасывает кэш; +1 worked на 1.1.1.1
const report = {
  schema_version: 1, report_id: "a".repeat(32), created_at: new Date(NOW).toISOString(),
  run_id: "posttest01-x", outcome: "worked", error_code: "", applied: "console",
  dns1: "1.1.1.1", dns2: "", network_type: "home", network_label: "Тест",
  network_org: "ISP One", verdict: "x", app_version: "4.1",
};
const post = JSON.parse(doPost({ postData: { contents: JSON.stringify({ token: "tok", report }) } }).getContent());
check("doPost новый отчёт -> ok, не дубликат", post.ok === true && post.duplicate === false);
r = get("tok");
check("после doPost кэш сброшен (cached=false)", r.cached === false);
check("dns A теперь 7 отчётов, 4 worked", (g => g.reports === 7 && g.worked === 4)(r.stats.by_dns.find(g => g.dns === "1.1.1.1")));

// один адрес — один счёт (dns1 == dns2)
const dbl = Object.assign({}, report, { report_id: "b".repeat(32), run_id: "posttest02-x", dns1: "9.9.9.9", dns2: "9.9.9.9" });
doPost({ postData: { contents: JSON.stringify({ token: "tok", report: dbl }) } });
r = get("tok");
check("9.9.9.9 скрыт (1 отчёт, посчитан один раз)", !r.stats.by_dns.some(g => g.dns === "9.9.9.9"));

// недельный порог: три отчёта в одну неделю -> неделя появляется
const triple = [1, 2, 3].map(i => Object.assign({}, report, {
  report_id: i.toString(16).padStart(32, "0"), run_id: "weektest0" + i + "-x",
  outcome: i === 3 ? "worked" : "same_error",
}));
triple.forEach(rep => doPost({ postData: { contents: JSON.stringify({ token: "tok", report: rep }) } }));
r = get("tok");
const thisWeek = r.stats.by_week.filter(w => w.reports >= 3);
check("неделя с 3+ отчётами появилась в by_week", thisWeek.length >= 1);
check("by_week: reports>=3 для каждой недели", r.stats.by_week.every(w => w.reports >= 3));

console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
