/*
 * Обратная связь с консоли (Stage 2): 2 нажатия, тот же отчёт, что в десктопе.
 *
 * Проверено 2026-11-23: Apps Script отдаёт Access-Control-Allow-Origin: * —
 * браузер МОЖЕТ прочитать ответ. Тело шлём как text/plain (без CORS-preflight),
 * ответ {ok:true} читается и показывается как «подтверждено».
 * Локальная копия отчёта в localStorage — доказательство и очередь повторной отправки.
 */
"use strict";

const FB_OUTCOMES = [
  { id: "worked",          label: "Вход заработал" },
  { id: "same_error",      label: "Та же ошибка" },
  { id: "different_error", label: "Другая ошибка" },
  { id: "unknown",         label: "Не знаю / не проверял" },
];

const FB_APPLIED = [
  { id: "console", label: "На консоли" },
  { id: "router",  label: "На роутере" },
  { id: "both",    label: "И там, и там" },
  { id: "unknown", label: "Не скажу" },
];

const FB_NETWORK_TYPE = "other";       // веб-страница не знает тип сети
const FB_NETWORK_LABEL = "Веб-проверка"; // обязательное непустое поле схемы
const FB_VERDICT_LIMIT = 160;

// --- Чистые функции (node-тесты) ---

function uuidHex() {
  // crypto.randomUUID есть и в браузере, и в node 19+.
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID().replace(/-/g, "");
  }
  return Array.from({ length: 32 }, () =>
    Math.floor(Math.random() * 16).toString(16)).join("");
}

function newRunIdWeb(now) {
  const d = now || new Date();
  const stamp = d.toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  return stamp + "-" + uuidHex().slice(0, 12);
}

// Сводка веб-проверки для поля verdict: только то, что увидели резолверы.
function summarizeVerdict(resultsMap) {
  const yellow = [], red = [];
  for (const [host, entry] of resultsMap) {
    const cls = entry.verdict && entry.verdict.cls;
    if (cls === "yellow") yellow.push(host);
    else if (cls === "red") red.push(host);
  }
  const parts = [];
  if (yellow.length) parts.push("не рабочий маршрут: " + yellow.join(", "));
  if (red.length) parts.push("подозрительные ответы: " + red.join(", "));
  return (parts.join("; ") || "аномалий в DNS-ответах не замечено").slice(0, FB_VERDICT_LIMIT);
}

// Тот же набор полей, что в десктопном отчёте (schema 1).
function buildWebReport(outcome, applied, verdictText, now) {
  now = now || new Date();
  const report = {
    schema_version: 1,
    report_id: uuidHex(),
    created_at: now.toISOString().replace(/\.\d+Z$/, "Z"),
    run_id: newRunIdWeb(now),
    outcome: outcome,
    error_code: "",
    applied: applied,
    dns1: "",   // веб-страница не знает DNS консоли; приёмник принимает пустые (после правки Code.gs)
    dns2: "",
    network_type: FB_NETWORK_TYPE,
    network_label: FB_NETWORK_LABEL,
    network_org: "",
    verdict: verdictText,
    app_version: (typeof window !== "undefined" && window.DNSCHECK_CONFIG
      ? window.DNSCHECK_CONFIG.appVersion : "web-1.0"),
  };
  validateWebReport(report);
  return report;
}

// Зеркало серверной валидации (cloud/Code.gs) — отчёт не отправляем заведомо битый.
function validateWebReport(report) {
  const FIELDS = ["schema_version", "report_id", "created_at", "run_id", "outcome",
    "error_code", "applied", "dns1", "dns2", "network_type", "network_label",
    "network_org", "verdict", "app_version"];
  const keys = Object.keys(report).sort();
  if (JSON.stringify(keys) !== JSON.stringify(FIELDS.slice().sort())) {
    throw new Error("неверный набор полей");
  }
  if (report.schema_version !== 1) throw new Error("неверная версия схемы");
  if (!/^[0-9a-f]{32}$/.test(report.report_id)) throw new Error("неверный report_id");
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(report.run_id)) throw new Error("неверный run_id");
  if (isNaN(Date.parse(report.created_at))) throw new Error("неверное время");
  if (!FB_OUTCOMES.some(o => o.id === report.outcome)) throw new Error("неверный результат");
  if (!FB_APPLIED.some(a => a.id === report.applied)) throw new Error("неверное место настройки");
  if (report.network_type !== FB_NETWORK_TYPE) throw new Error("неверный тип сети");
  if (!report.network_label || report.network_label.length > 80) throw new Error("неверная сеть");
  if (report.verdict.length > FB_VERDICT_LIMIT) throw new Error("длинный итог");
  return report;
}

// --- Отправка и очередь (браузер) ---

const FB_OUTBOX_KEY = "dnscheck-web-outbox";

function fbLoadOutbox() {
  try {
    const raw = localStorage.getItem(FB_OUTBOX_KEY);
    const data = raw ? JSON.parse(raw) : [];
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}

function fbSaveOutbox(items) {
  try {
    if (items.length) localStorage.setItem(FB_OUTBOX_KEY, JSON.stringify(items));
    else localStorage.removeItem(FB_OUTBOX_KEY);
  } catch {}
}

async function fbSend(report) {
  const cfg = window.DNSCHECK_CONFIG;
  const resp = await fetch(cfg.endpoint, {
    method: "POST",
    mode: "cors",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({ token: cfg.token, report: report }),
  });
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  const result = await resp.json();
  if (result.ok !== true) throw new Error(result.error || "приёмник отклонил отчёт");
  return result; // {ok:true, duplicate:bool}
}

// Очередь: неотправленное повторяем при следующем визите (как outbox в десктопе).
async function fbFlushOutbox() {
  const items = fbLoadOutbox();
  if (!items.length) return { sent: 0, pending: 0, error: "" };
  let sent = 0, error = "";
  const rest = [];
  for (const item of items) {
    if (error) { rest.push(item); continue; }
    try {
      await fbSend(item.report);
      sent++;
    } catch (e) {
      error = String(e.message || e);
      rest.push(item);
    }
  }
  fbSaveOutbox(rest);
  return { sent, pending: rest.length, error };
}

// --- Панель в интерфейсе ---

function fbSetStatus(text) {
  const s = document.getElementById("fb-status");
  if (s) s.textContent = text;
}

function fbShowPanel() {
  const p = document.getElementById("feedback-panel");
  if (p) p.hidden = false;
}

// Шаг 1: выбрали результат → показать шаг 2. Шаг 2: выбрали место → отправить.
function fbWire(state) {
  const panel = document.getElementById("feedback-panel");
  if (!panel) return;
  let pickedOutcome = null;
  let sending = false;

  panel.querySelectorAll("[data-outcome]").forEach(btn => {
    btn.addEventListener("click", () => {
      pickedOutcome = btn.dataset.outcome;
      panel.querySelectorAll("[data-outcome]").forEach(b =>
        b.classList.toggle("picked", b === btn));
      document.getElementById("fb-step2").hidden = false;
      fbSetStatus("");
    });
  });

  panel.querySelectorAll("[data-applied]").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (sending || !pickedOutcome) return;
      sending = true;
      panel.querySelectorAll("button").forEach(b => b.disabled = true);
      fbSetStatus("Отправляю…");
      try {
        const verdictText = summarizeVerdict(state.results);
        const report = buildWebReport(pickedOutcome, btn.dataset.applied, verdictText);
        const result = await fbSend(report);
        fbSetStatus(result.duplicate
          ? "Отчёт уже был (дубликат). Спасибо!"
          : "Отчёт отправлен и подтверждён приёмником. Спасибо!");
        panel.dataset.done = "1";
      } catch (e) {
        // Сеть/приёмник недоступен: сохраняем и честно говорим о статусе.
        try {
          const verdictText = summarizeVerdict(state.results);
          const report = buildWebReport(pickedOutcome, btn.dataset.applied, verdictText);
          const outbox = fbLoadOutbox();
          if (!outbox.some(i => i.report.report_id === report.report_id)) {
            outbox.push({ queued_at: new Date().toISOString(), report });
            fbSaveOutbox(outbox);
          }
          fbSetStatus("Не дошло (" + String(e.message || e) +
            "). Отчёт сохранён на устройстве и будет отправлен при следующем визите.");
        } catch (e2) {
          fbSetStatus("Не удалось сохранить отчёт: " + String(e2.message || e2));
        }
      } finally {
        sending = false;
        panel.querySelectorAll("button").forEach(b => b.disabled = false);
      }
    });
  });
}

if (typeof document !== "undefined") {
  // Повторная отправка очереди при входе + приветствие, если есть что досылать.
  fbFlushOutbox().then(r => {
    if (r.sent > 0) fbSetStatus("Доправлено из очереди: " + r.sent + " отчёт(ов).");
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { buildWebReport, validateWebReport, summarizeVerdict,
                     newRunIdWeb, FB_OUTCOMES, FB_APPLIED, FB_VERDICT_LIMIT };
}
