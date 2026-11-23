/*
 * Дашборд (Stage 4): читает агрегаты из stats endpoint (Stage 3) и рисует
 * SVG-графики без библиотек. Все числа — только то, что разрешает сервер
 * (min_group=3 уже применён на сервере; здесь мы лишь показываем).
 */
"use strict";

const OUTCOME_LABELS = {
  worked: "Вход заработал",
  same_error: "Та же ошибка",
  different_error: "Другая ошибка",
  unknown: "Не знаю",
};
const OUTCOME_COLORS = {
  worked: "#10dc60",
  same_error: "#e8c33f",
  different_error: "#e0564b",
  unknown: "#7d8f86",
};

function el(id) { return document.getElementById(id); }
function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function pct(x) { return Math.round(x * 100) + "%"; }

async function boot() {
  const cfg = window.DNSCHECK_CONFIG;
  let stats;
  try {
    const resp = await fetch(cfg.endpoint + "?token=" + encodeURIComponent(cfg.token),
      { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    if (data.ok !== true) throw new Error(data.error || "endpoint error");
    stats = data.stats;
  } catch (e) {
    el("dash-status").textContent =
      "Не удалось загрузить статистику (" + String(e.message || e) +
      "). Страница честно сдаётся — попробуйте позже.";
    return;
  }

  el("dash-status").textContent = "";
  renderKpis(stats);
  renderWeek(stats.by_week || []);
  renderDns(stats.by_dns || []);
  renderOutcome(stats.by_outcome || {});
  renderErrors(stats.by_error_code || {});
  renderOrg(stats.by_dns_org || []);
}

function renderKpis(s) {
  el("kpi-row").hidden = false;
  el("kpi-note").hidden = false;
  el("kpi-reports").textContent = s.totals.reports;
  el("kpi-rate").textContent = s.totals.reports > 0 ? pct(s.totals.success_rate) : "—";
  el("kpi-networks").textContent = s.totals.active_networks;
  el("kpi-30d").textContent = (s.totals.reports_30d || 0) +
    (s.totals.worked_30d ? " (" + pct(s.totals.worked_30d / Math.max(1, s.totals.reports_30d)) + " успеха)" : "");
}

function emptyPanel(container, text) {
  container.innerHTML = '<div class="dash-empty">' + esc(text) + "</div>";
}

// --- Линия: успешность по неделям ---
function renderWeek(weeks) {
  const box = el("chart-week");
  if (!weeks.length) {
    emptyPanel(box, "Пока нет недель с тремя и более отчётами. Данные накапливаются — график появится сам.");
    return;
  }
  const W = 560, H = 220, padL = 42, padB = 34, padT = 12;
  const rates = weeks.map(w => w.success_rate);
  const maxY = Math.max(0.25, ...rates, 0.05) * 1.15;
  const x = i => padL + (weeks.length === 1 ? (W - padL) / 2 : i * (W - padL - 20) / (weeks.length - 1));
  const y = v => padT + (1 - v / maxY) * (H - padT - padB);
  let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" class="chart">';
  [0, maxY / 2, maxY].forEach(v => {
    svg += '<line x1="' + padL + '" y1="' + y(v) + '" x2="' + (W - 10) + '" y2="' + y(v) + '" class="grid"/>'
      + '<text x="' + (padL - 6) + '" y="' + (y(v) + 4) + '" class="axis" text-anchor="end">' + Math.round(v * 100) + "%</text>";
  });
  const pts = weeks.map((w, i) => x(i) + "," + y(w.success_rate)).join(" ");
  svg += '<polyline points="' + pts + '" class="line"/>';
  weeks.forEach((w, i) => {
    svg += '<circle cx="' + x(i) + '" cy="' + y(w.success_rate) + '" r="' + (3 + Math.min(6, w.reports)) + '" class="dot">'
      + "<title>" + esc(w.week) + ": " + pct(w.success_rate) + " (" + w.worked + " из " + w.reports + ")</title></circle>"
      + '<text x="' + x(i) + '" y="' + (H - 12) + '" class="axis" text-anchor="middle">' + esc(w.week.slice(5)) + "</text>";
  });
  svg += "</svg>";
  box.innerHTML = svg;
}

// --- Горизонтальные бары: DNS, reports + worked ---
function renderDns(groups) {
  const box = el("chart-dns");
  const top = groups.slice(0, 10);
  if (!top.length) {
    emptyPanel(box, "Ни один DNS пока не набрал три отчёта. Как только наберут — появятся здесь.");
    return;
  }
  const max = Math.max(...top.map(g => g.reports), 1);
  let html = "";
  top.forEach(g => {
    const wTotal = Math.round(g.reports / max * 100);
    const wWorked = Math.round(g.worked / max * 100);
    html += '<div class="bar-row" title="' + esc(g.dns) + ": " + g.worked + " из " + g.reports + '">'
      + '<span class="bar-label">' + esc(g.dns) + "</span>"
      + '<span class="bar-track"><span class="bar-total" style="width:' + wTotal + '%"></span>'
      + '<span class="bar-worked" style="width:' + wWorked + '%"></span></span>'
      + '<span class="bar-value">' + g.worked + "/" + g.reports + " · " + pct(g.success_rate) + "</span></div>";
  });
  box.innerHTML = html;
}

// --- Донат: итоги ---
function renderOutcome(byOutcome) {
  const box = el("chart-outcome");
  const entries = Object.keys(OUTCOME_LABELS)
    .map(k => [k, byOutcome[k] || 0])
    .filter(([, v]) => v > 0);
  const total = entries.reduce((a, [, v]) => a + v, 0);
  if (!total) {
    emptyPanel(box, "Пока нет итогов.");
    return;
  }
  const R = 62, C = 2 * Math.PI * R;
  let acc = 0;
  let circles = "";
  entries.forEach(([k, v]) => {
    const frac = v / total;
    circles += '<circle r="' + R + '" cx="80" cy="80" class="donut-seg" stroke="' + OUTCOME_COLORS[k] + '"'
      + ' stroke-dasharray="' + (frac * C).toFixed(1) + " " + C.toFixed(1) + '"'
      + ' stroke-dashoffset="' + (-acc * C).toFixed(1) + '">'
      + "<title>" + esc(OUTCOME_LABELS[k]) + ": " + v + "</title></circle>";
    acc += frac;
  });
  let legend = "";
  entries.forEach(([k, v]) => {
    legend += '<div class="legend-item"><span class="legend-swatch" style="background:' + OUTCOME_COLORS[k] + '"></span>'
      + esc(OUTCOME_LABELS[k]) + " — " + v + " (" + pct(v / total) + ")</div>";
  });
  box.innerHTML = '<div class="donut-wrap"><svg viewBox="0 0 160 160" class="donut">'
    + '<g transform="rotate(-90 80 80)">' + circles + "</g>"
    + '<text x="80" y="76" text-anchor="middle" class="donut-total">' + total + "</text>"
    + '<text x="80" y="94" text-anchor="middle" class="donut-sub">отчётов</text></svg>'
    + '<div class="legend">' + legend + "</div></div>";
}

// --- Таблицы ---
function renderErrors(byError) {
  const box = el("table-errors");
  const codes = Object.keys(byError).filter(k => k !== "reports").sort((a, b) => byError[b] - byError[a]);
  if (!codes.length) {
    emptyPanel(box, "Кодов ошибок пока нет — а значит, есть о чём молчать красиво.");
    return;
  }
  let html = '<table class="dash-table"><thead><tr><th>Код</th><th>Отчётов</th></tr></thead><tbody>';
  codes.forEach(c => { html += "<tr><td>" + esc(c) + "</td><td>" + byError[c] + "</td></tr>"; });
  box.innerHTML = html + "</tbody></table>";
}

function renderOrg(combos) {
  const box = el("table-org");
  if (!combos.length) {
    emptyPanel(box, "Комбинаций «DNS + провайдер» с тремя и более отчётами пока нет.");
    return;
  }
  let html = '<table class="dash-table"><thead><tr><th>DNS</th><th>Провайдер</th><th>Отчётов</th>'
    + "<th>Успехов</th><th>Доля</th></tr></thead><tbody>";
  combos.forEach(g => {
    html += "<tr><td>" + esc(g.dns) + "</td><td>" + esc(g.org) + "</td><td>" + g.reports
      + "</td><td>" + g.worked + "</td><td>" + pct(g.success_rate) + "</td></tr>";
  });
  box.innerHTML = html + "</tbody></table>";
}

boot();
