/*
 * DNS Checker — веб-версия (Stage 1), дизайн Platform 2.0.
 *
 * Логика вердиктов (D1): «ответил Microsoft» НЕ значит «работает».
 * Страница сравнивает ответ публичных DoH-резолверов с курируемым
 * списком РАБОЧИХ адресов (working-ips.json, у каждой записи дата проверки).
 *
 * Чистые функции вынесены вверх и экспортируются для node-тестов (selftest.js).
 */

"use strict";

// --- Данные: те же домены, что в консольной программе (consoles.json) ---

const DOMAINS = [
  { host: "xsts.auth.xboxlive.com",    short: "Вход XBL",      what: "Вход: токен Xbox Live",            critical: true },
  { host: "user.auth.xboxlive.com",    short: "Вход польз.",   what: "Вход: авторизация пользователя",   critical: true },
  { host: "device.auth.xboxlive.com",  short: "Консоль",       what: "Авторизация консоли",              critical: true },
  { host: "title.auth.xboxlive.com",   short: "Игры",          what: "Авторизация игр",                  critical: true },
  { host: "login.live.com",            short: "Аккаунт",       what: "Учётная запись Microsoft",         critical: true },
  { host: "title.mgt.xboxlive.com",    short: "Сведения",      what: "Сведения об играх",                critical: true },
  { host: "notify.xboxlive.com",       short: "Уведомления",   what: "Уведомления",                      critical: false },
  { host: "assets1.xboxlive.com",      short: "Загрузки",      what: "Загрузки игр и обновлений",        critical: false },
  { host: "clientconfig.passport.net", short: "Passport",      what: "Вход и создание учётных записей",  critical: false },
  { host: "www.xbox.com",              short: "Сайт",          what: "Сайт / магазин",                   critical: false },
  { host: "www.msftconnecttest.com",   short: "Интернет (нов.)", what: "Проверка «есть ли интернет» (новая)", critical: false },
  { host: "www.msftncsi.com",          short: "Интернет (стар.)", what: "Проверка «есть ли интернет» (старая)", critical: false },
];

// Публичные DoH-резолверы: дают картину «что видит обычный DNS».
const PROVIDERS = [
  { id: "google",     name: "Google",     url: "https://dns.google/resolve",         json: true },
  { id: "cloudflare", name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query", json: true },
];

// Сети Microsoft из десктопной программы (dnschecker/config.py) —
// ответ из них = «настоящий Microsoft-адрес» (но не обязательно рабочий маршрут).
const MICROSOFT_NETS = [
  "20.0.0.0/8", "13.64.0.0/11", "40.64.0.0/10", "52.96.0.0/12",
  "104.40.0.0/13", "191.232.0.0/13",
];

// Маркеры CDN из РЕАЛЬНЫХ цепочек CNAME доменов Xbox (сняты 2026-11-19):
// akadns/trafficmanager/msidentity/msftauth — Microsoft, edgekey/akamaiedge/
// akamai/edgesuite — Akamai, globalcdn.co — CDN доставки Microsoft.
const CDN_CNAME_MARKERS = [
  "akadns.net", "trafficmanager.net", "msidentity.com", "msftauth.net",
  "azurefd.net", "azureedge.net", "msedge.net", "globalcdn.co",
  "edgekey.net", "akamaiedge.net", "akamai.net", "edgesuite.net",
];

// Статусы dns-json (RFC 8499 по смыслу): 0 NOERROR, 3 NXDOMAIN
const RCODE_NOERROR = 0;
const RCODE_NXDOMAIN = 3;

const REQUEST_TIMEOUT_MS = 8000;
const REQUEST_DELAY_MS = 250;      // не душим провайдеров (план: rate-limit)
const CACHE_TTL_MS = 5 * 60 * 1000;
const RETRY_AFTER_429_MS = 2000;   // один вежливый повтор при 429

// --- Чистые функции (без браузера) ---

function ipToLong(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function ipInCidr(ip, cidr) {
  const long = ipToLong(ip);
  if (long === null) return false;
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const baseLong = ipToLong(base);
  if (baseLong === null) return false;
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  return (long & mask) === (baseLong & mask);
}

function isMicrosoftIp(ip) {
  return MICROSOFT_NETS.some(cidr => ipInCidr(ip, cidr));
}

function isBlackholeIp(ip) {
  const long = ipToLong(ip);
  if (long === null) return false;
  const first = Number(ip.split(".")[0]);
  return long === 0 || first === 127 || first === 0; // 0.0.0.0, 127.x, 0.x.x.x
}

// Разбор ответа DoH в JSON: адреса, CNAME, статус.
function parseDohJson(data) {
  const ips = [], cnames = [];
  for (const a of data.Answer || []) {
    if (a.type === 1 && a.data) ips.push(a.data);
    if (a.type === 5 && a.data) cnames.push(a.data.replace(/\.$/, ""));
  }
  return { status: data.Status, ips, cnames };
}

// Вердикт для ОДНОГО ответа резолвера.
// workingMap: {domain: [{ip, source, verified}]} — курируемый список.
function classifyAnswer(domain, parsed, workingMap) {
  if (parsed.status === RCODE_NXDOMAIN) {
    return { cls: "red", label: "домен не существует (NXDOMAIN)" };
  }
  if (parsed.status !== RCODE_NOERROR) {
    return { cls: "gray", label: "DNS-ошибка (код " + parsed.status + ")" };
  }
  if (parsed.ips.length === 0) {
    if (parsed.cnames.length > 0) return { cls: "gray", label: "только CNAME, без IPv4" };
    return { cls: "gray", label: "пустой ответ" };
  }
  const working = workingMap[domain] || [];
  const hit = parsed.ips.find(ip => working.some(w => w.ip === ip));
  if (hit) {
    const w = working.find(w => w.ip === hit);
    return { cls: "green", label: "совпадает с рабочим адресом",
             working: w };
  }
  if (parsed.ips.some(isBlackholeIp)) {
    return { cls: "red", label: "заблокирован DNS-сервером (0.0.0.0/127.x)" };
  }
  if (parsed.ips.some(isMicrosoftIp)) {
    if (working.length > 0) {
      return { cls: "yellow", label: "не рабочий маршрут",
               hint: "Обычные DNS дают адрес Microsoft — этот маршрут сейчас не работает. Рабочий адрес — в подробностях." };
    }
    return { cls: "gray", label: "ответ Microsoft" };
  }
  const viaCdn = parsed.cnames.some(c =>
    CDN_CNAME_MARKERS.some(m => c === m || c.endsWith("." + m)));
  if (viaCdn) {
    return { cls: "gray", label: "ответ Microsoft через CDN" };
  }
  return { cls: "red", label: "подозрение на подмену адреса",
           hint: "Ответ ни из сетей Microsoft, ни через известный CDN." };
}

// Итог по домену из ответов всех провайдеров: худший из «красных» побеждает,
// иначе жёлтый, иначе зелёный, иначе серый.
function worstVerdict(perProvider) {
  const order = { red: 3, yellow: 2, green: 1, gray: 0, none: -1 };
  let worst = { cls: "none", label: "не проверено" };
  for (const p of perProvider) {
    if (!p || !p.verdict) continue;
    if (order[p.verdict.cls] > order[worst.cls]) worst = p.verdict;
  }
  return worst;
}

// --- Браузерная часть ---

const state = {
  workingMap: {},
  running: false,
  results: new Map(), // domain -> { perProvider: [...], verdict }
};

function el(id) { return document.getElementById(id); }

function setStatus(text) { el("status-line").textContent = text; }

function showError(text) {
  const b = el("error-banner");
  if (text) { b.textContent = text; b.hidden = false; }
  else { b.hidden = true; }
}

// Кэш в sessionStorage: не дёргаем провайдеров повторно при перезапуске проверки.
function cacheKey(providerId, domain) { return "doh:" + providerId + ":" + domain; }

function readCache(key) {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return null;
    const item = JSON.parse(raw);
    if (Date.now() - item.ts > CACHE_TTL_MS) return null;
    return item.value;
  } catch { return null; }
}

function writeCache(key, value) {
  try { sessionStorage.setItem(key, JSON.stringify({ ts: Date.now(), value })); } catch {}
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function fetchJson(url, attempt) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      headers: { "Accept": "application/dns-json" },
      signal: ctrl.signal,
      cache: "no-store",
    });
    if (resp.status === 429 && attempt === 0) {
      await sleep(RETRY_AFTER_429_MS);
      return fetchJson(url, 1);
    }
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

async function askProvider(provider, domain) {
  const key = cacheKey(provider.id, domain);
  const cached = readCache(key);
  if (cached) return { ...cached, cached: true };

  const url = provider.url + "?name=" + encodeURIComponent(domain) + "&type=A";
  const start = performance.now();
  const data = await fetchJson(url, 0);
  const ms = Math.round(performance.now() - start);
  const parsed = parseDohJson(data);
  const record = { provider: provider.name, ms, parsed };
  writeCache(key, record);
  return { ...record, cached: false };
}

const CLS_ICON = { green: "✓", yellow: "!", red: "✕", gray: "…", none: "…" };

function renderDomainCard(domain) {
  const box = el("results");
  const card = document.createElement("div");
  card.className = "v-card";
  card.id = "card-" + domain.host;

  const head = document.createElement("div");
  head.className = "v-head";
  const ico = document.createElement("span");
  ico.className = "v-ico i-gray";
  ico.id = "ico-" + domain.host;
  ico.textContent = "…";
  const title = document.createElement("div");
  title.className = "v-title";
  const b = document.createElement("b");
  b.textContent = domain.host;
  const span = document.createElement("span");
  span.textContent = domain.short + " — " + domain.what;
  title.appendChild(b);
  title.appendChild(span);
  const badge = document.createElement("span");
  badge.className = "v-badge s-gray";
  badge.id = "badge-" + domain.host;
  badge.textContent = "не проверено";
  head.appendChild(ico);
  head.appendChild(title);
  head.appendChild(badge);
  card.appendChild(head);

  const det = document.createElement("div");
  det.className = "v-det";
  det.id = "det-" + domain.host;
  det.hidden = true;
  card.appendChild(det);

  const toggle = document.createElement("button");
  toggle.className = "v-toggle";
  toggle.id = "tog-" + domain.host;
  toggle.textContent = "подробности";
  toggle.hidden = true;
  toggle.addEventListener("click", () => { det.hidden = !det.hidden; });
  card.appendChild(toggle);

  box.appendChild(card);
}

function buildDetailsHtml(domain, perProvider, verdict) {
  const working = state.workingMap[domain.host] || [];
  let html = "";
  for (const p of perProvider) {
    if (!p) { html += "<p>· ошибка запроса</p>"; continue; }
    if (p.error) { html += "<p>· " + escHtml(p.provider) + ": " + escHtml(p.error) + "</p>"; continue; }
    html += "<p>· <b>" + escHtml(p.provider) + "</b>: " +
            (p.parsed.ips.length ? escHtml(p.parsed.ips.join(", ")) : "без IPv4");
    if (p.parsed.cnames.length) html += " · через " + escHtml(p.parsed.cnames[0]);
    html += " · " + p.ms + " мс</p>";
  }
  if (verdict.hint) html += '<p class="v-hint">' + escHtml(verdict.hint) + "</p>";
  if (working.length > 0) {
    html += '<p class="v-work">Рабочий адрес (проверен):</p>';
    for (const w of working) {
      html += '<p class="v-work">· <b>' + escHtml(w.ip) + "</b> — " + escHtml(w.source) +
              ", проверено " + escHtml(w.verified) + "</p>";
    }
  }
  return html;
}

function escHtml(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const CLS_BADGE = { green: "s-ok", yellow: "s-warn", red: "s-bad", gray: "s-gray", none: "s-gray" };
const CLS_ICO = { green: "i-ok", yellow: "i-warn", red: "i-bad", gray: "i-gray", none: "i-gray" };

function updateDomainCard(domain, perProvider) {
  const card = el("card-" + domain.host);
  const withVerdicts = perProvider.map(p => {
    if (!p || p.error) return { p, verdict: null };
    return { p, verdict: classifyAnswer(domain.host, p.parsed, state.workingMap) };
  });
  const verdict = worstVerdict(withVerdicts.map(x => x.verdict ? { verdict: x.verdict } : null));

  const ico = el("ico-" + domain.host);
  ico.className = "v-ico " + (CLS_ICO[verdict.cls] || "i-gray");
  ico.textContent = CLS_ICON[verdict.cls] || "…";
  const badge = el("badge-" + domain.host);
  badge.className = "v-badge " + (CLS_BADGE[verdict.cls] || "s-gray");
  badge.textContent = verdict.label;

  const det = el("det-" + domain.host);
  det.innerHTML = buildDetailsHtml(domain, perProvider, verdict);
  el("tog-" + domain.host).hidden = false;

  state.results.set(domain.host, { perProvider, verdict });
}

function renderSummary() {
  const summary = el("summary");
  summary.hidden = false;
  let yellow = 0, red = 0, checked = 0;
  for (const { verdict } of state.results.values()) {
    checked++;
    if (verdict.cls === "yellow") yellow++;
    else if (verdict.cls === "red") red++;
  }
  if (checked === 0) { summary.hidden = true; return; }
  const lines = [];
  if (yellow > 0) lines.push(
    "Обычные DNS дают адреса Microsoft, но для " + yellow + " " +
    plural(yellow, "домена", "доменов", "доменов") +
    " входа рабочий маршрут сейчас другой — см. подробности в карточках.");
  if (red > 0) lines.push("По " + red + " " + plural(red, "домену", "доменам", "доменам") +
    " ответы подозрительные — DNS вмешивается в ответ.");
  if (lines.length === 0) lines.push("Аномалий в DNS-ответах не замечено. Если вход не работает — причина глубже DNS.");
  summary.innerHTML = lines.join("<br>");
}

function plural(n, one, few, many) {
  const mod100 = n % 100, mod10 = n % 10;
  if (mod100 >= 11 && mod100 <= 14) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

async function runAll() {
  if (state.running) return;
  state.running = true;
  const btn = el("check-all");
  btn.disabled = true;
  showError("");
  el("summary").hidden = true;
  setStatus("Проверяю…");

  if (!navigator.onLine) {
    showError("Нет подключения к интернету. Проверка невозможна — страница честно сдаётся.");
    setStatus("");
    btn.disabled = false;
    state.running = false;
    return;
  }

  let done = 0, failed = 0;
  for (const domain of DOMAINS) updateDomainCard(domain, [null, null]);
  for (const domain of DOMAINS) {
    const perProvider = [];
    for (const provider of PROVIDERS) {
      try {
        perProvider.push(await askProvider(provider, domain.host));
      } catch (e) {
        failed++;
        perProvider.push({ provider: provider.name, error: friendlyError(e) });
      }
      await sleep(REQUEST_DELAY_MS);
    }
    updateDomainCard(domain, perProvider);
    done++;
    setStatus("Проверено " + done + " из " + DOMAINS.length + "…");
  }
  renderSummary();
  const tail = failed > 0 ? " (" + failed + " запросов не дошло — возможно, сеть режет DoH)" : "";
  setStatus("Готово" + tail + ". Данные кэшируются 5 минут.");
  btn.disabled = false;
  state.running = false;
  if (typeof fbShowPanel === "function") fbShowPanel();
  if (typeof fbWire === "function" && !state.fbWired) {
    state.fbWired = true;
    fbWire(state);
  }
}

function friendlyError(e) {
  if (e.name === "AbortError") return "таймаут";
  return e.message || "ошибка сети";
}

async function boot() {
  for (const d of DOMAINS) renderDomainCard(d);
  try {
    const resp = await fetch("working-ips.json", { cache: "no-store" });
    if (resp.ok) {
      const data = await resp.json();
      state.workingMap = data.entries || {};
    }
  } catch { /* список рабочих адресов недоступен — проверка всё равно работает */ }
  el("check-all").addEventListener("click", runAll);
  setStatus("Готов. Нажмите «Проверить».");
  // ?autorun=1 — самозапуск проверки (автотесты в headless-браузерах).
  if (new URLSearchParams(location.search).get("autorun") === "1") runAll();
}

if (typeof document !== "undefined") {
  boot();
}

// Экспорт для node-тестов.
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    ipToLong, ipInCidr, isMicrosoftIp, isBlackholeIp,
    parseDohJson, classifyAnswer, worstVerdict, DOMAINS, PROVIDERS,
  };
}
