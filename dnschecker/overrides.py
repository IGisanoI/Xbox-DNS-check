"""
IP-обход (Stage 5b): проверка статических записей «домен → рабочий IP».

Список — курируемый (ip_overrides.json, как consoles.json). Каждый кандидат
проверяется так, как подключается консоль: TCP → TLS с SNI домена → HTTP.
Итог — только классификация: отвечает как Xbox / жив, но не тот ответ /
мёртвый. Результаты пишутся в ip_overrides_log.csv: «живы ли обходы на этой неделе».
"""

import json
from datetime import datetime

from . import paths, storage
from .http_probe import PROBE_RANK

OVERRIDES_FILE = paths.path("ip_overrides.json")
LOG_FILE = paths.path("ip_overrides_log.csv")

LOG_HEADER = ["Время", "Домен", "IP", "Итог", "Категория", "Детали", "мс"]

# Что считаем «живым» обходом: TLS с настоящим сертификатом домена прошёл,
# а дальше — любой осмысленный HTTP-ответ (включая отказ 403: сервер жив).
ALIVE_STATES = {"ok", "forbidden", "redirect", "unexpected", "server_error"}
STATE_LABELS = {
    "ok": "отвечает как Xbox",
    "forbidden": "жив, но отказ (регион?)",
    "redirect": "перенаправление",
    "unexpected": "ответ не похож на Xbox",
    "server_error": "ошибка сервера",
    "cert": "чужой сертификат",
    "tls_fail": "обрыв TLS (блок по имени?)",
    "no_http": "нет HTTP-ответа",
    "tcp_fail": "не открывается",
}


def load(path=None):
    """Курируемый список: {домен: [{ip, source, added}, ...]}. Пустой при любой ошибке."""
    try:
        with open(path or OVERRIDES_FILE, encoding="utf-8") as f:
            data = json.load(f)
        overrides = data.get("overrides", {})
        return overrides if isinstance(overrides, dict) else {}
    except (OSError, ValueError):
        return {}


def classify(probe_result):
    """Превращает результат probe() в (статус, подпись)."""
    state = probe_result.get("state", "tcp_fail")
    return state, STATE_LABELS.get(state, state)


def verify(overrides, items, timeout=6, probe_fn=None, now=None):
    """
    Проверяет каждый кандидат против описания домена из consoles.json.
    probe_fn — подмена в тестах; по умолчанию — http_probe.probe.
    Возвращает список результатов с меткой времени (каждая строка — для лога).
    """
    from .http_probe import probe
    probe_fn = probe_fn or probe
    now = now or datetime.now()
    item_by_host = {it["host"]: it for it in items}
    results = []
    for domain, candidates in overrides.items():
        item = item_by_host.get(domain)
        if not item:
            continue
        for cand in candidates:
            res = probe_fn(cand["ip"], domain, item.get("check", "https"), timeout,
                           item.get("method", "GET"), item.get("path", "/"),
                           item.get("headers"), item.get("payload"), item.get("expected"))
            state, label = classify(res)
            results.append({
                "domain": domain, "ip": cand["ip"], "source": cand.get("source", ""),
                "status": state, "label": label, "alive": state in ALIVE_STATES,
                "ms": res.get("ms"), "text": res.get("text", ""),
                "checked_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                "rank": PROBE_RANK.get(state, 4),
            })
    return results


def summary(results):
    """«Домен: N из M живые» для заголовка и интерфейса."""
    by_domain = {}
    for r in results:
        by_domain.setdefault(r["domain"], []).append(r)
    return {d: (sum(1 for r in rs if r["alive"]), len(rs)) for d, rs in by_domain.items()}


def log_rows(results):
    """Строки CSV: каждая проверка с меткой времени — «живы ли обходы на этой неделе»."""
    return [[r["checked_at"], r["domain"], r["ip"], r["label"], r["status"],
             (r["text"] or "")[:160], r["ms"] or ""] for r in results]


def write_log(results, path=None):
    storage.write_xbox_log(log_rows(results), LOG_HEADER, path or LOG_FILE)
