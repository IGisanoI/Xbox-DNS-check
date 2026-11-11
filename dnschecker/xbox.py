"""
Сетевые проверки Xbox и осторожный итог по каждому DNS.

Здесь нет окон и кнопок. Сетевой ответ не выдаётся за подтверждённый вход на
консоли: это отдельный вид доказательства, который добавляет пользователь.
"""

import ipaddress

from . import dns_tools, owners
from .config import MICROSOFT_CNAMES, MICROSOFT_NETS
from .http_probe import PROBE_RANK, probe


def microsoft_owned(ip, cname, info):
    """Похоже ли, что адрес ведёт напрямую в Microsoft. Возвращает (да/нет, уверенность)."""
    names = owners.owner_names(info)
    if names:
        return ("microsoft" in names or "msft" in names), True
    addr = ipaddress.ip_address(ip)
    guess = any(addr in net for net in MICROSOFT_NETS) or cname.endswith(MICROSOFT_CNAMES)
    return guess, False


def check_domain(server, item, timeout, resolve_fn=None, probe_fn=None, owner_fn=None):
    """
    Полная проверка одного домена через один DNS: резолв → подключение → оценка.
    level: 0 — ожидаемый ответ, 1 — нужна проверка, 2 — сетевая проблема.
    candidate/direct_unknown содержат предположения, а не подтверждение на консоли.
    """
    resolve_fn = resolve_fn or dns_tools.resolve
    probe_fn = probe_fn or probe
    owner_fn = owner_fn or owners.ip_owner

    host = item["host"]
    for _attempt in range(2):  # one retry for a lost UDP answer
        res = resolve_fn(server, host, timeout)
        if res["ok"] or "таймаут" not in res.get("error", ""):
            break
    out = {"resolve": res, "probes": [], "level": 2, "short": "", "owner": None,
           "note": "", "geo_direct": False, "candidate": False, "direct_unknown": False}
    if not res["ok"]:
        out["short"] = "✖ " + dns_tools.short_dns_error(res["error"])
        return out
    real_ips = [ip for ip in res["ips"] if not dns_tools.is_blackhole(ip)]
    if not real_ips:
        out["short"] = f"✖ заглушка {res['ips'][0]}"
        return out
    mode = item.get("check", "https")
    if mode == "dns":
        out["level"], out["short"] = 0, "✔ резолвится"
        return out

    # Try up to two addresses, with one retry for transient connection failures.
    best = None
    for ip in real_ips[:2]:
        for attempt in range(2):
            p = probe_fn(ip, host, mode, timeout, item.get("method", "GET"), item.get("path", "/"),
                         item.get("headers"), item.get("payload"), item.get("expected"))
            p["ip"], p["attempt"] = ip, attempt + 1
            out["probes"].append(p)
            if best is None or PROBE_RANK.get(p["state"], 4) < PROBE_RANK.get(best["state"], 4):
                best = p
            if p["state"] == "ok" or p["state"] not in ("tcp_fail", "tls_fail", "no_http"):
                break
        if best["state"] == "ok":
            break

    state = best["state"]
    if state in ("ok", "forbidden") and item.get("geo"):
        return _judge_geo(out, best, res["cname"], owner_fn)
    if state == "ok":
        out["level"], out["short"] = 0, f"✔ {best['code']}  {best['ms']:.0f} мс"
    elif state == "forbidden":
        out["level"], out["short"] = 1, f"⚠ {best['code']} отказ"
    elif state == "redirect":
        out["level"], out["short"] = 1, f"⚠ перенаправление {best['code']}"
    elif state == "unexpected":
        out["level"], out["short"] = 1, f"⚠ неожиданный HTTP {best['code']}"
    elif state == "server_error":
        out["short"] = f"✖ ошибка сервера {best['code']}"
    else:
        out["short"] = {"cert": "✖ чужой сертификат", "tls_fail": "✖ обрыв TLS",
                        "no_http": "✖ нет ответа HTTP"}.get(state, "✖ недоступен")
    return out


def _judge_geo(out, best, cname, owner_fn):
    """
    Оценивает сетевой путь, но не выдумывает региональный результат.
    Владелец IP и заголовки Microsoft — улики. Реальный вход и внешний адрес
    шлюза без полной аутентификации или отчёта с консоли не проверить.
    """
    info = owner_fn(best["ip"])
    out["owner"] = info
    direct, sure = microsoft_owned(best["ip"], cname, info)
    from_ms = any(h in best.get("head", "").lower() for h in ("x-xblcorrelationid", "ms-cv"))
    who = owners.owner_text(info)
    ownership_note = "" if sure else " (по косвенным признакам)"
    if direct:
        out["level"], out["direct_unknown"] = 1, True
        if best["state"] == "forbidden":
            out["short"] = f"⚠ прямой отказ {best.get('code', 403)}\nрегион не доказан"
            out["note"] = ("Адрес принадлежит Microsoft" + ownership_note + ". Сервис ответил отказом "
                           f"{best.get('code', 403)}. Это может быть региональное или другое ограничение; "
                           "без корректных токенов причину определить нельзя.")
        else:
            out["short"] = "⚠ напрямую в Microsoft\nрегион не проверен"
            out["note"] = ("Адрес принадлежит Microsoft" + ownership_note + ". Получен ожидаемый ответ "
                           "на запрос без настоящих токенов. Региональные правила и реальный вход "
                           "на консоли этот запрос не проверяет.")
    elif from_ms and best["state"] == "forbidden":
        out["level"] = 1
        out["short"] = f"⚠ шлюз, но отказ {best.get('code', 403)}\n{who[:24]}"
        out["note"] = (f"Адрес не принадлежит Microsoft ({who}), ответ похож на ответ Microsoft, "
                       f"но с кодом {best.get('code', 403)}. Причина отказа и внешний адрес шлюза "
                       "неизвестны. Нужна проверка на консоли.")
    elif from_ms:
        out["level"], out["candidate"] = 1, True
        out["short"] = f"⚠ возможен шлюз\n{who[:24]}"
        out["note"] = (f"Адрес не принадлежит Microsoft ({who}), сертификат настоящий, "
                       "а ответ похож на ответ Microsoft. Это кандидат на шлюз, но его внешний "
                       "адрес и успешный вход в Xbox не подтверждены."
                       + ("" if sure else "\nВладелец адреса не определён — уверенность ниже."))
    else:
        out["level"] = 1
        out["short"] = "⚠ шлюз, но ответ\nне похож на Microsoft"
        out["note"] = (f"Адрес не принадлежит Microsoft ({who}), но в ответе нет признаков сервера Microsoft. "
                       "Возможно, шлюз не работает или отвечает заглушкой.")
    return out


# Verdict kinds for one DNS server.
GOOD, DOUBT, BAD, DEAD = "good", "doubt", "bad", "dead"


def verdict(items, results, who=None):
    """Итог по сетевым проверкам одного DNS, без обещания результата на консоли."""
    if who and who.get("dead") and results and all(
            r.get("short", "").startswith("✖ таймаут DNS") for r in results.values()):
        return _verdict(DEAD, "Не отвечает", "закрыт для этой сети?")

    crit_fail = crit_warn = other = 0
    candidate = direct_unknown = False
    for i, item in enumerate(items):
        res = results.get(i, {})
        level = res.get("level", 2)
        if item.get("geo"):
            candidate = candidate or bool(res.get("candidate"))
            direct_unknown = direct_unknown or bool(res.get("direct_unknown"))
        if item.get("critical"):
            crit_fail += level == 2
            crit_warn += level == 1
        else:
            other += level > 0

    if crit_fail:
        return _verdict(BAD, "Не подходит", f"критичных проблем: {crit_fail + crit_warn}")
    if candidate:
        reason = "кандидат с этого ПК; нужна проверка на консоли"
        if other:
            reason += f"; второстепенных проблем: {other}"
        return _verdict(GOOD, "Стоит попробовать", reason)
    if direct_unknown:
        return _verdict(DOUBT, "Регион неясен", "прямой ответ Microsoft")
    if crit_warn:
        return _verdict(DOUBT, "Под вопросом", f"сомнительных проверок: {crit_warn}")
    if other:
        return _verdict(GOOD, "Стоит попробовать", f"второстепенных проблем: {other}")
    return _verdict(GOOD, "Стоит попробовать", "по сетевым проверкам с этого ПК")


def _verdict(kind, label, reason):
    text = f"{label}\n({reason})" if reason else label
    return {"kind": kind, "label": label, "reason": reason, "text": text}


def column_title(item):
    """Подпись столбца: поле short из consoles.json или начало имени домена."""
    return item.get("short") or item["host"].split(".")[0]


def cell_caption(res):
    """Короткая подпись для ячейки таблицы: (уровень, значок, текст)."""
    level = res.get("level", 2)
    icon = {0: "✓", 1: "!", 2: "✕"}[level]
    short = res.get("short", "")
    if res.get("direct_unknown") or "напрямую" in short or "прямой отказ" in short:
        return level, icon, "Microsoft"
    if "возможен шлюз" in short:
        return level, icon, "шлюз?"
    if "шлюз" in short and "отказ" in short:
        return level, icon, "шлюз, 403"
    if "шлюз" in short:
        return level, icon, "шлюз?"
    if level == 0:
        return level, icon, "OK"
    for key, caption in (("таймаут", "таймаут"), ("нет домена", "нет домена"),
                         ("DNS отказал", "DNS отказ"), ("заглушка", "заглушка"),
                         ("сертификат", "сертификат"), ("TLS", "обрыв TLS"),
                         ("ошибка сервера", "HTTP 5xx"), ("неожиданный", "HTTP?"),
                         ("перенаправление", "редирект"), ("HTTP", "нет HTTP"),
                         ("недоступен", "недоступен"), ("отказ", "отказ 403")):
        if key in short:
            return level, icon, caption
    return level, icon, "ошибка"


def changes(previous, current, names):
    """Изменения кандидатов для наблюдения, без утверждения об успехе на консоли."""
    out = []
    for ip, kind in current.items():
        before = previous.get(ip)
        if before is None or (before == GOOD) == (kind == GOOD):
            continue
        label = f"{names.get(ip) or ip} ({ip})"
        if kind == GOOD:
            out.append(f"✔ {label} снова стал кандидатом")
        else:
            out.append(f"✖ {label} больше не выглядит кандидатом")
    return out


# Columns of xbox_log.csv (history of checks on the "Xbox" tab).
HISTORY_HEADER = ["Время", "DNS", "Название", "Итог", "Причина", "Проблемные проверки",
                  "Кто отвечает", "Запуск", "ID запуска", "Тип сети", "Сеть", "Организация сети"]


def history_row(when, ip, name, v, items, results, who=None, from_monitor=False,
                run_id="", network=None):
    """One history row. Network and console feedback are deliberately separate evidence."""
    problems = []
    for i, item in enumerate(items):
        res = results.get(i)
        if res is None:
            continue
        level, _icon, caption = cell_caption(res)
        if level > 0:
            problems.append(f"{column_title(item)}: {caption}")
    who_text = who["text"].replace("\n", " · ") if who else ""
    network = network or {}
    return [when.strftime("%Y-%m-%d %H:%M:%S"), ip, name, v["label"], v["reason"],
            "; ".join(problems), who_text, "наблюдение" if from_monitor else "вручную",
            run_id, network.get("type", ""), network.get("label", ""), network.get("org", "")]
