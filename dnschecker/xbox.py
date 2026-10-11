"""
Проверка, поможет ли DNS владельцу Xbox, и итоговый вердикт.

Здесь нет ничего про окна и кнопки — только логика, поэтому её легко
проверять тестами (см. tests/test_xbox.py).
"""

import ipaddress

from . import dns_tools, owners
from .config import MICROSOFT_CNAMES, MICROSOFT_NETS
from .http_probe import PROBE_RANK, probe


def microsoft_owned(ip, cname, info):
    """
    Ведёт ли адрес напрямую в Microsoft. Возвращает (да/нет, уверенно ли).
    Уверенно — когда известен владелец сети; иначе по косвенным признакам.
    """
    names = owners.owner_names(info)
    if names:
        return ("microsoft" in names or "msft" in names), True
    addr = ipaddress.ip_address(ip)
    guess = any(addr in net for net in MICROSOFT_NETS) or cname.endswith(MICROSOFT_CNAMES)
    return guess, False


def check_domain(server, item, timeout, resolve_fn=None, probe_fn=None, owner_fn=None):
    """
    Полная проверка одного домена через один DNS: резолв → подключение → оценка.
    Возвращает словарь: level (0 хорошо / 1 под вопросом / 2 плохо), short (текст
    ячейки), geo_direct, resolve, probes, owner, note.
    Функции resolve_fn/probe_fn/owner_fn подменяются в тестах.
    """
    resolve_fn = resolve_fn or dns_tools.resolve
    probe_fn = probe_fn or probe
    owner_fn = owner_fn or owners.ip_owner

    host = item["host"]
    res = resolve_fn(server, host, timeout)
    out = {"resolve": res, "probes": [], "level": 2, "short": "", "owner": None,
           "note": "", "geo_direct": False}
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

    # Try up to two addresses and keep the best result.
    best = None
    for ip in real_ips[:2]:
        p = probe_fn(ip, host, mode, timeout, item.get("method", "GET"), item.get("path", "/"))
        p["ip"] = ip
        out["probes"].append(p)
        if best is None or PROBE_RANK[p["state"]] < PROBE_RANK[best["state"]]:
            best = p
        if p["state"] == "ok":
            break

    state = best["state"]
    if state in ("ok", "forbidden") and item.get("geo"):
        return _judge_geo(out, best, res["cname"], owner_fn)
    if state == "ok":
        out["level"], out["short"] = 0, f"✔ {best['code']}  {best['ms']:.0f} мс"
    elif state == "forbidden":
        out["level"], out["short"] = 1, f"⚠ {best['code']} отказ"
    else:
        out["short"] = {"cert": "✖ чужой сертификат", "tls_fail": "✖ обрыв TLS",
                        "no_http": "✖ нет ответа HTTP"}.get(state, "✖ недоступен")
    return out


def _judge_geo(out, best, cname, owner_fn):
    """
    Для сервисов, закрытых по региону, важно, КУДА ведёт адрес.
    Напрямую в Microsoft — консоль придёт с российским IP и получит отказ.
    На сторонний шлюз с настоящим сертификатом и ответом Microsoft — обход работает.
    """
    info = owner_fn(best["ip"])
    out["owner"] = info
    direct, sure = microsoft_owned(best["ip"], cname, info)
    from_ms = any(h in best.get("head", "").lower() for h in ("x-xblcorrelationid", "ms-cv"))
    who = owners.owner_text(info)
    if direct:
        out["level"], out["geo_direct"] = 2, True
        out["short"] = "✖ напрямую в Microsoft\n(блок по региону)"
        out["note"] = ("Адрес принадлежит Microsoft" + ("" if sure else " (по косвенным признакам)")
                       + ". Консоль подключится к Microsoft напрямую с российского IP абонента и получит отказ по региону (0x80a40401).")
    elif from_ms:
        out["level"] = 0 if sure else 1
        out["short"] = f"✔ через шлюз\n{who[:24]}"
        out["note"] = (f"Адрес не принадлежит Microsoft ({who}), сертификат настоящий, "
                       "ответ пришёл от Microsoft — значит, это шлюз, и Microsoft увидит "
                       "его адрес, а не российский IP абонента. Обход работает."
                       + ("" if sure else "\nВладелец адреса не определён — проверьте вручную."))
    else:
        out["level"] = 1
        out["short"] = "⚠ шлюз, но ответ\nне от Microsoft"
        out["note"] = (f"Адрес не принадлежит Microsoft ({who}), но в ответе нет признаков сервера Microsoft. "
                       "Возможно, шлюз не работает или отвечает заглушкой.")
    return out

# Verdict kinds for one DNS server.
GOOD, DOUBT, BAD, DEAD = "good", "doubt", "bad", "dead"


def verdict(items, results, who=None):
    """
    Итог по одному DNS.
      items   — список доменов (из consoles.json)
      results — {номер домена: результат check_domain}
      who     — результат whoami (если есть)
    Возвращает {"kind": good|doubt|bad|dead, "label": короткий итог,
                "reason": пояснение или "", "text": label и reason одной подписью}.
    """
    if who and who.get("dead") and results and all(
            r.get("short", "").startswith("✖ таймаут DNS") for r in results.values()):
        return _verdict(DEAD, "Не отвечает", "закрыт для этой сети?")

    crit_fail = crit_warn = other = geo_direct = 0
    for i, item in enumerate(items):
        res = results.get(i, {})
        level = res.get("level", 2)
        geo_direct += bool(item.get("geo") and res.get("geo_direct"))
        if item.get("critical"):
            crit_fail += level == 2
            crit_warn += level == 1
        else:
            other += level > 0

    if geo_direct:
        return _verdict(BAD, "Не поможет", "вход напрямую в Microsoft")
    if crit_fail:
        return _verdict(BAD, "Не поможет", f"критичных проблем: {crit_fail + crit_warn}")
    if crit_warn:
        return _verdict(DOUBT, "Под вопросом", f"сомнительных проверок: {crit_warn}")
    if other:
        return _verdict(GOOD, "Поможет", f"второстепенных проблем: {other}")
    return _verdict(GOOD, "Поможет", "")


def _verdict(kind, label, reason):
    text = f"{label}\n({reason})" if reason else label
    return {"kind": kind, "label": label, "reason": reason, "text": text}


def column_title(item):
    """Подпись столбца: поле short из consoles.json или начало имени домена."""
    return item.get("short") or item["host"].split(".")[0]


def cell_caption(res):
    """
    Короткая подпись для ячейки таблицы: (уровень, значок, текст).
    Подробности — по клику, здесь только самое главное.
    """
    level = res.get("level", 2)
    icon = {0: "✓", 1: "!", 2: "✕"}[level]
    short = res.get("short", "")
    if res.get("geo_direct"):
        return level, icon, "Microsoft"
    if "через шлюз" in short:
        return level, icon, "шлюз"
    if "шлюз" in short:
        return level, icon, "шлюз?"
    if level == 0:
        return level, icon, "OK"
    for key, caption in (("таймаут", "таймаут"), ("нет домена", "нет домена"),
                         ("DNS отказал", "DNS отказ"), ("заглушка", "заглушка"),
                         ("сертификат", "сертификат"), ("TLS", "обрыв TLS"),
                         ("HTTP", "нет HTTP"), ("недоступен", "недоступен"), ("отказ", "отказ 403")):
        if key in short:
            return level, icon, caption
    return level, icon, "ошибка"


def changes(previous, current, names):
    """
    Что изменилось между двумя проверками (для наблюдения в фоне).
      previous, current — {ip: kind}; names — {ip: название}
    Возвращает список строк. Интересно только «стал / перестал помогать».
    """
    out = []
    for ip, kind in current.items():
        before = previous.get(ip)
        if before is None or (before == GOOD) == (kind == GOOD):
            continue
        label = f"{names.get(ip) or ip} ({ip})"
        if kind == GOOD:
            out.append(f"✔ {label} снова помогает")
        else:
            out.append(f"✖ {label} перестал помогать")
    return out
