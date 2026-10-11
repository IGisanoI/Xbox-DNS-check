"""
Запросы к DNS-серверам: резолв имени и «кто на самом деле отвечает».
"""

import ipaddress
import threading
import time

import dns.exception
import dns.resolver

from . import owners
from .config import KNOWN_PUBLIC_DNS

# Max 4 parallel requests to one server, so the server does not
# start dropping our requests (rate limit).
_slots = {}
_slots_lock = threading.Lock()


def _slot(server):
    with _slots_lock:
        return _slots.setdefault(server, threading.Semaphore(4))


def resolve(server, domain, timeout):
    """
    Спрашивает у DNS-сервера IPv4-адреса домена.
    Возвращает словарь: ok, ms, ips, cname, error.
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    result = {"ok": False, "ms": None, "ips": [], "cname": "", "error": ""}
    with _slot(server):
        start = time.perf_counter()
        try:
            answer = resolver.resolve(domain, "A")
        except dns.resolver.NXDOMAIN:
            result["error"] = "домен не существует (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            result["error"] = "нет IPv4-адреса в ответе"
        except dns.resolver.NoNameservers:
            result["error"] = "сервер отказал (SERVFAIL/REFUSED)"
        except dns.exception.Timeout:
            result["error"] = "нет ответа (таймаут)"
        except Exception as e:
            result["error"] = f"ошибка: {e}"
        else:
            result["ok"] = True
            result["ips"] = [r.address for r in answer]
            if answer.canonical_name != answer.qname:
                result["cname"] = str(answer.canonical_name).rstrip(".")
        result["ms"] = (time.perf_counter() - start) * 1000
    return result


def is_blackhole(ip):
    """0.0.0.0, 127.x и подобные — так DNS обычно «блокирует» домен."""
    addr = ipaddress.ip_address(ip)
    return addr.is_unspecified or addr.is_loopback


def short_dns_error(text):
    """Короткая подпись ошибки DNS для ячейки таблицы."""
    if "NXDOMAIN" in text:
        return "нет домена"
    if "таймаут" in text:
        return "таймаут DNS"
    if "отказал" in text:
        return "DNS отказал"
    return "ошибка DNS"


def whoami(server, timeout, tries=3, resolve_fn=None, owner_fn=None):
    """
    Кто на самом деле отвечает: whoami.akamai.net возвращает адрес резолвера,
    который обратился к серверам Akamai. Если вместо Google отвечает чужая
    сеть — запросы к 8.8.8.8 по дороге перехватываются. Перехват бывает
    непостоянным, поэтому спрашиваем несколько раз и собираем всех ответивших.

    Возвращает {"text", "level", "details", "dead"}:
      level None — нейтрально, 1 — замечен перехват; dead — сервер молчит.
    """
    resolve_fn = resolve_fn or resolve
    owner_fn = owner_fn or owners.ip_owner

    seen = []
    for _ in range(tries):
        res = resolve_fn(server, "whoami.akamai.net", timeout)
        if not res["ok"]:
            continue
        for ip in res["ips"]:
            if ip not in seen:
                seen.append(ip)
    if not seen:
        return {"text": "—", "level": None, "dead": True,
                "details": f"DNS {server} не ответил ни на один из {tries} запросов."}

    expected = KNOWN_PUBLIC_DNS.get(server)
    lines, foreign = [], 0
    for ip in seen:
        info = owner_fn(ip)
        names = owners.owner_names(info)
        mark = ""
        if expected and names and expected not in names:
            foreign += 1
            mark = "   ← не " + expected.capitalize()
        lines.append(f"  {ip} — {owners.owner_text(info)}{mark}")
        if info.get("error"):
            lines.append(f"      (владелец не определён: {info['error']})")

    text = f"{seen[0]}\n{owners.owner_text(owner_fn(seen[0]))[:30]}"
    if len(seen) > 1:
        text += f"\n(и ещё {len(seen) - 1} — клик)"
    details = [f"DNS: {server}", f"Запросов: {tries}, ответили разные резолверы: {len(seen)}", ""]
    details += lines
    level = None
    if foreign:
        level = 1
        text += f"\n⚠ не {expected.capitalize()} — перехват"
        details += ["", f"Часть ответов ({foreign} из {len(seen)}) пришла не от "
                        f"{expected.capitalize()}: запросы к этому DNS по дороге перехватываются и отвечает другой сервер."]
    elif expected:
        details += ["", "Перехвата в этой проверке не замечено. Он бывает непостоянным — при сомнениях запустите проверку ещё раз."]
    else:
        # Private DNS: we just show which resolvers it uses itself.
        details += ["", "Для частных DNS (провайдерских, xbox-dns и т. п.) здесь видно, через какие резолверы они сами ходят в интернет. Это не перехват."]

    return {"text": text, "level": level, "dead": False, "details": "\n".join(details)}
