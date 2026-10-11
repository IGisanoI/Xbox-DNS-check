"""
Владелец IP-адреса: через публичный сервис RDAP (данные регистраторов IP).

Ответы кэшируются в памяти и на диске (ip_owners.json, на 7 дней):
владельцы адресов меняются редко, а сервисы RDAP ограничивают частоту запросов.
"""

import json
import threading
import time
import urllib.error
import urllib.request

from . import paths

CACHE_TTL = 7 * 24 * 3600  # 7 days
RDAP_SOURCES = ("https://rdap.org/ip/{ip}", "https://rdap.db.ripe.net/ip/{ip}")

_cache = {}
_lock = threading.Lock()
_dirty = False  # True = the cache changed and must be saved to disk
# Max 2 RDAP requests at the same time: the services block us for too many requests.
_gate = threading.Semaphore(2)

# --- cache on disk ---


def load_cache(path=None):
    """Загружает сохранённых владельцев, отбрасывая устаревшие записи."""
    global _dirty
    path = path or paths.OWNERS_CACHE_FILE
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    now = time.time()
    with _lock:
        for ip, info in data.items():
            if isinstance(info, dict) and now - info.get("ts", 0) < CACHE_TTL:
                _cache[ip] = info
        _dirty = False


def save_cache(path=None):
    """Сохраняет кэш на диск, если в нём что-то поменялось."""
    global _dirty
    path = path or paths.OWNERS_CACHE_FILE
    with _lock:
        if not _dirty:
            return
        snapshot = dict(_cache)
        _dirty = False
    # Write outside the lock, so other threads don't wait for the disk.
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def clear_cache():
    global _dirty
    with _lock:
        _cache.clear()
        _dirty = False

# --- RDAP requests ---


def _fetch_rdap(url, timeout):
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": "DNS-Checker"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def ip_owner(ip, timeout=6, fetch=None):
    """
    Возвращает {"org", "net", "country", "error"} — кому принадлежит сеть с этим IP.
    fetch — функция загрузки (подменяется в тестах).
    """
    global _dirty
    fetch = fetch or _fetch_rdap
    with _lock:
        if ip in _cache:
            return _cache[ip]

    errors, data = [], None
    with _gate:
        for url in RDAP_SOURCES:
            source = url.split("/")[2]
            for attempt in range(3):
                try:
                    data = fetch(url.format(ip=ip), timeout)
                    break
                except urllib.error.HTTPError as e:
                    errors.append(f"{source}: HTTP {e.code}")
                    if e.code == 429 and attempt < 2:  # too many requests: wait and retry
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    break
                except Exception as e:
                    errors.append(f"{source}: {e}")
                    break
            if data:
                break

    if not data:
        # Errors are not cached: next time we try again.
        return {"org": "", "net": "", "country": "", "error": "; ".join(errors) or "нет ответа"}

    info = {"org": rdap_org(data), "net": data.get("name", "") or "",
            "country": data.get("country", "") or "", "error": "", "ts": time.time()}
    with _lock:
        _cache[ip] = info
        _dirty = True
    return info


def _vcard_value(entity, key):
    vcard = entity.get("vcardArray")
    if vcard and len(vcard) > 1:
        for field in vcard[1]:
            if field and field[0] == key and len(field) > 3 and field[3]:
                return str(field[3])
    return ""


def rdap_org(data):
    """
    Название организации-владельца из ответа RDAP. Служебные записи вида
    «MNT-SELECTEL» пропускаем: это учётка для правки базы, а не компания.
    """
    fallback = ""
    for ent in data.get("entities", []) or []:
        name = _vcard_value(ent, "fn")
        handle = (ent.get("handle") or "").upper()
        if not name or "MNT" in handle.replace("_", "-").split("-"):
            continue
        if _vcard_value(ent, "kind") == "org" or handle.startswith("ORG-"):
            return name
        if "registrant" in (ent.get("roles") or []) and not fallback:
            fallback = name
    return fallback


def owner_text(info):
    """Короткая подпись владельца: «Selectel Ltd. (RU)»."""
    if info.get("error") and not info.get("org") and not info.get("net"):
        return "владелец неизвестен"
    name = info.get("org") or info.get("net") or "?"
    return f"{name} ({info['country']})" if info.get("country") else name


def owner_names(info):
    """Всё, что известно о владельце, одной строкой в нижнем регистре — для поиска."""
    return f"{info.get('org', '')} {info.get('net', '')}".lower().strip()
