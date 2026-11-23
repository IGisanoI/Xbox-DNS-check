"""
Статистика из общей таблицы (Stage 5): «известно-хорошие» DNS.

Читает агрегаты из облачного приёмника (тот же endpoint и токен, что для отчётов),
кэширует их в stats_cache.json рядом с программой. Работает на устаревшем кэше
без сети и честно сдаётся («нет данных»), если кэша нет — приложение при этом
работает ровно как раньше.
"""

import json
import os
import threading
import time
import urllib.parse
import urllib.request

from . import paths

CACHE_TTL = 6 * 3600  # 6 часов: статистика не меняется быстро
STATS_CACHE_FILE = paths.path("stats_cache.json")

_lock = threading.Lock()
_state = {"stats": None, "source": "none", "loaded": False}

OUTCOME_OK = "worked"


def fetch_stats(timeout=8, fetch=None):
    """GET агрегатов с endpoint. Только числа и перечисления — сервер уже всё отфильтровал."""
    from . import feedback
    config = feedback.load_cloud_config()  # RuntimeError, если облако не настроено
    url = config["endpoint"] + "?token=" + urllib.parse.quote(config["token"])
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "DNS-Checker"})
    opener = fetch or (lambda r, timeout: urllib.request.urlopen(r, timeout=timeout))
    with opener(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    if data.get("ok") is not True:
        raise RuntimeError(str(data.get("error", "облако отклонило запрос статистики")))
    return data["stats"]


def save_cache(stats, path=None):
    """Атомарно сохраняет свежую сводку (время внутри — чтобы не подменили)."""
    payload = {"fetched_at": time.time(), "stats": stats}
    tmp = (path or STATS_CACHE_FILE) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, path or STATS_CACHE_FILE)


def load_cache(path=None):
    """Кэш любой свежести: устаревшая статистика лучше «нет данных». Ошибки — как пусто."""
    try:
        with open(path or STATS_CACHE_FILE, encoding="utf-8") as f:
            payload = json.load(f)
        stats = payload.get("stats")
        return stats if isinstance(stats, dict) else None
    except (OSError, ValueError):
        return None


def get_stats(timeout=8, fetch=None):
    """
    Сводка и её происхождение: ("live", stats) — свежий ответ облака,
    ("cache", stats) — только кэш (сеть недоступна), ("none", None) — ничего нет.
    Результат запоминается: повторные вызовы в этом запуске дешёвые.
    fetch — подмена загрузки (тесты).
    """
    with _lock:
        if _state["loaded"]:
            return _state["source"], _state["stats"]
        _state["loaded"] = True
    stats = None
    try:
        stats = fetch_stats(timeout=timeout, fetch=fetch)
        try:
            save_cache(stats)
        except OSError:
            pass  # кэш — оптимизация, его отказ никому не мешает
        source = "live"
    except Exception:
        stats = load_cache()
        source = "cache" if stats is not None else "none"
    with _lock:
        _state["stats"], _state["source"] = stats, source
    return source, stats


def reset():
    """Сбрасывает запомненное состояние (тесты)."""
    with _lock:
        _state.update({"stats": None, "source": "none", "loaded": False})


def recommendations(stats, org="", limit=3):
    """
    DNS из сводки, отсортированные для предложения: сначала подтверждённые
    в сети текущего абонента (org совпал), затем по доле успеха и числу отчётов.
    Только то, что разрешил сервер (min_group уже применён): предлагаем,
    ничего не применяя автоматически.
    """
    if not stats:
        return []
    groups = stats.get("by_dns") or []
    org_set = {c["dns"] for c in (stats.get("by_dns_org") or []) if c.get("org") == org and org}
    ranked = sorted(groups,
                    key=lambda g: (g["dns"] in org_set, g.get("success_rate", 0), g.get("reports", 0)),
                    reverse=True)
    out = []
    for g in ranked[:limit]:
        out.append({
            "dns": g["dns"],
            "reports": g.get("reports", 0),
            "worked": g.get("worked", 0),
            "success_rate": g.get("success_rate", 0),
            "last_report": g.get("last_report", ""),
            "org_match": g["dns"] in org_set,
        })
    return out


def label(rec):
    """Честная подпись без магических чисел: «подтверждено: 2 из 3»."""
    return f"подтверждено: {rec['worked']} из {rec['reports']}"
