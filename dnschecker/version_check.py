"""
Проверка новой версии на GitHub (Stage 7).

Спросить у GitHub последний релиз и, если он новее нашей версии, один раз
показать уведомление со ссылкой. Никаких автообновлений: человек решает сам,
когда идти за новой версией. Любая ошибка сети/парсинга — тихий None:
наличие интернета не должно влиять на запуск программы.
"""

import json
import re
import threading
import urllib.request

REPO = "IGisanoI/Xbox-DNS-check"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"


def parse_version(tag):
    """«v5.0»/«5.0» -> (5, 0); всё остальное — None."""
    match = re.match(r"^v?(\d+)\.(\d+)$", str(tag or "").strip())
    return (int(match.group(1)), int(match.group(2))) if match else None


def is_newer(latest_tag, current):
    """True, если latest_tag — версия выше current. Непонятные теги — False."""
    latest, now = parse_version(latest_tag), parse_version(current)
    return bool(latest and now and latest > now)


def check_latest(timeout=6, fetch=None):
    """
    Последний релиз: {"tag", "url"} или None при любой неудаче.
    fetch — подмена загрузки (тесты).
    """
    try:
        req = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json",
                                                       "User-Agent": "DNS-Checker"})
        opener = fetch or (lambda r, timeout: urllib.request.urlopen(r, timeout=timeout))
        with opener(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        tag = str(data.get("tag_name", "")).strip()
        if not tag:
            return None
        return {"tag": tag, "url": data.get("html_url") or RELEASES_PAGE}
    except Exception:
        return None


def check_async(current, callback):
    """Проверяет в фоне; callback(result_or_None) вызывается всегда."""
    def _work():
        result = check_latest()
        if result and not is_newer(result["tag"], current):
            result = None  # наша версия свежее или равна: уведомлять не о чем
        callback(result)
    threading.Thread(target=_work, daemon=True).start()
