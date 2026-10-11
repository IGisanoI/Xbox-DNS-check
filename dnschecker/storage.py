"""
Чтение и запись файлов программы: серверы, домены, настройки, шаблон, лог.

Функции принимают путь к файлу (по умолчанию — рядом с программой),
поэтому тесты могут работать во временной папке.
"""

import copy
import csv
import ipaddress
import json
import os

from . import paths
from .config import CONSOLES_VERSION, DEFAULT_CONSOLES, DEFAULT_REPLY_TEMPLATE, DEFAULT_SERVERS

# --- servers.txt ---


def load_servers(path=None):
    """
    Список (ip, название) из servers.txt. Если файла нет — создаём его
    из встроенного списка, чтобы он сразу лежал рядом с программой.
    """
    path = path or paths.SERVERS_FILE
    if not os.path.exists(path):
        try:
            save_servers(DEFAULT_SERVERS, path)
        except OSError:
            pass  # read-only folder: just work with the built-in list
        return list(DEFAULT_SERVERS)
    servers = []
    seen = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()  # "#" starts a comment
            if not line:
                continue
            parts = line.split(maxsplit=1)
            # A typo like "8.8.8,4" is skipped: a bad address used to stop
            # the whole check on the "Серверы" tab.
            try:
                ip = str(ipaddress.ip_address(parts[0]))
            except ValueError:
                continue
            if ip in seen:  # the same IP twice would break the table (IP is the row id)
                continue
            seen.add(ip)
            servers.append((ip, parts[1] if len(parts) > 1 else ""))
    return servers


def save_servers(servers, path=None):
    path = path or paths.SERVERS_FILE
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Список DNS-серверов: адрес и (необязательно) название\n")
        for ip, name in servers:
            f.write(f"{ip:<16} {name}".rstrip() + "\n")

# --- consoles.json ---


def _profiles(data):
    """Убирает служебные ключи (начинаются с «_»), оставляет консоли."""
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _write_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_consoles(path=None):
    """
    Списки доменов из consoles.json.
    Возвращает (профили, сообщение для строки состояния, предупреждение об ошибке).
    Нет файла — создаём; файл старой версии — обновляем, старый кладём в .bak.
    """
    path = path or paths.CONSOLES_FILE
    defaults = _profiles(copy.deepcopy(DEFAULT_CONSOLES))
    if not os.path.exists(path):
        try:
            _write_json(DEFAULT_CONSOLES, path)
        except OSError:
            pass
        return defaults, "", ""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not _profiles(data):
            raise ValueError("ожидался словарь «консоль: список доменов»")
    except (OSError, ValueError) as e:
        return defaults, "", f"Не удалось прочитать consoles.json:\n{e}\n\nИспользую встроенные списки."
    if data.get("_version", 1) < CONSOLES_VERSION:
        # Old file: keep a backup and write the new built-in list.
        try:
            os.replace(path, path + ".bak")
            _write_json(DEFAULT_CONSOLES, path)
            return (defaults, "Списки доменов обновлены (старый consoles.json сохранён как consoles.json.bak)",
                    "")
        except OSError:
            return defaults, "", ""
    return _profiles(data), "", ""

# --- settings.json ---


def load_settings(path=None):
    """Настройки окна и вкладок; при любой ошибке — пустой словарь."""
    path = path or paths.SETTINGS_FILE
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(settings, path=None):
    path = path or paths.SETTINGS_FILE
    try:
        _write_json(settings, path)
    except OSError:
        pass

# --- reply_template.txt ---


def load_reply_template(path=None):
    """Текст из reply_template.txt; если файла нет — создаём из встроенного."""
    path = path or paths.REPLY_TEMPLATE_FILE
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if text.strip():
            return text
    except OSError:
        pass
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_REPLY_TEMPLATE)
    except OSError:
        pass
    return DEFAULT_REPLY_TEMPLATE

# --- dns_log.csv ---


def write_log(rows, path=None):
    """Дописывает результаты в CSV (открывается в Excel)."""
    _append_csv(rows, ["Время", "Сервер", "Название", "Домен", "Статус", "мс", "Ответ"],
                path or paths.LOG_FILE)


def write_xbox_log(rows, header, path=None):
    """Дописывает историю проверок вкладки «Xbox» в xbox_log.csv."""
    _append_csv(rows, header, path or paths.XBOX_LOG_FILE)


def _append_csv(rows, header, path):
    new_file = not os.path.exists(path)
    # utf-8-sig + ";" — so Excel opens Russian text correctly.
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        if new_file:
            w.writerow(header)
        w.writerows(rows)
