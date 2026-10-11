"""
Готовый текст для абонента: какие DNS прописать на Xbox и где.
"""

import re


def _group(name, ip):
    """«xbox-dns.ru 1» и «xbox-dns.ru 2» — одна группа «xbox-dns.ru»."""
    base = re.sub(r"[\s\-_#№]*\d+$", "", name or "").strip().lower()
    return base or ip


def pick_pair(good_servers):
    """
    Выбирает основной и дополнительный DNS из подходящих.
      good_servers — [(ip, название), ...] в порядке таблицы
    Сначала ищем пару одного сервиса (основной + резервный сервер одного
    провайдера), иначе берём два первых подходящих.
    Возвращает (dns1, dns2) или (dns1, None), или (None, None).
    """
    if not good_servers:
        return None, None
    groups = {}
    for ip, name in good_servers:
        groups.setdefault(_group(name, ip), []).append(ip)
    for ips in groups.values():
        if len(ips) >= 2:
            return ips[0], ips[1]
    if len(good_servers) >= 2:
        return good_servers[0][0], good_servers[1][0]
    return good_servers[0][0], None


def build_reply(template, dns1, dns2):
    """
    Подставляет адреса в шаблон. Используем замену строк, а не format(),
    чтобы фигурные скобки в тексте шаблона не ломали программу.
    """
    # Empty second DNS: tell the subscriber to leave the field blank.
    second = dns2 or "оставьте поле пустым"
    return template.replace("{dns1}", dns1).replace("{dns2}", second)
