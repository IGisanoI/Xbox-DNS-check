"""
Список DNS-серверов, общий для обеих вкладок: порядок, добавление,
удаление, перестановка и сортировка.

Здесь нет ничего про окна: модель хранит «свой порядок» пользователя
(он же сохраняется в servers.txt), а сортировка только выдаёт другой
порядок для показа и сам список не меняет.
"""

import ipaddress

from . import storage

SORT_CUSTOM, SORT_NAME, SORT_IP, SORT_RESULT = "custom", "name", "ip", "result"


class ServerList:
    """
    Список (ip, название) в пользовательском порядке.
    После каждого изменения список сохраняется и вызываются подписчики.
    """

    def __init__(self, servers, save=None):
        self._items = list(servers)
        self._save = save or storage.save_servers  # tests pass their own save function
        self._listeners = []

    def items(self):
        return list(self._items)

    def ips(self):
        return [ip for ip, _ in self._items]

    def subscribe(self, callback):
        self._listeners.append(callback)

    def add(self, ip, name):
        """Добавляет сервер в конец. Возвращает False, если такой IP уже есть."""
        if ip in self.ips():
            return False
        self._items.append((ip, name))
        self._changed()
        return True

    def rename(self, ip, name):
        """Меняет название сервера, не трогая его место в списке."""
        name = name.strip()
        new = [(i, name if i == ip else n) for i, n in self._items]
        if new != self._items:
            self._items = new
            self._changed()

    def remove(self, ips):
        ips = set(ips)
        kept = [s for s in self._items if s[0] not in ips]
        if len(kept) != len(self._items):
            self._items = kept
            self._changed()

    def set_order(self, ips):
        """
        Задаёт новый порядок по списку IP. Неизвестные IP пропускаются,
        забытые — остаются в конце, так что серверы никогда не теряются.
        """
        by_ip = dict(self._items)
        new = [(ip, by_ip[ip]) for ip in dict.fromkeys(ips) if ip in by_ip]
        listed = {ip for ip, _ in new}
        new += [s for s in self._items if s[0] not in listed]
        if new != self._items:
            self._items = new
            self._changed()

    def _changed(self):
        self._save(self._items)
        for callback in self._listeners:
            callback()


def move(order, item, index):
    """Новый список, в котором item стоит на позиции index (для перетаскивания)."""
    rest = [x for x in order if x != item]
    rest.insert(max(0, min(index, len(rest))), item)
    return rest


def place_like(order, item, display):
    """
    Moves only item inside order: next to the row it now stands next to on screen.
    All other items keep their places. Needed because the screen order is not
    the user's order (unchecked servers are shown at the bottom).
    """
    rest = [x for x in order if x != item]
    i = display.index(item)
    if i + 1 < len(display) and display[i + 1] in rest:
        pos = rest.index(display[i + 1])           # before the row below it
    elif i > 0 and display[i - 1] in rest:
        pos = rest.index(display[i - 1]) + 1       # after the row above it
    else:
        pos = len(rest)
    rest.insert(pos, item)
    return rest


def _ip_key(ip):
    # Sort IPs as numbers (so 9.9.9.9 goes before 77.88.8.8); bad text goes last.
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (99, 0)


def sort_servers(servers, mode, rank=None, unchecked=()):
    """
    Порядок для показа.
      servers   — [(ip, название)] в своём порядке
      mode      — SORT_CUSTOM | SORT_NAME | SORT_IP | SORT_RESULT
      rank      — {ip: значение} для сортировки по результату (меньше — выше);
                  серверы без результата идут в конце
      unchecked — IP без галочки: они всегда ниже отмеченных
    Сортировка устойчивая: при равенстве сохраняется свой порядок.
    """
    if mode == SORT_NAME:
        result = sorted(servers, key=lambda s: (s[1] or s[0]).casefold())
    elif mode == SORT_IP:
        result = sorted(servers, key=lambda s: _ip_key(s[0]))
    elif mode == SORT_RESULT:
        rank = rank or {}
        result = sorted(servers, key=lambda s: (0, rank[s[0]]) if s[0] in rank else (1,))
    else:
        result = list(servers)
    return sorted(result, key=lambda s: s[0] in unchecked)
