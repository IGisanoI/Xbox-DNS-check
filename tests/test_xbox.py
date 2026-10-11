"""Tests for the logic part (no window, no network). Run: python -m pytest"""

from dnschecker import config, http_probe, reply, server_list, xbox

XSTS = config.DEFAULT_CONSOLES["Xbox"][0]  # the geo-blocked sign-in domain


def fake_resolve(ip):
    # Pretend the DNS server answered with this IP.
    return lambda server, host, timeout: {"ok": True, "ips": [ip], "cname": "", "error": "", "ms": 5}


def fake_probe(head):
    return lambda *args: {"state": "ok", "code": 401, "ms": 40, "text": "HTTP/1.1 401", "head": head}


def test_direct_microsoft_is_bad():
    owner = lambda ip: {"org": "Microsoft Corporation", "net": "", "country": "US", "error": ""}
    res = xbox.check_domain("8.8.8.8", XSTS, 2, fake_resolve("20.1.2.3"), fake_probe(""), owner)
    assert res["level"] == 2 and res["geo_direct"]


def test_gateway_with_microsoft_answer_is_good():
    owner = lambda ip: {"org": "Some Hosting Ltd", "net": "", "country": "DE", "error": ""}
    res = xbox.check_domain("111.88.96.54", XSTS, 2, fake_resolve("5.6.7.8"),
                            fake_probe("x-xblcorrelationid: abc"), owner)
    assert res["level"] == 0


def test_blackhole_answer():
    res = xbox.check_domain("1.1.1.1", XSTS, 2, fake_resolve("0.0.0.0"), fake_probe(""), None)
    assert res["short"].startswith("✖ заглушка")


def test_verdict_good_when_all_ok():
    items = config.DEFAULT_CONSOLES["Xbox"]
    results = {i: {"level": 0} for i in range(len(items))}
    assert xbox.verdict(items, results)["kind"] == xbox.GOOD


def test_pick_pair_prefers_same_service():
    good = [("111.88.96.54", "xbox-dns.ru"), ("8.8.8.8", "Google"), ("111.88.96.55", "xbox-dns.ru")]
    assert reply.pick_pair(good) == ("111.88.96.54", "111.88.96.55")


def test_sort_by_ip_is_numeric():
    servers = [("77.88.8.8", "Яндекс"), ("9.9.9.9", "Quad9")]
    assert server_list.sort_servers(servers, server_list.SORT_IP)[0][0] == "9.9.9.9"


def test_parse_forbidden():
    assert http_probe.parse_response(b"HTTP/1.1 403 Forbidden\r\n\r\n", 10)["state"] == "forbidden"


# --- tests for the fixes in 3.5 ---

import datetime
import os
import tempfile

from dnschecker import dns_tools, storage


def test_bad_lines_in_servers_txt_are_skipped():
    path = os.path.join(tempfile.mkdtemp(), "servers.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("8.8.8.8 Google\n8.8.8,4 Typo\n8.8.8.8 Again\n")
    assert storage.load_servers(path) == [("8.8.8.8", "Google")]


def test_resolve_with_bad_server_does_not_raise():
    res = dns_tools.resolve("8.8.8,4", "xbox.com", 1)
    assert not res["ok"] and res["ms"] == 0


def test_403_through_gateway_is_doubt():
    owner = lambda ip: {"org": "Some Hosting", "net": "", "country": "DE", "error": ""}
    probe = lambda *a: {"state": "forbidden", "code": 403, "ms": 30, "text": "", "head": "MS-CV: x"}
    res = xbox.check_domain("x", XSTS, 1, fake_resolve("5.6.7.8"), probe, owner)
    assert res["level"] == 1
    assert xbox.cell_caption(res)[2] == "шлюз, 403"


def test_whoami_without_owner_is_not_all_clear():
    w = dns_tools.whoami("8.8.8.8", 1, resolve_fn=lambda s, d, t: {"ok": True, "ips": ["9.9.9.1"]},
                         owner_fn=lambda ip: {"org": "", "net": "", "country": "", "error": "HTTP 429"})
    assert "не проверен" in w["text"]
    assert "не замечено" not in w["details"]


def test_drag_moves_only_one_server():
    order = ["a", "b", "c", "d"]          # user's own order, "b" is unchecked
    screen = ["a", "d", "c", "b"]         # "d" dragged above "c"; "b" shown at the bottom
    assert server_list.place_like(order, "d", screen) == ["a", "b", "d", "c"]


def test_history_row_lists_only_problems():
    items = config.DEFAULT_CONSOLES["Xbox"][:2]
    results = {0: {"level": 2, "short": "✖ напрямую в Microsoft", "geo_direct": True}, 1: {"level": 0}}
    v = xbox.verdict(items, results)
    row = xbox.history_row(datetime.datetime(2026, 10, 11, 12, 0), "9.9.9.9", "Quad9", v, items, results)
    assert row[:4] == ["2026-10-11 12:00:00", "9.9.9.9", "Quad9", "Не поможет"]
    assert row[5] == "Вход XBL: Microsoft"
    assert len(row) == len(xbox.HISTORY_HEADER)


# --- tests for the fixes after the review ---

import socket
import threading
import time

from dnschecker import owners


def test_quad9_partner_network_is_not_interception():
    # Real data: 9.9.9.9 is answered by 74.63.24.200 of "WoodyNet, Inc." (Packet Clearing House).
    w = dns_tools.whoami("9.9.9.9", 1, resolve_fn=lambda s, d, t: {"ok": True, "ips": ["74.63.24.200"]},
                         owner_fn=lambda ip: {"org": "WoodyNet, Inc.", "net": "", "country": "US", "error": ""})
    assert w["level"] is None and "перехват" not in w["text"]


def test_real_interception_still_found():
    w = dns_tools.whoami("8.8.8.8", 1, resolve_fn=lambda s, d, t: {"ok": True, "ips": ["5.5.5.5"]},
                         owner_fn=lambda ip: {"org": "Some ISP LLC", "net": "", "country": "RU", "error": ""})
    assert w["level"] == 1


def test_one_rdap_request_per_ip():
    calls = []

    def slow_fetch(url, timeout):
        calls.append(url)
        time.sleep(0.2)
        return {"name": "TEST", "entities": [], "country": "US"}

    owners.clear_cache()
    threads = [threading.Thread(target=owners.ip_owner, args=("192.0.2.1", 6, slow_fetch)) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1


def test_tls_timeout_has_honest_text():
    # A local server that accepts the connection but never answers TLS.
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        res = http_probe.probe("127.0.0.1", "example.com", "https", 0.5, port=port)
    finally:
        srv.close()
    assert res["state"] == "tls_fail" and "не ответил" in res["text"]
