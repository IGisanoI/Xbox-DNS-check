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
