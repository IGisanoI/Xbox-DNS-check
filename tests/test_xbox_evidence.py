"""Retries and verdicts must distinguish network evidence from console proof."""

from dnschecker import config, xbox


XSTS = config.DEFAULT_CONSOLES["Xbox"][0]
OWNER = {"org": "Some Hosting Ltd", "net": "", "country": "DE", "error": ""}


def resolve(ip="5.6.7.8"):
    return lambda server, host, timeout: {"ok": True, "ips": [ip], "cname": "", "error": "", "ms": 4}


def ok_probe(*args):
    return {"state": "ok", "code": 401, "ms": 20, "text": "HTTP/1.1 401",
            "category": "expected", "head": "MS-CV: test", "body": ""}


def test_transient_tcp_failure_is_retried_once():
    calls = []

    def sometimes(*args):
        calls.append(args)
        if len(calls) == 1:
            return {"state": "tcp_fail", "code": None, "ms": 1, "text": "timeout", "head": ""}
        return ok_probe()

    result = xbox.check_domain("111.88.96.54", XSTS, 1, resolve(), sometimes, lambda ip: OWNER)
    assert len(calls) == 2
    assert [p["attempt"] for p in result["probes"]] == [1, 2]
    assert result["candidate"]


def test_expected_response_is_not_retried():
    calls = []

    def probe(*args):
        calls.append(args)
        return ok_probe()

    result = xbox.check_domain("111.88.96.54", XSTS, 1, resolve(), probe, lambda ip: OWNER)
    assert len(calls) == 1 and result["candidate"]


def test_timeout_dns_answer_is_retried_once():
    calls = []

    def resolver(server, host, timeout):
        calls.append(server)
        if len(calls) == 1:
            return {"ok": False, "ips": [], "cname": "", "error": "таймаут DNS", "ms": 1000}
        return {"ok": True, "ips": ["5.6.7.8"], "cname": "", "error": "", "ms": 5}

    result = xbox.check_domain("111.88.96.54", XSTS, 1, resolver, ok_probe, lambda ip: OWNER)
    assert len(calls) == 2 and result["candidate"]


def test_direct_microsoft_verdict_does_not_claim_bypass():
    items = [XSTS]
    results = {0: {"level": 1, "direct_unknown": True}}
    verdict = xbox.verdict(items, results)
    assert verdict["kind"] == xbox.DOUBT and verdict["label"] == "Регион неясен"


def test_legacy_geo_direct_flag_is_not_console_proof():
    verdict = xbox.verdict([XSTS], {0: {"level": 1, "geo_direct": True}})
    assert verdict["label"] == "Под вопросом"


def test_real_critical_failure_is_not_suitable():
    verdict = xbox.verdict([XSTS], {0: {"level": 2, "short": "✖ недоступен"}})
    assert verdict["kind"] == xbox.BAD and verdict["label"] == "Не подходит"


def test_candidate_beats_secondary_problem_but_still_needs_console():
    items = [XSTS, {"host": "www.xbox.com", "short": "Сайт", "critical": False}]
    results = {0: {"level": 1, "candidate": True}, 1: {"level": 2}}
    verdict = xbox.verdict(items, results)
    assert verdict["label"] == "Стоит попробовать"
    assert "консоли" in verdict["reason"] and "второстепенных" in verdict["reason"]
