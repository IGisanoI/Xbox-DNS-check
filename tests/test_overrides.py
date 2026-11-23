"""Тесты dnschecker/overrides.py: классификация, сводка, лог."""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dnschecker import overrides  # noqa: E402

ITEMS = [
    {"host": "xsts.auth.xboxlive.com", "check": "https", "method": "POST",
     "path": "/xsts/authorize", "expected": [400, 401]},
    {"host": "other.example.com", "check": "http"},
]


def fake_probe(state, ms=12.0, text="HTTP/1.1 400 Bad Request"):
    def _probe(ip, host, mode, timeout, method="GET", path="/", headers=None,
               payload=None, expected=None):
        assert host in ("xsts.auth.xboxlive.com",), host
        return {"state": state, "ms": ms, "text": text}
    return _probe


class OverridesTests(unittest.TestCase):
    def test_classify_states(self):
        cases = {
            "ok": ("ok", "отвечает как Xbox"),
            "forbidden": ("forbidden", "жив, но отказ (регион?)"),
            "redirect": ("redirect", "перенаправление"),
            "cert": ("cert", "чужой сертификат"),
            "tls_fail": ("tls_fail", "обрыв TLS (блок по имени?)"),
            "tcp_fail": ("tcp_fail", "не открывается"),
        }
        for state, expected in cases.items():
            self.assertEqual(overrides.classify({"state": state}), expected)

    def test_alive_definition(self):
        # запрет и редирект — всё ещё «живые» (TLS с настоящим сертификатом прошёл)
        for state in ("ok", "forbidden", "redirect", "unexpected", "server_error"):
            self.assertIn(state, overrides.ALIVE_STATES)
        for state in ("cert", "tls_fail", "tcp_fail", "no_http"):
            self.assertNotIn(state, overrides.ALIVE_STATES)

    def test_verify_uses_domain_check_and_marks_dead(self):
        data = {"xsts.auth.xboxlive.com": [{"ip": "87.0.0.1", "source": "t", "added": "2026-11-19"}]}
        calls = {}

        def probe_fn(ip, host, mode, timeout, method="GET", path="/", headers=None,
                     payload=None, expected=None):
            calls.update(ip=ip, mode=mode, method=method, path=path, expected=expected)
            return {"state": "ok", "ms": 5.0, "text": "HTTP/1.1 400"}
        results = overrides.verify(data, ITEMS, timeout=3, probe_fn=probe_fn,
                                   now=datetime(2026, 11, 24, 2, 30))
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual((r["domain"], r["ip"]), ("xsts.auth.xboxlive.com", "87.0.0.1"))
        self.assertTrue(r["alive"])
        self.assertEqual(r["checked_at"], "2026-11-24 02:30:00")
        # параметры домена из consoles.json дошли до probe
        self.assertEqual(calls["mode"], "https")
        self.assertEqual(calls["method"], "POST")
        self.assertEqual(calls["path"], "/xsts/authorize")
        self.assertEqual(calls["expected"], [400, 401])

    def test_verify_skips_unknown_domains(self):
        data = {"no.such.domain": [{"ip": "1.1.1.1"}]}
        self.assertEqual(overrides.verify(data, ITEMS, probe_fn=fake_probe("ok")), [])

    def test_summary_counts(self):
        data = {"xsts.auth.xboxlive.com": [
            {"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}, {"ip": "3.3.3.3"}]}

        def mixed(*args):
            return {"state": "ok" if args[0] != "3.3.3.3" else "tcp_fail", "ms": 1.0}
        results = overrides.verify(data, ITEMS, probe_fn=mixed)
        self.assertEqual(overrides.summary(results), {"xsts.auth.xboxlive.com": (2, 3)})

    def test_log_rows_shape(self):
        data = {"xsts.auth.xboxlive.com": [{"ip": "1.1.1.1"}]}
        results = overrides.verify(data, ITEMS, probe_fn=fake_probe("forbidden"))
        rows = overrides.log_rows(results)
        self.assertEqual(len(rows[0]), 7)
        self.assertEqual(rows[0][1:4], ["xsts.auth.xboxlive.com", "1.1.1.1", "жив, но отказ (регион?)"])

    def test_load_missing_file_is_empty(self):
        self.assertEqual(overrides.load("/no/such/file.json"), {})


if __name__ == "__main__":
    unittest.main()
