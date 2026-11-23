"""Тесты dnschecker/stats.py: разбор, кэш, деградация без сети, ранжирование."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dnschecker import stats  # noqa: E402


def make_stats():
    return {
        "totals": {"reports": 9, "worked": 6, "unknown": 1, "success_rate": 0.75,
                   "active_networks": 2},
        "by_dns": [
            {"dns": "1.1.1.1", "reports": 4, "worked": 3, "success_rate": 0.75,
             "last_report": "2026-11-20"},
            {"dns": "2.2.2.2", "reports": 3, "worked": 3, "success_rate": 1.0,
             "last_report": "2026-11-22"},
            {"dns": "3.3.3.3", "reports": 3, "worked": 1, "success_rate": 0.5,
             "last_report": "2026-11-10"},
        ],
        "by_dns_org": [
            {"dns": "1.1.1.1", "org": "TTK", "reports": 3, "worked": 2, "success_rate": 2 / 3},
        ],
    }


class StatsTests(unittest.TestCase):
    def setUp(self):
        stats.reset()
        self.tmp = tempfile.mkdtemp()
        self.cache = os.path.join(self.tmp, "stats_cache.json")
        self._orig_save, self._orig_load = stats.save_cache, stats.load_cache
        stats.save_cache = lambda s, path=None: self._orig_save(s, self.cache)
        stats.load_cache = lambda path=None: self._orig_load(self.cache)
        # конфиг облака читается рядом с argv[0] — в тестах его там нет
        import dnschecker.feedback as feedback_mod
        self._orig_cfg = feedback_mod.load_cloud_config
        feedback_mod.load_cloud_config = lambda: {"endpoint": "https://example.test/exec",
                                                  "token": "tok"}

    def tearDown(self):
        import dnschecker.feedback as feedback_mod
        feedback_mod.load_cloud_config = self._orig_cfg
        stats.save_cache, stats.load_cache = self._orig_save, self._orig_load
        stats.reset()

    def test_live_success_saves_cache(self):
        def fetch(req, timeout):
            class Resp:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return json.dumps({"ok": True, "stats": make_stats()}).encode()
            return Resp()

        source, data = stats.get_stats(fetch=fetch)
        self.assertEqual(source, "live")
        self.assertEqual(data["totals"]["reports"], 9)
        self.assertTrue(os.path.exists(self.cache))

    def test_network_failure_falls_back_to_cache(self):
        stats.save_cache(make_stats())
        stats.reset()
        source, data = stats.get_stats(fetch=lambda req, timeout: (_ for _ in ()).throw(OSError("нет сети")))
        self.assertEqual(source, "cache")
        self.assertEqual(data["totals"]["worked"], 6)

    def test_no_network_no_cache_is_none(self):
        source, data = stats.get_stats(fetch=lambda req, timeout: (_ for _ in ()).throw(OSError("нет сети")))
        self.assertEqual((source, data), ("none", None))

    def test_recommendations_ranking_and_org(self):
        recs = stats.recommendations(make_stats(), org="TTK")
        self.assertEqual([r["dns"] for r in recs], ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        # 1.1.1.1 первым: совпала организация сети, несмотря на более низкую долю
        self.assertTrue(recs[0]["org_match"])
        self.assertFalse(recs[1]["org_match"])
        # без org — чистая сортировка по доле успеха
        recs2 = stats.recommendations(make_stats(), org="")
        self.assertEqual(recs2[0]["dns"], "2.2.2.2")
        self.assertEqual(stats.label(recs2[0]), "подтверждено: 3 из 3")

    def test_recommendations_empty_stats(self):
        self.assertEqual(stats.recommendations(None), [])
        self.assertEqual(stats.recommendations({}), [])

    def test_get_stats_memoized(self):
        calls = []

        def fetch(req, timeout):
            calls.append(1)

            class Resp:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return json.dumps({"ok": True, "stats": make_stats()}).encode()
            return Resp()

        stats.get_stats(fetch=fetch)
        stats.get_stats(fetch=fetch)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
