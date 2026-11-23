"""Тесты dnschecker/version_check.py."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dnschecker import version_check  # noqa: E402


def fake_fetch(payload):
    def _fetch(req, timeout):
        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(payload).encode()
        return Resp()
    return _fetch


class VersionCheckTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(version_check.parse_version("v5.0"), (5, 0))
        self.assertEqual(version_check.parse_version("5.10"), (5, 10))
        self.assertIsNone(version_check.parse_version("v5"))
        self.assertIsNone(version_check.parse_version(""))
        self.assertIsNone(version_check.parse_version("DNS_check"))

    def test_is_newer(self):
        self.assertTrue(version_check.is_newer("v5.1", "5.0"))
        self.assertTrue(version_check.is_newer("6.0", "5.9"))
        self.assertFalse(version_check.is_newer("v5.0", "5.0"))
        self.assertFalse(version_check.is_newer("v4.9", "5.0"))
        self.assertFalse(version_check.is_newer("мусор", "5.0"))

    def test_check_latest_success(self):
        result = version_check.check_latest(fetch=fake_fetch(
            {"tag_name": "v5.0", "html_url": "https://github.com/IGisanoI/Xbox-DNS-check/releases/tag/v5.0"}))
        self.assertEqual(result["tag"], "v5.0")

    def test_check_latest_failure_is_silent_none(self):
        def boom(req, timeout):
            raise OSError("нет сети")
        self.assertIsNone(version_check.check_latest(fetch=boom))
        self.assertIsNone(version_check.check_latest(fetch=fake_fetch({})))  # нет tag_name

    def test_check_async_suppresses_older(self):
        import threading
        done = threading.Event()
        seen = []
        orig = version_check.check_latest
        try:
            version_check.check_latest = lambda timeout=6: {"tag": "v4.9", "url": "u"}
            version_check.check_async("5.0", lambda r: (seen.append(r), done.set()))
            self.assertTrue(done.wait(5))
            self.assertEqual(seen, [None])  # 4.9 старше 5.0: уведомлять не о чем
        finally:
            version_check.check_latest = orig


if __name__ == "__main__":
    unittest.main()
