"""Static contract checks for Apps Script; this does not execute Google code."""

import json
import re
from pathlib import Path

from dnschecker import feedback


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "cloud" / "Code.gs").read_text(encoding="utf-8")


def test_apps_script_accepts_exactly_the_anonymous_schema():
    match = re.search(r"const FIELDS = \[(.*?)\];", SOURCE, re.DOTALL)
    fields = re.findall(r"'([^']+)'", match.group(1))
    assert fields == list(feedback.FIELDS)
    assert not ({"operator", "username", "hostname", "public_ip", "subscriber", "notes"} & set(fields))


def test_apps_script_has_duplicate_lock_and_formula_protection():
    assert "LockService.getScriptLock()" in SOURCE
    assert "matchEntireCell(true)" in SOURCE
    assert ".setNumberFormat('@').setValues([row])" in SOURCE
    assert "if (/^[=+\\-@]/.test(text))" in SOURCE


def test_cloud_example_has_no_real_endpoint_or_token():
    example = json.loads((ROOT / "cloud_config.example.json").read_text(encoding="utf-8"))
    assert "PASTE_DEPLOYMENT_ID" in example["endpoint"]
    assert example["token"].startswith("replace-")
    assert set(example) == {"enabled", "endpoint", "token"}
