"""Anonymous feedback, durable outbox, and cloud acknowledgement tests."""

import csv
import json

import pytest

from dnschecker import feedback


def sample_report(report_id="a" * 32):
    return {
        "schema_version": 1, "report_id": report_id, "created_at": "2026-11-11T04:00:00Z",
        "run_id": "20261111T040000Z-abcdef123456", "outcome": "worked", "error_code": "",
        "applied": "console", "dns1": "111.88.96.54", "dns2": "111.88.96.55",
        "network_type": "office", "network_label": "Офис", "network_org": "Example ISP",
        "verdict": "Стоит попробовать", "app_version": "4.0",
    }


def test_build_report_contains_only_anonymous_fields():
    report = feedback.build_report(
        "20261111T040000Z-abcdef123456", "same_error", "0x80a40401", "router",
        "8.8.8.8", "", {"type": "home", "label": "Дом", "org": "Example ISP"},
        "Регион неясен", "4.0")
    assert set(report) == set(feedback.FIELDS)
    assert not ({"operator", "username", "hostname", "public_ip", "subscriber", "notes"} & set(report))
    assert feedback.validate_report(report) == report


def test_unapproved_personal_field_is_rejected():
    report = sample_report()
    report["operator"] = "Danil"
    with pytest.raises(ValueError, match="полей"):
        feedback.validate_report(report)


@pytest.mark.parametrize("field,value", [
    ("dns1", "not-an-ip"), ("outcome", "definitely-fixed"), ("applied", "subscriber-laptop"),
    ("network_type", "goodline"), ("network_label", ""), ("error_code", "x" * 41),
])
def test_invalid_report_fields_are_rejected(field, value):
    report = sample_report()
    report[field] = value
    with pytest.raises((ValueError, TypeError)):
        feedback.validate_report(report)


def test_record_report_saves_csv_and_survives_restart(tmp_path):
    history, outbox = tmp_path / "history.csv", tmp_path / "outbox.json"
    report = feedback.record_report(sample_report(), str(history), str(outbox))
    assert feedback.pending_count(str(outbox)) == 1
    assert feedback.load_outbox(str(outbox)) == [report]
    with history.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f, delimiter=";"))
    assert rows[0][0] == "ID отчёта" and rows[1][0] == report["report_id"]
    assert len(rows[0]) == len(feedback.CSV_COLUMNS)


def test_queue_deduplicates_same_report_id(tmp_path):
    outbox = str(tmp_path / "outbox.json")
    report = sample_report()
    feedback.queue_report(report, outbox)
    feedback.queue_report(report, outbox)
    assert feedback.pending_count(outbox) == 1


def test_different_reports_are_both_queued(tmp_path):
    outbox = str(tmp_path / "outbox.json")
    feedback.queue_report(sample_report(), outbox)
    feedback.queue_report(sample_report("b" * 32), outbox)
    assert feedback.pending_count(outbox) == 2


def test_corrupt_outbox_does_not_crash_startup(tmp_path):
    path = tmp_path / "outbox.json"
    path.write_text("not JSON", encoding="utf-8")
    assert feedback.load_outbox(str(path)) == []


class FakeResponse:
    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, limit):
        return self.raw


def test_send_report_posts_token_and_requires_explicit_success():
    captured = {}

    def fetch(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured.update(json.loads(request.data.decode("utf-8")))
        return FakeResponse(b'{"ok":true,"duplicate":false}')

    config = {"endpoint": "https://example.com/exec", "token": "secret-token"}
    result = feedback.send_report(sample_report(), config=config, fetch=fetch)
    assert result["ok"] is True
    assert captured["url"] == config["endpoint"] and captured["timeout"] == 8
    assert captured["token"] == "secret-token" and captured["report"]["dns1"] == "111.88.96.54"


@pytest.mark.parametrize("raw", [b"<html>login required</html>", b'{"ok":false,"error":"unauthorized"}'])
def test_cloud_errors_are_not_counted_as_delivered(raw):
    config = {"endpoint": "https://example.com/exec", "token": "token"}
    with pytest.raises(RuntimeError):
        feedback.send_report(sample_report(), config=config, fetch=lambda *a, **k: FakeResponse(raw))


def test_flush_keeps_failed_and_untried_reports(tmp_path):
    outbox = str(tmp_path / "outbox.json")
    first, second = sample_report(), sample_report("b" * 32)
    feedback.queue_report(first, outbox)
    feedback.queue_report(second, outbox)
    config = {"endpoint": "https://example.com/exec", "token": "token"}

    def fail(report, config):
        raise RuntimeError("offline")

    result = feedback.flush_outbox(config=config, path=outbox, send_fn=fail)
    assert result == {"sent": 0, "pending": 2, "error": "offline"}
    assert feedback.load_outbox(outbox) == [first, second]


def test_flush_retries_after_failure_and_preserves_order(tmp_path):
    outbox = str(tmp_path / "outbox.json")
    first, second = sample_report(), sample_report("b" * 32)
    feedback.queue_report(first, outbox)
    feedback.queue_report(second, outbox)
    config = {"endpoint": "https://example.com/exec", "token": "token"}
    attempts = []

    def fail_first(report, config):
        attempts.append(report["report_id"])
        if len(attempts) == 1:
            raise RuntimeError("offline")

    result = feedback.flush_outbox(config=config, path=outbox, send_fn=fail_first)
    assert result["sent"] == 0 and result["pending"] == 2
    result = feedback.flush_outbox(config=config, path=outbox, send_fn=fail_first)
    assert result == {"sent": 2, "pending": 0, "error": ""}
    assert attempts == [first["report_id"], first["report_id"], second["report_id"]]
    assert feedback.load_outbox(outbox) == []


def test_missing_cloud_config_leaves_reports_pending(tmp_path):
    outbox = str(tmp_path / "outbox.json")
    feedback.queue_report(sample_report(), outbox)
    result = feedback.flush_outbox(config=None, path=str(tmp_path / "missing-outbox.json"))
    assert result["pending"] == 0  # an empty outbox needs no cloud configuration
    with pytest.raises(RuntimeError, match="облако"):
        feedback.load_cloud_config(str(tmp_path / "missing.json"))
