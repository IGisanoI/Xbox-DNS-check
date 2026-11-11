"""Existing colleague files survive upgrades without losing custom text."""

import csv

from dnschecker import config, storage, xbox


def test_xbox_csv_header_migration_keeps_old_values_and_backup(tmp_path):
    path = tmp_path / "xbox_log.csv"
    old_header = xbox.HISTORY_HEADER[:7]
    old_row = ["2026-10-11 12:00:00", "8.8.8.8", "Google", "Под вопросом", "old reason", "", "Google"]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(old_header)
        writer.writerow(old_row)
    new_row = ["2026-11-11 12:00:00"] + [""] * (len(xbox.HISTORY_HEADER) - 1)
    storage.write_xbox_log([new_row], xbox.HISTORY_HEADER, str(path))

    assert (tmp_path / "xbox_log.csv.bak").exists()
    with path.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f, delimiter=";"))
    assert rows[0]["DNS"] == "8.8.8.8" and rows[0]["Итог"] == "Под вопросом"
    assert rows[0]["ID запуска"] == "" and rows[0]["Тип сети"] == ""
    assert len(rows) == 2


def test_matching_csv_header_does_not_create_backup(tmp_path):
    path = tmp_path / "xbox_log.csv"
    storage.write_xbox_log([], xbox.HISTORY_HEADER, str(path))
    storage.write_xbox_log([], xbox.HISTORY_HEADER, str(path))
    assert not (tmp_path / "xbox_log.csv.bak").exists()


def test_untouched_legacy_reply_is_upgraded(tmp_path):
    path = tmp_path / "reply_template.txt"
    path.write_text(config.LEGACY_REPLY_TEMPLATE, encoding="utf-8")
    assert storage.load_reply_template(str(path)) == config.DEFAULT_REPLY_TEMPLATE
    assert path.read_text(encoding="utf-8") == config.DEFAULT_REPLY_TEMPLATE


def test_custom_reply_is_never_replaced(tmp_path):
    path = tmp_path / "reply_template.txt"
    custom = "Our office template: {dns1} and {dns2}. No guarantees."
    path.write_text(custom, encoding="utf-8")
    assert storage.load_reply_template(str(path)) == custom
    assert path.read_text(encoding="utf-8") == custom
