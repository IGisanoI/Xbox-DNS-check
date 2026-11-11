"""Anonymous console feedback, local history, offline outbox, and Google delivery."""

import csv
import ipaddress
import json
import os
import re
import threading
import urllib.request
import uuid
from datetime import datetime, timezone

from . import network, paths

SCHEMA_VERSION = 1
OUTCOMES = ("worked", "same_error", "different_error", "unknown")
APPLIED = ("console", "router", "both", "unknown")
FIELDS = ("schema_version", "report_id", "created_at", "run_id", "outcome", "error_code",
          "applied", "dns1", "dns2", "network_type", "network_label", "network_org",
          "verdict", "app_version")
LIMITS = {"error_code": 40, "network_label": 80, "network_org": 120,
          "verdict": 160, "app_version": 20}
CSV_COLUMNS = (
    ("ID отчёта", "report_id"), ("Время UTC", "created_at"), ("ID запуска", "run_id"),
    ("Результат", "outcome"), ("Код ошибки", "error_code"), ("Где настроено", "applied"),
    ("DNS 1", "dns1"), ("DNS 2", "dns2"), ("Тип сети", "network_type"),
    ("Сеть", "network_label"), ("Организация сети", "network_org"),
    ("Сетевой итог", "verdict"), ("Версия", "app_version"),
)
_lock = threading.Lock()
_upload_lock = threading.Lock()


def new_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]


def build_report(run_id, outcome, error_code, applied, dns1, dns2, network_info,
                 verdict, app_version):
    report = {
        "schema_version": SCHEMA_VERSION,
        "report_id": uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "run_id": run_id,
        "outcome": outcome,
        "error_code": error_code.strip(),
        "applied": applied,
        "dns1": dns1.strip(),
        "dns2": dns2.strip(),
        "network_type": network_info.get("type", "other"),
        "network_label": network_info.get("label", "").strip() or "Не указано",
        "network_org": network_info.get("org", ""),
        "verdict": verdict,
        "app_version": app_version,
    }
    return validate_report(report)


def validate_report(report):
    """Return a clean report containing only approved, anonymous technical fields."""
    if not isinstance(report, dict) or set(report) != set(FIELDS):
        raise ValueError("неверный набор полей отчёта")
    clean = dict(report)
    if clean["schema_version"] != SCHEMA_VERSION:
        raise ValueError("неподдерживаемая версия отчёта")
    if not re.fullmatch(r"[0-9a-f]{32}", str(clean["report_id"])):
        raise ValueError("неверный ID отчёта")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", str(clean["run_id"])):
        raise ValueError("неверный ID запуска")
    try:
        datetime.fromisoformat(str(clean["created_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("неверное время отчёта") from exc
    if clean["outcome"] not in OUTCOMES or clean["applied"] not in APPLIED:
        raise ValueError("неверный результат или место настройки")
    if clean["network_type"] not in network.TYPE_LABELS:
        raise ValueError("неверный тип сети")
    for key in ("dns1", "dns2"):
        value = str(clean[key]).strip()
        if key == "dns1" or value:
            ipaddress.ip_address(value)
        clean[key] = value
    for key in FIELDS[2:]:
        if key not in ("dns1", "dns2"):
            clean[key] = str(clean[key]).strip()
    for key, limit in LIMITS.items():
        if len(clean[key]) > limit:
            raise ValueError(f"слишком длинное поле: {key}")
    if not clean["network_label"] or len(clean["network_label"]) > 80:
        raise ValueError("неверное название сети")
    return clean


def record_report(report, history_path=None, outbox_path=None):
    """Save locally first, then queue the same report ID for cloud delivery."""
    report = validate_report(report)
    history_path = history_path or paths.FEEDBACK_FILE
    new_file = not os.path.exists(history_path)
    with open(history_path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        if new_file:
            writer.writerow([title for title, _key in CSV_COLUMNS])
        writer.writerow([report[key] for _title, key in CSV_COLUMNS])
    queue_report(report, outbox_path)
    return report


def load_outbox(path=None):
    path = path or paths.FEEDBACK_OUTBOX_FILE
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_outbox(reports, path):
    temp = path + ".tmp"
    try:
        if reports:
            with open(temp, "w", encoding="utf-8") as f:
                json.dump(reports, f, ensure_ascii=False, indent=2)
            os.replace(temp, path)
        elif os.path.exists(path):
            os.remove(path)
    finally:
        if os.path.exists(temp):
            os.remove(temp)


def queue_report(report, path=None):
    path = path or paths.FEEDBACK_OUTBOX_FILE
    with _lock:
        reports = load_outbox(path)
        if report["report_id"] not in {item.get("report_id") for item in reports}:
            reports.append(report)
        _save_outbox(reports, path)


def pending_count(path=None):
    return len(load_outbox(path))


def load_cloud_config(path=None):
    path = path or paths.CLOUD_CONFIG_FILE
    try:
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, ValueError) as exc:
        raise RuntimeError("облако не настроено") from exc
    if not config.get("enabled", True):
        raise RuntimeError("облачная отправка выключена")
    endpoint = str(config.get("endpoint", "")).strip()
    if not endpoint.startswith("https://"):
        raise RuntimeError("неверный адрес облачного приёмника")
    return {"endpoint": endpoint, "token": str(config.get("token", ""))}


def send_report(report, config=None, timeout=8, fetch=None):
    """Send one report. Only an explicit JSON {ok: true} response counts as delivered."""
    config = config or load_cloud_config()
    payload = json.dumps({"token": config["token"], "report": validate_report(report)},
                         ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        config["endpoint"], data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "DNS-Checker"},
        method="POST")
    fetch = fetch or urllib.request.urlopen
    with fetch(request, timeout=timeout) as response:
        raw = response.read(4096).decode("utf-8", errors="replace")
    try:
        result = json.loads(raw)
    except ValueError as exc:
        raise RuntimeError("облако вернуло не JSON") from exc
    if result.get("ok") is not True:
        raise RuntimeError(str(result.get("error", "облако отклонило отчёт")))
    return result


def flush_outbox(config=None, path=None, send_fn=None):
    """Try queued reports in order; keep failed and not-yet-tried reports for later."""
    path = path or paths.FEEDBACK_OUTBOX_FILE
    with _upload_lock:
        reports = load_outbox(path)
        if not reports:
            return {"sent": 0, "pending": 0, "error": ""}
        try:
            config = config or load_cloud_config()
        except RuntimeError as exc:
            return {"sent": 0, "pending": len(reports), "error": str(exc)}
        sender = send_fn or send_report
        sent, error = 0, ""
        for index, report in enumerate(reports):
            try:
                sender(report, config=config)
                sent += 1
            except Exception as exc:
                error = str(exc)
                reports = reports[index:]
                break
        else:
            reports = []
        with _lock:
            _save_outbox(reports, path)
        return {"sent": sent, "pending": len(reports), "error": error}
