"""
Где лежат файлы программы.

Все рабочие файлы (список серверов, настройки, кэш) хранятся рядом с программой:
рядом с .py при запуске из исходников и рядом с .exe после сборки PyInstaller.
"""

import os
import sys

# Folder of the script or the .exe (sys.argv[0] works for both cases).
APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))


def path(name):
    """Полный путь к файлу программы по его имени."""
    return os.path.join(APP_DIR, name)


SERVERS_FILE = path("servers.txt")
CONSOLES_FILE = path("consoles.json")
SETTINGS_FILE = path("settings.json")
OWNERS_CACHE_FILE = path("ip_owners.json")
REPLY_TEMPLATE_FILE = path("reply_template.txt")
LOG_FILE = path("dns_log.csv")
XBOX_LOG_FILE = path("xbox_log.csv")  # history of the "Xbox" tab
FEEDBACK_FILE = path("console_feedback.csv")
FEEDBACK_OUTBOX_FILE = path("feedback_outbox.json")
CLOUD_CONFIG_FILE = path("cloud_config.json")
