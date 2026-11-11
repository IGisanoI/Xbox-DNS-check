"""
DNS Checker — диагностика DNS-серверов для техподдержки.

Вкладка «Серверы» — живы ли DNS-серверы.
Вкладка «Xbox»    — какие DNS стоит попробовать при ошибке входа на Xbox.

Запуск:  python dns_checker_gui.py
Нужны библиотеки dnspython и customtkinter:  pip install -r requirements.txt
"""

import sys
import tkinter as tk
from tkinter import messagebox


def _check_dependencies():
    missing = []
    for module, package in (("dns.resolver", "dnspython"), ("customtkinter", "customtkinter")):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if missing:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Не хватает библиотек",
            "Для работы нужны библиотеки: " + ", ".join(missing) + "\n\nУстановите их командой:\n    pip install "
            + " ".join(missing) + "\n\nи запустите программу снова.",
        )
        sys.exit(1)


# Check libraries first, so the user sees a clear message instead of a crash.
if __name__ == "__main__":
    _check_dependencies()
    from dnschecker.ui.app import main
    main()
