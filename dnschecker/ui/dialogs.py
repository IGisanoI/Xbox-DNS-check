"""Small dialogs for generic network labels and anonymous console feedback."""

import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from .. import feedback, network
from . import common as ui
from .common import C

OUTCOME_OPTIONS = (("worked", "Вход заработал"), ("same_error", "Та же ошибка"),
                   ("different_error", "Другая ошибка"), ("unknown", "Неизвестно / не пробовали"))
APPLIED_OPTIONS = (("console", "На консоли"), ("router", "На роутере"),
                   ("both", "На консоли и роутере"), ("unknown", "Неизвестно"))


def network_settings(root, type_var, label_var, detect_var):
    win = ui.toplevel(root, "Сеть для истории проверок", "440x280")
    frame = ctk.CTkFrame(win, fg_color="transparent")
    frame.pack(fill="both", expand=True, padx=16, pady=16)
    ui.label(frame, "Тип подключения").pack(anchor="w", pady=(0, 4))
    ctk.CTkOptionMenu(frame, values=[label for _key, label in network.NETWORK_TYPES],
                      variable=type_var, fg_color=C["surface2"], button_color=C["surface2"],
                      button_hover_color=C["border"], text_color=C["text"],
                      dropdown_fg_color=C["surface2"], dropdown_hover_color=C["border"],
                      dropdown_text_color=C["text"]).pack(fill="x", pady=(0, 12))
    ui.label(frame, "Название сети (например, Офис или Дом)").pack(anchor="w", pady=(0, 4))
    ui.entry(frame, label_var, width=300).pack(fill="x", pady=(0, 12))
    ui.checkbox(frame, detect_var, "Определять организацию сети без сохранения публичного IP").pack(anchor="w")
    ui.label(frame, "Имя сотрудника, имя ПК и данные абонента не собираются.",
             muted=True, size=11, wraplength=380).pack(anchor="w", pady=(12, 0))
    ui.button(frame, "Готово", win.destroy, primary=True, width=100).pack(anchor="e", pady=(14, 0))
    return win


def console_feedback(root, servers, verdicts, run_id, network_info, app_version, on_report):
    if not servers or not run_id:
        messagebox.showinfo("Результат на консоли", "Сначала запустите проверку DNS.")
        return None
    win = ui.toplevel(root, "Анонимный результат на консоли", "520x520")
    frame = ctk.CTkFrame(win, fg_color="transparent")
    frame.pack(fill="both", expand=True, padx=16, pady=16)

    server_map = {f"{name or ip} — {ip}": ip for ip, name in servers}
    server_var = tk.StringVar(value=next(iter(server_map)))
    outcome_labels = {label: key for key, label in OUTCOME_OPTIONS}
    applied_labels = {label: key for key, label in APPLIED_OPTIONS}
    outcome_var = tk.StringVar(value=OUTCOME_OPTIONS[0][1])
    applied_var = tk.StringVar(value=APPLIED_OPTIONS[0][1])
    dns2_var = tk.StringVar()
    error_var = tk.StringVar()

    def option(text, variable, values):
        ui.label(frame, text).pack(anchor="w", pady=(5, 3))
        ctk.CTkOptionMenu(frame, values=values, variable=variable, fg_color=C["surface2"],
                          button_color=C["surface2"], button_hover_color=C["border"],
                          text_color=C["text"], dropdown_fg_color=C["surface2"],
                          dropdown_hover_color=C["border"], dropdown_text_color=C["text"],
                          font=ui.font(12), dropdown_font=ui.font(12)).pack(fill="x")

    option("DNS из последней проверки", server_var, list(server_map))
    option("Что произошло на консоли", outcome_var, list(outcome_labels))
    option("Где меняли DNS", applied_var, list(applied_labels))
    ui.label(frame, "Дополнительный DNS (необязательно)").pack(anchor="w", pady=(8, 3))
    ui.entry(frame, dns2_var, width=220).pack(fill="x")
    ui.label(frame, "Итоговый код ошибки (необязательно)").pack(anchor="w", pady=(8, 3))
    ui.entry(frame, error_var, width=220, placeholder_text="0x80a40401").pack(fill="x")
    ui.label(frame, "Отправляются только технические данные. Имя сотрудника, имя ПК, "
                    "публичный IP и данные абонента не отправляются.",
             muted=True, size=11, wraplength=460).pack(anchor="w", pady=(12, 0))

    def save():
        dns1 = server_map[server_var.get()]
        try:
            report = feedback.build_report(
                run_id=run_id,
                outcome=outcome_labels[outcome_var.get()],
                error_code=error_var.get(),
                applied=applied_labels[applied_var.get()],
                dns1=dns1,
                dns2=dns2_var.get(),
                network_info=network_info,
                verdict=verdicts.get(dns1, {}).get("text", ""),
                app_version=app_version,
            )
            on_report(report)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Результат не сохранён", str(exc), parent=win)
            return
        win.destroy()

    ui.button(frame, "Сохранить и отправить", save, primary=True, width=180).pack(anchor="e", pady=(16, 0))
    return win
