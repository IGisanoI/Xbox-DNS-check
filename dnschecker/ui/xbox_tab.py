"""
Вкладка «Xbox»: сетевые кандидаты DNS и отдельный результат на консоли.

Раскладка «DNS в строках»: каждая строка — один DNS (ручка ⠿ для
перетаскивания, галочка, адрес, итог и важные проверки), под стрелкой ▾
раскрываются второстепенные проверки. Таблица тянется по ширине окна,
новые DNS добавляют строки, а не столбцы.
"""

import ipaddress
import os
import queue
import sys
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from tkinter import messagebox

import customtkinter as ctk

from .. import __version__, dns_tools, feedback, network, owners, paths, reply, server_list, storage, xbox
from . import common as ui, dialogs
from .common import C, KIND_COLORS, LEVEL_FG

# Column widths (pixels) and column numbers in the grid.
HANDLE_W, SEL_W, NAME_W, VERDICT_W, CHECK_W, EXPAND_W = 24, 34, 180, 160, 80, 40
COL_HANDLE, COL_SEL, COL_NAME, COL_VERDICT, COL_CHECKS = range(5)

SORT_OPTIONS = [(server_list.SORT_CUSTOM, "Свой порядок"), (server_list.SORT_NAME, "По названию"),
                (server_list.SORT_IP, "По IP"), (server_list.SORT_RESULT, "По итогу")]
KIND_RANK = {xbox.GOOD: 0, xbox.DOUBT: 1, xbox.BAD: 2, xbox.DEAD: 3}  # for sorting by verdict


class Row:
    """Виджеты одной строки таблицы (одного DNS)."""

    def __init__(self):
        self.frame = None
        self.selected = None      # tk.BooleanVar of the checkbox
        self.name_label = None
        self.ip_label = None
        self.pill = None          # colored verdict label
        self.reason = None
        self.cells = {}           # item index -> label of an important check
        self.details = None       # panel under the row
        self.expand_btn = None
        self.expanded = False


class XboxTab:
    def __init__(self, app, parent, settings):
        self.app = app
        self.root = app.root
        self.parent = parent
        self.model = app.servers
        self.profiles, load_note, load_warning = storage.load_consoles()
        if load_warning:
            messagebox.showwarning("consoles.json", load_warning)
        self.items = self.profiles[next(iter(self.profiles))]  # the first profile ("Xbox")
        self.critical = [i for i, it in enumerate(self.items) if it.get("critical")]
        self.secondary = [i for i, it in enumerate(self.items) if not it.get("critical")]

        self.results = queue.Queue()
        self.running = False
        self.monitor_job = None
        self.poll_job = None
        self.unchecked = self._initial_unchecked(settings)
        self.names = {}         # ip -> name
        self.display = []       # ip order on screen
        self.checked = []       # [(ip, name)] of the last check
        self.data = {}          # (ip, item index) -> check_domain result
        self.whoami = {}        # ip -> whoami result
        self.verdicts = {}      # ip -> verdict
        self.last_kinds = {}    # ip -> kind of the previous check (for monitoring)
        self.rows = {}          # ip -> Row
        self.drag = None
        self.from_monitor = False
        self.network_type_var = tk.StringVar(value=network.type_label(settings.get("network_type", "office")))
        self.network_label_var = tk.StringVar(value=settings.get("network_label", "Офис"))
        self.detect_network_var = tk.BooleanVar(value=settings.get("detect_network", True))
        self.run_id = ""
        self.run_network = {}
        self.feedback_sending = False
        self.console_results = {}

        self._build(parent, settings)
        self.model.subscribe(self._sync_rows)
        self._sync_rows()
        if load_note:
            self.status_var.set(load_note)
        self.poll_job = self.root.after(100, self._poll)
        self.root.after(1500, self._start_feedback_flush)
        if self.monitor_var.get():
            # Monitoring was on when the program closed: start again.
            self.monitor_job = self.root.after(3000, self._monitor_tick)

    def _initial_unchecked(self, settings):
        """Один раз снимаем все галочки, затем восстанавливаем выбор пользователя."""
        if not settings.get("selection_initialized"):
            return set(self.model.ips())
        if "unchecked" in settings:
            return set(settings["unchecked"])
        if settings.get("selected") is not None:
            selected = set(settings["selected"])
            return {ip for ip in self.model.ips() if ip not in selected}
        return set(self.model.ips())

    # --- building the window ---

    def _build(self, parent, settings):
        # Daily actions stay visible. Advanced controls live in a collapsible row.
        primary = ctk.CTkFrame(parent, fg_color="transparent")
        primary.pack(fill="x", pady=(4, 6))
        self.check_btn = ui.button(primary, "▶  Проверить", self.start, primary=True, width=130)
        self.check_btn.pack(side="left")
        self.reply_btn = ui.button(primary, "Ответ абоненту", self.show_reply, width=150)
        self.reply_btn.pack(side="left", padx=8)
        ui.button(primary, "Результат на консоли", self.show_feedback, width=170).pack(side="left")
        self.advanced_btn = ui.button(primary, "⚙  Настройки", self._toggle_advanced, width=120)
        self.advanced_btn.pack(side="right")
        self.monitor_caption = ui.label(primary, "", muted=True, size=12)
        self.monitor_caption.pack(side="right", padx=12)

        tools = ctk.CTkFrame(parent, fg_color="transparent")
        tools.pack(fill="x", pady=(0, 6))
        self.ip_entry = ui.entry(tools, None, width=140, placeholder_text="IP-адрес")
        self.ip_entry.pack(side="left")
        self.name_entry = ui.entry(tools, None, width=155, placeholder_text="Название")
        self.name_entry.pack(side="left", padx=6)
        for entry in (self.ip_entry, self.name_entry):
            entry.bind("<Return>", lambda _event: self._add_server())
        ui.button(tools, "+ Добавить и выбрать", self._add_server, width=160).pack(side="left")
        bar, self.sort = ui.selection_bar(tools, self._check_all, SORT_OPTIONS,
                                          settings.get("sort"), self._relayout)
        bar.pack(side="right")

        self.advanced = ctk.CTkFrame(parent, fg_color=C["surface"], corner_radius=8)
        self.advanced_visible = False
        ui.button(self.advanced, "Сеть", self.show_network_settings, width=70).pack(
            side="left", padx=(10, 14), pady=8)
        ui.label(self.advanced, "Таймаут, с", muted=True).pack(side="left")
        self.timeout_var = tk.StringVar(value=str(settings.get("timeout", 4)))
        ui.entry(self.advanced, self.timeout_var, width=44).pack(side="left", padx=(6, 14))
        self.monitor_var = tk.BooleanVar(value=settings.get("monitor", False))
        ui.switch(self.advanced, self.monitor_var, "Следить каждые", self._toggle_monitor).pack(side="left")
        self.monitor_minutes_var = tk.StringVar(value=str(settings.get("monitor_minutes", 30)))
        ui.entry(self.advanced, self.monitor_minutes_var, width=46).pack(side="left", padx=(8, 4))
        ui.label(self.advanced, "мин", muted=True).pack(side="left")
        self.history_var = tk.BooleanVar(value=settings.get("history", True))
        ui.checkbox(self.advanced, self.history_var, "Писать историю").pack(side="right", padx=10)
        if sys.platform == "win32":  # os.startfile exists only on Windows
            ui.button(self.advanced, "Открыть историю", self._open_history, width=140,
                      height=28, font=ui.font(12)).pack(side="right")

        self.table_area = ctk.CTkFrame(parent, fg_color="transparent")
        self.table_area.pack(fill="both", expand=True)
        self.table = ctk.CTkScrollableFrame(self.table_area, fg_color="transparent", corner_radius=0,
                                            scrollbar_button_color=C["border"],
                                            scrollbar_button_hover_color=C["muted"])
        self.table.pack(fill="both", expand=True)

        header = ctk.CTkFrame(self.table, fg_color="transparent")
        header.pack(fill="x", pady=(0, 2))
        self._columns(header)
        ui.label(header, "DNS", muted=True, size=12).grid(row=0, column=COL_NAME, sticky="w", padx=4)
        ui.label(header, "Итог", muted=True, size=12).grid(row=0, column=COL_VERDICT, sticky="w", padx=4)
        for k, i in enumerate(self.critical):
            ui.label(header, xbox.column_title(self.items[i]), muted=True, size=12,
                     wraplength=CHECK_W).grid(row=0, column=COL_CHECKS + k)
        self.empty_label = ui.label(self.table, "Список DNS пуст — добавьте адрес в поле выше.", muted=True)

        bottom = ctk.CTkFrame(parent, fg_color="transparent")
        bottom.pack(fill="x", pady=(6, 0))
        self.status_var = tk.StringVar(value="Отметьте DNS и нажмите «Проверить»")
        ctk.CTkLabel(bottom, textvariable=self.status_var, font=ui.font(12),
                     text_color=C["muted"], anchor="w").pack(side="left", fill="x", expand=True)
        self.monitor_var.trace_add("write", lambda *_args: self._update_monitor_caption())
        self._update_monitor_caption()

    def _toggle_advanced(self):
        self.advanced_visible = not self.advanced_visible
        if self.advanced_visible:
            self.advanced.pack(fill="x", pady=(0, 6), before=self.table_area)
        else:
            self.advanced.pack_forget()
        self.advanced_btn.configure(text="⚙  Скрыть настройки" if self.advanced_visible else "⚙  Настройки")

    def _update_monitor_caption(self):
        enabled = self.monitor_var.get()
        self.monitor_caption.configure(text="Слежение включено" if enabled else "",
                                       text_color=C["ok"] if enabled else C["muted"])

    def _add_server(self):
        raw_ip = self.ip_entry.get().strip()
        name = self.name_entry.get().strip()
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            messagebox.showwarning("Ошибка", f"«{raw_ip}» — не IP-адрес")
            return
        self.unchecked.discard(ip)
        if ip in self.rows:
            self.rows[ip].selected.set(True)
            self._relayout()
            self.status_var.set(f"{ip} уже в списке — выбран для проверки")
        else:
            self.model.add(ip, name)  # subscribers create the Xbox row and update the Servers tab
            self.status_var.set(f"{ip} добавлен и выбран для проверки")
        self.ip_entry.delete(0, "end")
        self.name_entry.delete(0, "end")
        self.ip_entry.focus_set()

    def get_settings(self):
        return {"timeout": ui.int_from(self.timeout_var, 4, 1, 30),
                "monitor": self.monitor_var.get(),
                "monitor_minutes": ui.int_from(self.monitor_minutes_var, 30, 5, 240),
                "sort": self.sort.mode,
                "history": self.history_var.get(),
                "network_type": network.type_key(self.network_type_var.get()),
                "network_label": self.network_label_var.get().strip() or "Не указано",
                "detect_network": self.detect_network_var.get(),
                "selection_initialized": True,
                "unchecked": sorted(ip for ip, row in self.rows.items() if not row.selected.get())}

    def _columns(self, frame):
        """Одинаковая сетка колонок для заголовка и всех строк — так они совпадают."""
        for col, width in ((COL_HANDLE, HANDLE_W), (COL_SEL, SEL_W), (COL_NAME, NAME_W),
                           (COL_VERDICT, VERDICT_W)):
            frame.grid_columnconfigure(col, minsize=width)
        for k in range(len(self.critical)):
            frame.grid_columnconfigure(COL_CHECKS + k, minsize=CHECK_W, weight=1, uniform="checks")
        frame.grid_columnconfigure(COL_CHECKS + len(self.critical), minsize=EXPAND_W)

    # --- rows ---

    def _sync_rows(self):
        """
        Приводит строки в соответствие со списком DNS: создаёт новые, убирает
        удалённые, а существующие только переставляет — галочки и результаты
        при этом сохраняются.
        """
        self.names = dict(self.model.items())
        for ip in [ip for ip in self.rows if ip not in self.names]:
            self.rows.pop(ip).frame.destroy()
        for ip, name in self.model.items():
            if ip in self.rows:
                self.rows[ip].name_label.configure(text=name or ip)
            else:
                self._build_row(ip, name)
        if self.names:
            self.empty_label.pack_forget()
        else:
            self.empty_label.pack(pady=30)
        self._relayout()

    def _relayout(self):
        """Меняет порядок только по явной сортировке, не по состоянию галочек."""
        rank = {ip: KIND_RANK[v["kind"]] for ip, v in self.verdicts.items()}
        display = [ip for ip, _ in server_list.sort_servers(
            self.model.items(), self.sort.mode, rank)]
        if display != self.display:
            self.display = display
            self._repack()

    def _repack(self):
        """Переставляет готовые строки без пересоздания — это быстро."""
        for ip in self.display:
            self.rows[ip].frame.pack_forget()
        for ip in self.display:
            self.rows[ip].frame.pack(fill="x", pady=3)

    def _build_row(self, ip, name):
        row = Row()
        self.rows[ip] = row
        f = ctk.CTkFrame(self.table, fg_color=C["surface"], corner_radius=8)
        self._columns(f)
        row.frame = f

        handle = ctk.CTkLabel(f, text="⠿", text_color=C["muted"], font=ui.font(16),
                              width=HANDLE_W, cursor="fleur")
        handle.grid(row=0, column=COL_HANDLE, padx=(6, 0))
        handle.bind("<ButtonPress-1>", lambda e: self._drag_start(ip))
        handle.bind("<B1-Motion>", self._drag_motion)
        handle.bind("<ButtonRelease-1>", self._drag_end)

        row.selected = tk.BooleanVar(value=ip not in self.unchecked)
        ui.checkbox(f, row.selected, width=24).grid(row=0, column=COL_SEL, pady=8)

        name_box = ctk.CTkFrame(f, fg_color="transparent")
        name_box.grid(row=0, column=COL_NAME, sticky="w", padx=4, pady=6)
        row.name_label = ui.label(name_box, name or ip, bold=True, anchor="w")
        row.name_label.pack(anchor="w")
        row.name_label.bind("<Double-1>", lambda e: self._rename(ip))
        row.ip_label = ctk.CTkLabel(name_box, text=ip, font=ui.font(12), text_color=C["muted"],
                                    cursor="hand2", anchor="w", height=18)
        row.ip_label.pack(anchor="w")
        row.ip_label.bind("<Button-1>", lambda e: self._copy_ip(ip))

        verdict_box = ctk.CTkFrame(f, fg_color="transparent", width=VERDICT_W - 8)
        verdict_box.grid(row=0, column=COL_VERDICT, sticky="w", padx=4)
        row.pill = ctk.CTkLabel(verdict_box, text="—", width=120, height=24, corner_radius=12,
                                fg_color=C["surface2"], text_color=C["muted"], font=ui.font(12, bold=True))
        row.pill.pack(anchor="w")
        row.reason = ctk.CTkLabel(verdict_box, text="", font=ui.font(11), text_color=C["muted"],
                                  width=VERDICT_W - 8, wraplength=VERDICT_W - 16,
                                  height=0, anchor="w", justify="left")
        row.reason.pack(anchor="w")

        for k, i in enumerate(self.critical):
            cell = ctk.CTkLabel(f, text="—", font=ui.font(12), text_color=C["muted"], cursor="hand2")
            cell.grid(row=0, column=COL_CHECKS + k, sticky="ew")
            cell.bind("<Button-1>", lambda e, i=i: self._show_details(ip, i))  # i=i: remember this i
            row.cells[i] = cell

        row.expand_btn = ctk.CTkButton(f, text="▾", width=28, height=28, corner_radius=6,
                                       fg_color="transparent", hover_color=C["surface2"],
                                       text_color=C["muted"], font=ui.font(14),
                                       command=lambda: self._toggle_details(ip))
        row.expand_btn.grid(row=0, column=COL_CHECKS + len(self.critical), padx=(0, 6))

        row.details = ctk.CTkFrame(f, fg_color="transparent")
        self._paint_row(ip)

    def _paint_row(self, ip):
        """Перерисовывает строку по сохранённым результатам."""
        row = self.rows.get(ip)
        if not row:
            return
        for i, cell in row.cells.items():
            res = self.data.get((ip, i))
            if not res:
                continue
            level, icon, caption = xbox.cell_caption(res)
            cell.configure(text=f"{icon} {caption}", text_color=LEVEL_FG[level])
        v = self.verdicts.get(ip)
        if v:
            bg, fg = KIND_COLORS[v["kind"]]
            row.pill.configure(text=v["label"], fg_color=bg, text_color=fg)
            reason = v["reason"]
            outcome = self.console_results.get(ip)
            if outcome:
                labels = {"worked": "консоль: вход заработал", "same_error": "консоль: та же ошибка",
                          "different_error": "консоль: другая ошибка", "unknown": "консоль: неизвестно"}
                reason = (reason + " · " if reason else "") + labels[outcome]
            row.reason.configure(text=reason)
        if row.expanded:
            self._fill_details(ip)

    def _reset_row(self, ip, active):
        row = self.rows[ip]
        mark = "…" if active else "—"
        for cell in row.cells.values():
            cell.configure(text=mark, text_color=C["muted"])
        row.pill.configure(text="проверка…" if active else "не выбран",
                           fg_color=C["surface2"], text_color=C["muted"])
        row.reason.configure(text="")
        if row.expanded:
            self._fill_details(ip)

    def _toggle_details(self, ip):
        row = self.rows[ip]
        row.expanded = not row.expanded
        row.expand_btn.configure(text="▴" if row.expanded else "▾")
        if row.expanded:
            self._fill_details(ip)
            row.details.grid(row=1, column=0, columnspan=COL_CHECKS + len(self.critical) + 1,
                             sticky="ew", padx=(HANDLE_W + SEL_W + 10, 10), pady=(0, 10))
        else:
            row.details.grid_remove()

    def _fill_details(self, ip):
        """Панель под строкой: все проверки (в том числе второстепенные) и «кто отвечает»."""
        box = self.rows[ip].details
        for w in box.winfo_children():
            w.destroy()
        box.grid_columnconfigure(2, weight=1)
        line = 0
        for title, indices in (("Важные проверки", self.critical),
                               ("Второстепенные — учитываются в итоге", self.secondary)):
            if not indices:
                continue
            ui.label(box, title, muted=True, size=11).grid(row=line, column=0, columnspan=4,
                                                           sticky="w", pady=(6, 2))
            line += 1
            for i in indices:
                item, res = self.items[i], self.data.get((ip, i))
                if res:
                    level, icon, caption = xbox.cell_caption(res)
                    color = LEVEL_FG[level]
                else:
                    icon, caption, color = "…", "нет данных", C["muted"]
                widgets = [
                    ctk.CTkLabel(box, text=icon, text_color=color, font=ui.font(12, bold=True), width=18),
                    ctk.CTkLabel(box, text=xbox.column_title(item), text_color=C["text"],
                                 font=ui.font(12), anchor="w", width=120),
                    ctk.CTkLabel(box, text=item["host"], text_color=C["muted"], font=ui.font(12), anchor="w"),
                    ctk.CTkLabel(box, text=caption, text_color=color, font=ui.font(12), anchor="e"),
                ]
                for col, w in enumerate(widgets):
                    w.grid(row=line, column=col, sticky="ew", padx=(0, 10))
                    w.configure(cursor="hand2", height=20)
                    w.bind("<Button-1>", lambda e, i=i: self._show_details(ip, i))
                line += 1

        who = self.whoami.get(ip)
        ui.label(box, "Кто реально отвечает на запросы этого DNS", muted=True, size=11).grid(
            row=line, column=0, columnspan=4, sticky="w", pady=(8, 2))
        text = who["text"].replace("\n", "  ·  ") if who else "нет данных"
        color = C["warn"] if who and who["level"] else C["text"]
        w = ctk.CTkLabel(box, text=text, text_color=color, font=ui.font(12), anchor="w",
                         cursor="hand2", height=20)
        w.grid(row=line + 1, column=0, columnspan=4, sticky="w")
        w.bind("<Button-1>", lambda e: self._show_who(ip))

    # --- checkboxes, rename, copy ---

    def _selected_servers(self):
        return [(ip, self.names[ip]) for ip in self.display if self.rows[ip].selected.get()]

    def _check_all(self, checked):
        for row in self.rows.values():
            row.selected.set(checked)
        self._relayout()

    def _rename(self, ip):
        """Поле для нового названия прямо поверх старого."""
        label = self.rows[ip].name_label
        entry = ui.inline_editor(label.master, self.names[ip],
                                 lambda name: self.model.rename(ip, name), width=NAME_W - 12)
        entry.place(in_=label, x=-2, y=-2)

    def _copy_ip(self, ip):
        ui.copy_to_clipboard(self.root, ip)
        self.status_var.set(f"Адрес {ip} скопирован в буфер обмена")
        lbl = self.rows[ip].ip_label
        lbl.configure(text="✓ скопировано", text_color=C["ok"])
        self.root.after(1200, lambda: lbl.winfo_exists() and lbl.configure(text=ip, text_color=C["muted"]))

    # --- drag and drop by the ⠿ handle ---

    def _drag_start(self, ip):
        self.drag = {"ip": ip, "moved": False}
        self.rows[ip].frame.configure(fg_color=C["surface2"])

    def _drag_motion(self, event):
        if not self.drag:
            return
        ip = self.drag["ip"]
        target = self._row_under(event.y_root)
        if not target or target == ip:
            return
        # Swap only after the mouse passes the middle of the other row,
        # otherwise two rows jump back and forth.
        frame = self.rows[target].frame
        middle = frame.winfo_rooty() + frame.winfo_height() / 2
        going_down = self.display.index(target) > self.display.index(ip)
        if (event.y_root > middle) == going_down:
            self.display = server_list.move(self.display, ip, self.display.index(target))
            self.drag["moved"] = True
            self._repack()

    def _row_under(self, y_root):
        for ip in self.display:
            frame = self.rows[ip].frame
            top = frame.winfo_rooty()
            if top <= y_root < top + frame.winfo_height():
                return ip
        return None

    def _drag_end(self, _event):
        drag, self.drag = self.drag, None
        if not drag:
            return
        self.rows[drag["ip"]].frame.configure(fg_color=C["surface"])
        if drag["moved"]:
            if self.sort.mode == server_list.SORT_CUSTOM:
                # Move only the dragged server, the others keep their places.
                self.model.set_order(server_list.place_like(self.model.ips(), drag["ip"], self.display))
                self._relayout()  # if the order did not change, put the rows back
            else:
                # Dragged in a sorted view: this sorted order becomes the user's own.
                self.sort.set(server_list.SORT_CUSTOM)
                self.model.set_order(self.display)

    # --- check ---

    def start(self, from_monitor=False):
        if self.running:
            return
        checked = self._selected_servers()
        if not checked:
            if not from_monitor:
                messagebox.showwarning("Нет DNS", "Отметьте галочкой хотя бы один DNS")
            return
        self.checked = checked
        self.from_monitor = from_monitor  # written to the history
        self.run_id = feedback.new_run_id()
        self.run_network = {"type": network.type_key(self.network_type_var.get()),
                            "label": self.network_label_var.get().strip() or "Не указано", "org": ""}
        timeout = ui.int_from(self.timeout_var, 4, 1, 30)
        self.running = True
        self.check_btn.configure(state="disabled")
        self.data.clear()
        self.whoami.clear()
        self.verdicts.clear()
        active = {ip for ip, _ in checked}
        for ip in self.rows:
            self._reset_row(ip, ip in active)
        self.started = time.perf_counter()
        self.done_count = 0
        self.total = len(checked) * len(self.items)
        prefix = "Наблюдение: " if from_monitor else ""
        self.status_var.set(f"{prefix}проверка {len(self.items)} доменов через {len(checked)} DNS…")
        threading.Thread(target=self._worker,
                         args=(list(checked), list(self.items), timeout, self.detect_network_var.get()),
                         daemon=True).start()

    def _worker(self, servers, items, timeout, detect_network):
        with ThreadPoolExecutor(max_workers=24) as pool:
            futures = {}
            if detect_network:
                futures[pool.submit(network.detect_org)] = ("network", None, None)
            for ip, _ in servers:
                futures[pool.submit(dns_tools.whoami, ip, timeout)] = ("who", ip, None)
                for i, item in enumerate(items):
                    futures[pool.submit(xbox.check_domain, ip, item, timeout)] = ("cell", ip, i)
            for fut in as_completed(futures):
                kind, ip, i = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:  # one failed check must not stop the others
                    if kind == "who":
                        res = {"text": "—", "level": None, "dead": False, "details": str(e)}
                    elif kind == "network":
                        res = {"org": "", "country": ""}
                    else:
                        res = {"resolve": {}, "probes": [], "level": 2, "short": f"✖ сбой: {e}",
                               "owner": None, "note": "", "geo_direct": False}
                self.results.put((kind, ip, i, res))
        self.results.put(("done", None, None, None))

    def _poll(self):
        """Забирает результаты из очереди: Tkinter можно трогать только из главного потока."""
        touched = set()
        finished = False
        while not self.results.empty():
            kind, ip, i, res = self.results.get()
            if kind == "done":
                finished = True
            elif kind == "who":
                self.whoami[ip] = res
                touched.add(ip)
            elif kind == "network":
                self.run_network["org"] = network.org_text(res)
            elif kind == "feedback":
                self.feedback_sending = False
                if res.get("error"):
                    self.status_var.set(f"Отчёт сохранён локально; в облако позже. Ожидает: {res['pending']}")
                elif res.get("sent"):
                    self.status_var.set("Отчёт отправлен в общую таблицу")
            else:
                self.data[ip, i] = res
                self.done_count += 1
                touched.add(ip)
        for ip in touched:
            self._paint_row(ip)
        if touched and self.running and not finished:
            self.status_var.set(f"Проверено {self.done_count} из {self.total}…")
        if finished:
            self._finish()
        self.poll_job = self.root.after(100, self._poll)

    def _finish(self):
        self.running = False
        self.check_btn.configure(state="normal")
        kinds, names = {}, {}
        history = []
        now = datetime.now()
        for ip, name in self.checked:
            results = {i: self.data[ip, i] for i in range(len(self.items)) if (ip, i) in self.data}
            v = xbox.verdict(self.items, results, self.whoami.get(ip))
            self.verdicts[ip] = v
            kinds[ip], names[ip] = v["kind"], name
            history.append(xbox.history_row(now, ip, name, v, self.items, results,
                                            self.whoami.get(ip), self.from_monitor,
                                            self.run_id, self.run_network))
            self._paint_row(ip)
        owners.save_cache()
        history_error = ""
        if self.history_var.get() and history:
            try:
                storage.write_xbox_log(history, xbox.HISTORY_HEADER)
            except OSError:  # for example, the file is open in Excel
                history_error = "   ⚠ История не записана — xbox_log.csv открыт в другой программе?"
        if self.sort.mode == server_list.SORT_RESULT:
            self._relayout()

        good = [names[ip] or ip for ip in kinds if kinds[ip] == xbox.GOOD]
        took = time.perf_counter() - self.started
        text = (f"Готово за {took:.0f} с ({datetime.now():%H:%M:%S}).   Подходят: "
                f"{', '.join(good) if good else 'ни один'}")
        if self.monitor_var.get():
            changed = xbox.changes(self.last_kinds, kinds, names)
            if changed:
                ui.notify(self.root, "DNS для Xbox: изменения", changed)
            text += self._schedule_monitor()
        self.last_kinds.update(kinds)
        self.status_var.set(text + history_error)

    # --- monitoring in the background ---

    def _toggle_monitor(self):
        if self.monitor_var.get():
            if not self.running:
                self.start(from_monitor=True)
        else:
            if self.monitor_job:
                self.root.after_cancel(self.monitor_job)
                self.monitor_job = None
            self.status_var.set("Наблюдение выключено")

    def _schedule_monitor(self):
        """Планирует следующую проверку; возвращает текст для строки состояния."""
        if self.monitor_job:
            self.root.after_cancel(self.monitor_job)
        minutes = ui.int_from(self.monitor_minutes_var, 30, 5, 240)
        self.monitor_job = self.root.after(minutes * 60 * 1000, self._monitor_tick)
        at = datetime.now() + timedelta(minutes=minutes)
        return f"   Наблюдение: следующая проверка в {at:%H:%M}"

    def _monitor_tick(self):
        self.monitor_job = None
        if not self.monitor_var.get() or self.running:
            return
        self.start(from_monitor=True)
        if not self.running:  # nothing to check: try again later
            self._schedule_monitor()

    def shutdown(self):
        """Отменяет таймеры перед закрытием окна."""
        for job in (self.poll_job, self.monitor_job):
            if job:
                self.root.after_cancel(job)

    # --- windows and anonymous feedback ---

    def show_network_settings(self):
        dialogs.network_settings(self.root, self.network_type_var, self.network_label_var,
                                 self.detect_network_var)

    def show_feedback(self):
        dialogs.console_feedback(self.root, self.checked, self.verdicts, self.run_id,
                                 self.run_network, __version__, self._save_feedback)

    def _save_feedback(self, report):
        feedback.record_report(report)
        self.console_results[report["dns1"]] = report["outcome"]
        self.status_var.set("Отчёт сохранён локально. Отправляем в общую таблицу…")
        self._start_feedback_flush()

    def _start_feedback_flush(self):
        if self.feedback_sending or not feedback.pending_count():
            return
        self.feedback_sending = True
        threading.Thread(target=self._feedback_worker, daemon=True).start()

    def _feedback_worker(self):
        result = feedback.flush_outbox()
        self.results.put(("feedback", None, None, result))

    def show_reply(self):
        good = [(ip, name) for ip, name in self.checked
                if self.verdicts.get(ip, {}).get("kind") == xbox.GOOD]
        dns1, dns2 = reply.pick_pair(good)
        if not dns1:
            messagebox.showinfo("Ответ абоненту",
                                "Пока нет DNS с итогом «Стоит попробовать». Запустите проверку.")
            return
        text = reply.build_reply(storage.load_reply_template(), dns1, dns2)

        win = ui.toplevel(self.root, "Ответ абоненту", "700x480")
        bar = ctk.CTkFrame(win, fg_color="transparent")
        bar.pack(side="bottom", fill="x", padx=12, pady=(0, 12))
        box = ui.textbox(win, mono=False)
        box.configure(font=ui.font(13))
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", text)

        def copy_and_close():
            ui.copy_to_clipboard(self.root, box.get("1.0", "end").strip())
            self.status_var.set("Ответ абоненту скопирован в буфер обмена")
            win.destroy()

        ui.button(bar, "Скопировать и закрыть", copy_and_close, primary=True).pack(side="right")
        ui.label(bar, "Текст можно поправить здесь. Насовсем — в reply_template.txt",
                 muted=True, size=12).pack(side="left")

    def _open_history(self):
        if os.path.exists(paths.XBOX_LOG_FILE):
            os.startfile(paths.XBOX_LOG_FILE)
        else:
            messagebox.showinfo("История", "История пока пуста — сначала запустите проверку")

    def _show_who(self, server):
        res = self.whoami.get(server)
        if res:
            ui.show_text_window(self.root, f"Кто отвечает за {server}", res["details"])

    def _show_details(self, server, i):
        res = self.data.get((server, i))
        if not res:
            return
        item = self.items[i]
        r = res["resolve"]
        lines = [f"Домен:   {item['host']}  — {item.get('what', '')}", f"DNS:     {server}", ""]
        if r.get("ok"):
            lines.append(f"DNS ответил за {r['ms']:.0f} мс: {', '.join(r['ips'])}")
            if r.get("cname"):
                lines.append(f"Через CNAME: {r['cname']}")
        elif r:
            lines.append(f"DNS: {r.get('error')}")
        for p in res["probes"]:
            mode = item.get("check", "https").upper()
            lines += ["", f"Подключение к {p['ip']} ({mode}, {item.get('method', 'GET')} "
                          f"{item.get('path', '/')}):", f"  {p['text']}"]
            if p.get("attempt"):
                lines.append(f"  попытка: {p['attempt']}")
            if p.get("category"):
                lines.append(f"  категория: {p['category']}")
            if p.get("ms"):
                lines.append(f"  время: {p['ms']:.0f} мс")
            if p.get("head"):
                lines += ["", "  Начало ответа сервера:", p["head"]]
            if p.get("body"):
                lines += ["", "  Начало тела ответа (без настоящих токенов):", p["body"]]
        if res.get("owner") is not None:
            lines += ["", f"Владелец адреса: {owners.owner_text(res['owner'])}"]
            if res["owner"].get("error"):
                lines.append(f"  (сервис RDAP не ответил: {res['owner']['error']})")
        if res.get("note"):
            lines += ["", res["note"]]
        lines += ["", "Итог: " + res["short"].replace("\n", " ")]
        ui.show_text_window(self.root, f"{item['host']} через {server}", "\n".join(lines))
