"""Вкладка «Серверы»: живы ли DNS-серверы, список серверов, лог."""

import ipaddress
import os
import queue
import sys
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import messagebox, ttk

import customtkinter as ctk

from .. import dns_tools, paths, server_list, storage
from . import common as ui
from .common import C

SORT_OPTIONS = [(server_list.SORT_CUSTOM, "Свой порядок"), (server_list.SORT_NAME, "По названию"),
                (server_list.SORT_IP, "По IP"), (server_list.SORT_RESULT, "По статусу")]
CHECK_ON, CHECK_OFF = "☑", "☐"


class ServersTab:
    def __init__(self, app, parent, settings):
        self.app = app
        self.root = app.root
        self.model = app.servers
        self.results = queue.Queue()  # worker threads -> main thread
        self.res = {}                 # ip -> last result for the table
        self.details = {}             # ip -> text for the details window
        self.unchecked = set(settings.get("unchecked", []))
        self.running = False
        self.auto_job = None
        self.log_rows = []
        self.drag = None
        self._build(parent, settings)
        self.model.subscribe(self._render)
        self._render()
        self.status_var.set("Нажмите «Проверить»")
        self.poll_job = self.root.after(100, self._poll)

    def _build(self, parent, settings):
        top = ctk.CTkFrame(parent, fg_color="transparent")
        top.pack(fill="x", pady=(4, 6))

        self.check_btn = ui.button(top, "▶  Проверить", self.start, primary=True, width=130)
        self.check_btn.pack(side="left")
        ui.label(top, "Домен", muted=True).pack(side="left", padx=(18, 6))
        self.domain_var = tk.StringVar(value=settings.get("domain", "google.com"))
        ui.entry(top, self.domain_var, width=170).pack(side="left")
        ui.label(top, "Таймаут, с", muted=True).pack(side="left", padx=(14, 6))
        self.timeout_var = tk.StringVar(value=str(settings.get("timeout", 3)))
        ui.entry(top, self.timeout_var, width=44).pack(side="left")

        self.interval_var = tk.StringVar(value=str(settings.get("interval", 60)))
        ui.label(top, "с", muted=True).pack(side="right", padx=(6, 0))
        ui.entry(top, self.interval_var, width=54).pack(side="right")
        self.auto_var = tk.BooleanVar()
        ui.switch(top, self.auto_var, "Повторять каждые", self._toggle_auto).pack(side="right", padx=(0, 8))

        bar, self.sort = ui.selection_bar(parent, self._check_all, SORT_OPTIONS,
                                          settings.get("sort"), self._render)
        ui.label(bar, "Строку можно перетащить · двойной клик по названию — переименовать",
                 muted=True, size=12).pack(side="left", padx=10)
        bar.pack(fill="x", pady=(0, 6))

        # Table of servers.
        mid = ctk.CTkFrame(parent, fg_color=C["surface"], corner_radius=10)
        mid.pack(fill="both", expand=True)
        columns = ("check", "server", "name", "status", "time", "answer")
        self.tree = ttk.Treeview(mid, columns=columns, show="headings", selectmode="extended",
                                 style="Dark.Treeview")
        for col, title, width in (("check", "", 40), ("server", "Сервер", 140), ("name", "Название", 150),
                                  ("status", "Статус", 100), ("time", "Время", 80),
                                  ("answer", "Ответ", 380)):
            self.tree.heading(col, text=title, anchor="w")
            self.tree.column(col, width=width, minwidth=width if col == "check" else 40,
                             anchor="center" if col == "check" else "w", stretch=col == "answer")
        self.tree.tag_configure("ok", foreground=C["ok"])
        self.tree.tag_configure("fail", foreground=C["bad"])
        self.tree.tag_configure("wait", foreground=C["muted"])
        self.tree.tag_configure("off", foreground=C["muted"])
        scroll = ctk.CTkScrollbar(mid, command=self.tree.yview, button_color=C["border"],
                                  button_hover_color=C["muted"])
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scroll.pack(side="right", fill="y", padx=4, pady=8)
        self.tree.bind("<ButtonPress-1>", self._on_press)
        self.tree.bind("<B1-Motion>", self._on_drag)
        self.tree.bind("<ButtonRelease-1>", self._on_release)
        self.tree.bind("<Double-1>", self._show_details)
        self.tree.bind("<Delete>", lambda e: self.delete_selected())
        self.tree.bind("<F2>", lambda e: self.tree.focus() and self._rename(self.tree.focus()))

        bottom = ctk.CTkFrame(parent, fg_color="transparent")
        bottom.pack(fill="x", pady=(8, 0))

        self.ip_entry = ui.entry(bottom, None, width=150, placeholder_text="IP-адрес")
        self.ip_entry.pack(side="left")
        self.name_entry = ui.entry(bottom, None, width=170, placeholder_text="Название")
        self.name_entry.pack(side="left", padx=6)
        for e in (self.ip_entry, self.name_entry):
            e.bind("<Return>", lambda _e: self.add_server())
        ui.button(bottom, "Добавить", self.add_server, width=100).pack(side="left")
        ui.button(bottom, "Удалить выделенные", self.delete_selected, width=160).pack(side="left", padx=6)

        self.log_var = tk.BooleanVar(value=settings.get("log", True))
        ui.checkbox(bottom, self.log_var, "Писать лог").pack(side="right")
        if sys.platform == "win32":  # os.startfile exists only on Windows
            ui.button(bottom, "Открыть лог", self._open_log, width=110).pack(side="right", padx=10)

        self.status_var = tk.StringVar()
        ctk.CTkLabel(parent, textvariable=self.status_var, font=ui.font(12),
                     text_color=C["muted"], anchor="w").pack(fill="x", pady=(8, 0))

    def get_settings(self):
        return {"domain": self.domain_var.get().strip() or "google.com",
                "timeout": ui.int_from(self.timeout_var, 3, 1, 30),
                "interval": ui.int_from(self.interval_var, 60, 10, 3600),
                "log": self.log_var.get(),
                "sort": self.sort.mode,
                "unchecked": sorted(self.unchecked & set(self.model.ips()))}

    # --- table ---

    def _render(self):
        """Перестраивает таблицу: свой порядок или сортировка, плюс сохранённые результаты."""
        rank = {ip: (0 if r["ok"] else 1, r["ms"]) for ip, r in self.res.items() if "ok" in r}
        order = server_list.sort_servers(self.model.items(), self.sort.mode, rank, self.unchecked)
        self.tree.delete(*self.tree.get_children())
        for ip, name in order:
            r = self.res.get(ip, {})
            checked = ip not in self.unchecked
            tag = r.get("tag", "") if checked else "off"
            self.tree.insert("", "end", iid=ip, tags=(tag,), values=(
                CHECK_ON if checked else CHECK_OFF, ip, name,
                r.get("status", "—"), r.get("time", ""), r.get("answer", "")))

    def _toggle_checked(self, ip):
        """Галочка переключается, и строка сразу уходит к своей группе: отмеченные — выше."""
        self.unchecked ^= {ip}
        self._render()

    def _check_all(self, checked):
        self.unchecked = set() if checked else set(self.model.ips())
        self._render()

    def _rename(self, ip):
        """Поле для нового названия прямо поверх ячейки «Название»."""
        self.tree.see(ip)            # scroll to the row first: a hidden row has no box
        self.tree.update_idletasks()
        box = self.tree.bbox(ip, "name")
        if not box:                  # still not visible (window too small): do nothing
            return
        x, y, w, h = box
        entry = ui.inline_editor(self.tree.master, self.tree.set(ip, "name"),
                                 lambda name: self.model.rename(ip, name), width=w, height=h)
        entry.place(in_=self.tree, x=x, y=y)

    # --- drag and drop ---

    def _on_press(self, event):
        ip = self.tree.identify_row(event.y)
        if not ip:
            return
        if self.tree.identify_column(event.x) == "#1":  # click on the checkbox column
            self._toggle_checked(ip)
            return "break"
        self.drag = {"ip": ip, "moved": False}
        return None

    def _on_drag(self, event):
        if not self.drag:
            return
        target = self.tree.identify_row(event.y)
        if target and target != self.drag["ip"]:
            self.tree.move(self.drag["ip"], "", self.tree.index(target))
            self.drag["moved"] = True
        return "break"

    def _on_release(self, _event):
        drag, self.drag = self.drag, None
        if drag and drag["moved"]:
            screen = list(self.tree.get_children())
            if self.sort.mode == server_list.SORT_CUSTOM:
                # Move only the dragged server, the others keep their places.
                self.model.set_order(server_list.place_like(self.model.ips(), drag["ip"], screen))
                self._render()  # if the order did not change, put the rows back
            else:
                # Dragged in a sorted view: this sorted order becomes the user's own.
                self.sort.set(server_list.SORT_CUSTOM)
                self.model.set_order(screen)

    # --- add / delete ---

    def add_server(self):
        ip = self.ip_entry.get().strip()
        name = self.name_entry.get().strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            messagebox.showwarning("Ошибка", f"«{ip}» — не IP-адрес")
            return
        if not self.model.add(ip, name):
            messagebox.showinfo("Уже есть", f"Сервер {ip} уже в списке")
            return
        self.ip_entry.delete(0, "end")
        self.name_entry.delete(0, "end")
        self.root.focus()

    def delete_selected(self):
        selected = self.tree.selection()
        if selected and messagebox.askyesno("Удаление", f"Удалить серверов: {len(selected)}?"):
            self.model.remove(selected)

    # --- check ---

    def start(self):
        if self.running:
            return
        servers = [s for s in self.model.items() if s[0] not in self.unchecked]
        domain = self.domain_var.get().strip()
        if not servers or not domain:
            messagebox.showwarning("Нечего проверять", "Отметьте серверы галочкой и укажите домен")
            return
        timeout = ui.int_from(self.timeout_var, 3, 1, 30)
        self.running = True
        self.check_btn.configure(state="disabled")
        self.log_rows = []
        self.res = {ip: {"status": "проверка…", "tag": "wait"} for ip, _ in servers}
        self._render()
        self.status_var.set(f"Проверка {len(servers)} серверов…")
        threading.Thread(target=self._worker, args=(servers, domain, timeout), daemon=True).start()

    def _worker(self, servers, domain, timeout):
        # try/finally: "done" is always sent, even after an error.
        # Without it the "Проверить" button stayed grey until restart.
        try:
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(dns_tools.resolve, ip, domain, timeout): (ip, name)
                           for ip, name in servers}
                for fut in as_completed(futures):
                    ip, name = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:  # one broken server must not stop the others
                        res = {"ok": False, "ms": 0, "ips": [], "cname": "", "error": f"сбой: {e}"}
                    self.results.put(("result", ip, name, domain, res))
        finally:
            self.results.put(("done", None, None, None, None))

    def _poll(self):
        """Забирает результаты из очереди: Tkinter можно трогать только из главного потока."""
        while not self.results.empty():
            kind, ip, name, domain, res = self.results.get()
            if kind == "result":
                self._show_result(ip, name, domain, res)
            else:
                self._finish()
        self.poll_job = self.root.after(100, self._poll)

    def _show_result(self, ip, name, domain, res):
        answer = ", ".join(res["ips"]) if res["ok"] else res["error"]
        if res["cname"]:
            answer += f"   (через {res['cname']})"
        status = "OK" if res["ok"] else "ОШИБКА"
        ms_text = f"{res['ms']:.0f} мс"
        self.details[ip] = (f"Сервер: {ip} {name}\nДомен: {domain}\nСтатус: {status}\nВремя: "
                            f"{ms_text}\nОтвет: {answer}")
        self.res[ip] = {"ok": res["ok"], "ms": res["ms"], "status": status, "time": ms_text,
                        "answer": answer, "tag": "ok" if res["ok"] else "fail"}
        if self.tree.exists(ip):
            r = self.res[ip]
            self.tree.item(ip, tags=(r["tag"] if ip not in self.unchecked else "off",))
            for col in ("status", "time", "answer"):
                self.tree.set(ip, col, r[col])
        self.log_rows.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                              ip, name, domain, status, f"{res['ms']:.0f}", answer])

    def _finish(self):
        self.running = False
        self.check_btn.configure(state="normal")
        if self.sort.mode == server_list.SORT_RESULT:
            self._render()
        total = len(self.log_rows)
        ok = sum(1 for r in self.log_rows if r[4] == "OK")
        log_error = ""
        if self.log_var.get() and self.log_rows:
            try:
                storage.write_log(self.log_rows)
            except OSError:  # for example, the CSV is open in Excel
                # No "return" here: before, it also stopped the auto-repeat.
                log_error = "   ⚠ Лог не записан — dns_log.csv открыт в другой программе?"
        text = f"Последняя проверка: {datetime.now():%H:%M:%S}   Работают: {ok} из {total}"
        if self.auto_var.get():
            interval = ui.int_from(self.interval_var, 60, 10, 3600)
            self.auto_job = self.root.after(interval * 1000, self.start)
            text += f"   Следующая через {interval} с"
            if ok < total:
                self.root.bell()
        self.status_var.set(text + log_error)

    def shutdown(self):
        """Отменяет таймеры перед закрытием окна."""
        for job in (self.poll_job, self.auto_job):
            if job:
                self.root.after_cancel(job)

    def _toggle_auto(self):
        if self.auto_var.get():
            if not self.running:
                self.start()
        elif self.auto_job:
            self.root.after_cancel(self.auto_job)
            self.auto_job = None
            self.status_var.set("Автопроверка выключена")

    def _show_details(self, event):
        """Двойной клик: по названию — переименовать, по остальным колонкам — подробности."""
        ip = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if not ip or column == "#1":
            return
        if column == "#3":
            self._rename(ip)
            return
        ui.show_text_window(self.root, f"Подробности — {ip}",
                            self.details.get(ip, "Сервер ещё не проверялся."))

    def _open_log(self):
        if os.path.exists(paths.LOG_FILE):
            os.startfile(paths.LOG_FILE)
        else:
            messagebox.showinfo("Лог", "Лог пока пуст — сначала запустите проверку")
