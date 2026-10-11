"""
Тема оформления и общие элементы интерфейса на CustomTkinter.

Тёмная тёплая палитра: графитовый фон, чуть более светлые «карточки»,
мягкие зелёный/красный/жёлтый для статусов и терракотовый акцент.
Все цвета собраны здесь — чтобы поменять вид программы, достаточно
поправить словарь C.
"""

import re
import sys
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

C = {
    "bg": "#262624",          # window background
    "surface": "#30302e",     # cards and tables
    "surface2": "#3a3a37",    # buttons, headers
    "border": "#4a4945",
    "text": "#ece9e1",
    "muted": "#9c9a92",       # secondary text
    "accent": "#d97757",      # main button (terracotta)
    "accent_hover": "#c4643f",
    "ok": "#8fc06b", "ok_bg": "#2f3d25",
    "warn": "#e3b45c", "warn_bg": "#463a22",
    "bad": "#e0786a", "bad_bg": "#4a2a24",
    "dead_bg": "#3a3a37",
}

LEVEL_FG = {0: C["ok"], 1: C["warn"], 2: C["bad"]}  # by level: 0 good, 1 doubt, 2 bad
LEVEL_BG = {0: C["ok_bg"], 1: C["warn_bg"], 2: C["bad_bg"]}
KIND_COLORS = {"good": (C["ok_bg"], C["ok"]), "doubt": (C["warn_bg"], C["warn"]),
               "bad": (C["bad_bg"], C["bad"]), "dead": (C["dead_bg"], C["muted"])}

FAMILY = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"
_fonts = {}


def font(size=13, bold=False, mono=False):
    """Шрифты создаются один раз и переиспользуются."""
    key = (size, bold, mono)
    if key not in _fonts:
        _fonts[key] = ctk.CTkFont(family=MONO if mono else FAMILY, size=size,
                                  weight="bold" if bold else "normal")
    return _fonts[key]


def setup(root):
    """Общие настройки темы. Вызывается один раз после создания окна."""
    ctk.set_appearance_mode("dark")
    style = ttk.Style(root)
    style.theme_use("clam")
    # ttk.Treeview is not part of CustomTkinter, so we paint it ourselves.
    style.configure("Dark.Treeview", background=C["surface"], fieldbackground=C["surface"],
                    foreground=C["text"], rowheight=28, borderwidth=0, font=(FAMILY, 10))
    style.configure("Dark.Treeview.Heading", background=C["surface2"], foreground=C["muted"],
                    relief="flat", borderwidth=0, font=(FAMILY, 10))
    style.map("Dark.Treeview.Heading", background=[("active", C["border"])])
    style.map("Dark.Treeview", background=[("selected", C["border"])],
              foreground=[("selected", C["text"])])
    style.layout("Dark.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])  # no border

# --- small widget helpers ---


def button(parent, text, command, primary=False, width=None, **kw):
    opts = dict(text=text, command=command, height=32, corner_radius=8, font=font(13),
                fg_color=C["accent"] if primary else C["surface2"],
                hover_color=C["accent_hover"] if primary else C["border"],
                text_color="#ffffff" if primary else C["text"],
                text_color_disabled=C["muted"])
    if width:
        opts["width"] = width
    opts.update(kw)
    return ctk.CTkButton(parent, **opts)


def label(parent, text="", muted=False, size=13, bold=False, **kw):
    return ctk.CTkLabel(parent, text=text, font=font(size, bold),
                        text_color=C["muted"] if muted else C["text"], **kw)


def entry(parent, variable, width=60, **kw):
    return ctk.CTkEntry(parent, textvariable=variable, width=width, height=32, corner_radius=8,
                        fg_color=C["surface"], border_color=C["border"], text_color=C["text"],
                        font=font(13), **kw)


def checkbox(parent, variable, text="", command=None, **kw):
    return ctk.CTkCheckBox(parent, text=text, variable=variable, command=command,
                           checkbox_width=18, checkbox_height=18, corner_radius=5, border_width=2,
                           fg_color=C["accent"], hover_color=C["accent_hover"],
                           border_color=C["muted"], text_color=C["text"], font=font(13), **kw)


def switch(parent, variable, text, command=None):
    return ctk.CTkSwitch(parent, text=text, variable=variable, command=command,
                         progress_color=C["accent"], button_color=C["text"],
                         button_hover_color="#ffffff", fg_color=C["border"],
                         text_color=C["text"], font=font(13))


class SortMenu:
    """
    Выпадающий список «Сортировка». Наружу отдаёт режим (ключ из server_list),
    а не подпись — подписи можно менять, не трогая логику и настройки.
    """

    def __init__(self, parent, options, mode, command):
        self._labels = dict(options)                                   # mode -> label
        self._modes = {label_: key for key, label_ in options}         # label -> mode
        self.var = tk.StringVar(value=self._labels.get(mode, options[0][1]))
        self.widget = ctk.CTkOptionMenu(
            parent, values=[label_ for _, label_ in options], variable=self.var,
            command=lambda _value: command(), width=150, height=30, corner_radius=8,
            fg_color=C["surface2"], button_color=C["surface2"], button_hover_color=C["border"],
            text_color=C["text"], dropdown_fg_color=C["surface2"], dropdown_hover_color=C["border"],
            dropdown_text_color=C["text"], font=font(12), dropdown_font=font(12))

    @property
    def mode(self):
        return self._modes[self.var.get()]

    def set(self, mode):
        """Меняет режим без вызова command."""
        self.var.set(self._labels[mode])


def selection_bar(parent, on_check_all, sort_options, sort_mode, on_sort):
    """
    Панель «Отметить все · Снять все ... Сортировка [..]» — одинаковая на обеих вкладках.
    on_check_all(True/False) отмечает или снимает все галочки.
    Возвращает (панель, SortMenu).
    """
    bar = ctk.CTkFrame(parent, fg_color="transparent")
    small = dict(width=110, height=28, font=font(12))
    button(bar, "Отметить все", lambda: on_check_all(True), **small).pack(side="left")
    button(bar, "Снять все", lambda: on_check_all(False), **small).pack(side="left", padx=6)
    sort_menu = SortMenu(bar, sort_options, sort_mode, on_sort)
    sort_menu.widget.pack(side="right")
    label(bar, "Сортировка", muted=True, size=12).pack(side="right", padx=(0, 8))
    return bar, sort_menu


def inline_editor(master, text, on_save, width=160, height=28):
    """
    Поле для правки текста прямо на месте (например, названия DNS).
    Enter или клик мимо — сохранить, Esc — отменить. Размещает поле вызывающий код.
    """
    entry = ctk.CTkEntry(master, width=width, height=height, corner_radius=6, border_width=1,
                         fg_color=C["surface2"], border_color=C["accent"], text_color=C["text"],
                         font=font(13))
    entry.insert(0, text)
    finished = False

    def finish(save):
        nonlocal finished
        if finished:  # FocusOut comes after Return/Escape: don't save twice
            return
        finished = True
        value = entry.get()
        entry.destroy()
        if save:
            on_save(value)

    entry.bind("<Return>", lambda e: finish(True))
    entry.bind("<Escape>", lambda e: finish(False))
    entry.bind("<FocusOut>", lambda e: finish(True))
    entry.after(10, lambda: (entry.focus_set(), entry.select_range(0, "end")))
    return entry


def toplevel(root, title, geometry):
    """Дочернее окно. CustomTkinter на Windows иногда открывает его позади главного —
    поэтому через мгновение явно поднимаем его наверх."""
    win = ctk.CTkToplevel(root, fg_color=C["bg"])
    win.title(title)
    win.geometry(geometry)
    win.after(150, lambda: (win.lift(), win.focus_force()))
    return win


def textbox(parent, mono=True, **kw):
    return ctk.CTkTextbox(parent, fg_color=C["surface"], text_color=C["text"],
                          border_width=0, corner_radius=8, wrap="word",
                          font=font(12, mono=mono), **kw)


def show_text_window(root, title, text):
    """Окно только для чтения с текстом подробностей."""
    win = toplevel(root, title, "720x460")
    box = textbox(win)
    box.pack(fill="both", expand=True, padx=12, pady=12)
    box.insert("1.0", text)
    box.configure(state="disabled")
    return win

# --- misc ---


def _screen_area(root):
    """(left, top, right, bottom) of all monitors together."""
    if sys.platform == "win32":
        try:
            import ctypes
            m = ctypes.windll.user32.GetSystemMetrics
            # 76-79 = the "virtual screen": a box around all connected monitors.
            left, top = m(76), m(77)
            return left, top, left + m(78), top + m(79)
        except Exception:
            pass
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


def safe_geometry(root, geometry):
    """
    Saved window size and position. If the position is off all screens (for example,
    the second monitor is unplugged), keep only the size, and Windows places the window.
    """
    m = re.fullmatch(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", geometry or "")
    if not m:
        return geometry
    w, h, x, y = map(int, m.groups())
    left, top, right, bottom = _screen_area(root)
    # At least 100 px of the window's top edge must be on a screen, so it can be dragged.
    # A few pixels above the screen is normal on Windows (a window at the top edge has y = -8).
    if x + w - 100 < left or x + 100 > right or y < top - 30 or y + 40 > bottom:
        return f"{w}x{h}"
    return geometry


def int_from(var, default, low, high):
    """Число из поля ввода в пределах [low, high]; при ошибке — значение по умолчанию."""
    try:
        return max(low, min(high, int(var.get())))
    except (ValueError, tk.TclError):
        var.set(str(default))
        return default


def copy_to_clipboard(root, text):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()  # keeps the text in the clipboard after the program closes


def notify(root, title, lines):
    """
    Заметное, но не мешающее уведомление: окно поверх всех в правом нижнем
    углу экрана, звуковой сигнал и «⚠» в заголовке программы (видно на панели
    задач, пока не вернёшься в окно).
    """
    win = ctk.CTkToplevel(root, fg_color=C["surface"])
    win.title(title)
    win.attributes("-topmost", True)
    label(win, title, bold=True).pack(anchor="w", padx=16, pady=(14, 4))
    for line in lines:
        color = C["ok"] if line.startswith("✔") else C["bad"]
        ctk.CTkLabel(win, text=line, font=font(13), text_color=color).pack(anchor="w", padx=16)
    button(win, "Понятно", win.destroy, primary=True, width=110).pack(anchor="e", padx=16, pady=14)
    win.update_idletasks()
    x = win.winfo_screenwidth() - win.winfo_reqwidth() - 30
    y = win.winfo_screenheight() - win.winfo_reqheight() - 80
    win.geometry(f"+{x}+{y}")
    root.bell()

    base_title = root.title().removeprefix("⚠ ")
    root.title("⚠ " + base_title)

    def reset_title(_event=None):
        root.title(base_title)
        root.unbind("<FocusIn>")
    root.bind("<FocusIn>", reset_title)
    return win
