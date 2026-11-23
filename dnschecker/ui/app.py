"""Главное окно: вкладки, тема, сохранение настроек при закрытии."""

import webbrowser

import customtkinter as ctk

from .. import __version__, owners, storage, version_check
from ..server_list import ServerList
from . import common as ui
from .common import C
from .servers_tab import ServersTab
from .xbox_tab import XboxTab

TAB_XBOX, TAB_SERVERS = "Xbox", "Серверы"


class App:
    def __init__(self, root):
        self.root = root
        self.settings = storage.load_settings()
        # One server list shared by both tabs.
        self.servers = ServerList(storage.load_servers())
        owners.load_cache()
        ui.setup(root)

        root.title("DNS Checker")
        root.geometry(ui.safe_geometry(root, self.settings.get("geometry", "1180x700")))
        root.minsize(1000, 520)

        self.tabs = ctk.CTkTabview(
            root, fg_color=C["bg"], corner_radius=10, anchor="w",
            segmented_button_fg_color=C["surface"],
            segmented_button_selected_color=C["surface2"],
            segmented_button_selected_hover_color=C["border"],
            segmented_button_unselected_color=C["surface"],
            segmented_button_unselected_hover_color=C["surface2"],
            text_color=C["text"])
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(4, 22))
        major, minor = __version__.split(".")
        ui.label(root, f"Версия {major} · релиз {minor}", muted=True, size=11).place(
            relx=1.0, rely=1.0, x=-16, y=-3, anchor="se")
        try:
            self.tabs._segmented_button.configure(font=ui.font(13))
        except Exception:
            pass  # private CustomTkinter attribute: may change in a new version

        xbox_page = self._page(TAB_XBOX)
        servers_page = self._page(TAB_SERVERS)
        self.servers_tab = ServersTab(self, servers_page, self.settings.get("servers_tab", {}))
        self.xbox_tab = XboxTab(self, xbox_page, self.settings.get("xbox_tab", {}))
        tab = self.settings.get("tab")
        self.tabs.set(tab if tab in (TAB_XBOX, TAB_SERVERS) else TAB_XBOX)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        version_check.check_async(__version__, self._on_version_result)

    def _on_version_result(self, result):
        """Показ из главного потока: версия новее — уведомление со ссылкой, без автообновлений."""
        if not result:
            return
        self.root.after(0, lambda: self._show_version_notice(result))

    def _show_version_notice(self, result):
        win = ui.toplevel(self.root, "Новая версия DNS Checker", "460x170")
        ui.label(win, f"Вышла версия {result['tag']} (у вас {__version__}).", size=14)\
            .pack(anchor="w", padx=16, pady=(16, 4))
        ui.label(win, "Обновление только вручную — по ссылке. Ничего не скачивается само.",
                 muted=True, size=12).pack(anchor="w", padx=16)
        bar = ctk.CTkFrame(win, fg_color="transparent")
        bar.pack(fill="x", padx=16, pady=(14, 12))
        ui.button(bar, "Открыть страницу релизов",
                  lambda: webbrowser.open(result["url"]), primary=True).pack(side="right")
        ui.button(bar, "Позже", win.destroy).pack(side="right", padx=(0, 8))

    def _page(self, name):
        """Вкладка с внутренними отступами."""
        page = ctk.CTkFrame(self.tabs.add(name), fg_color="transparent")
        page.pack(fill="both", expand=True, padx=6, pady=2)
        return page

    def collect_settings(self):
        return {"geometry": self.root.geometry(),
                "tab": self.tabs.get(),
                "servers_tab": self.servers_tab.get_settings(),
                "xbox_tab": self.xbox_tab.get_settings()}

    def on_close(self):
        storage.save_settings(self.collect_settings())
        owners.save_cache()
        self.servers_tab.shutdown()
        self.xbox_tab.shutdown()
        self.root.destroy()


def main():
    root = ctk.CTk(fg_color=C["bg"])
    App(root)
    root.mainloop()
