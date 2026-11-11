"""Xbox selection defaults and upgrade behavior without creating GUI widgets."""

from types import SimpleNamespace

from dnschecker import server_list
from dnschecker.ui.xbox_tab import XboxTab


class FakeModel:
    def ips(self):
        return ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def items(self):
        return [(ip, "") for ip in self.ips()]


class FakeVar:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


def make_tab():
    tab = XboxTab.__new__(XboxTab)
    tab.model = FakeModel()
    return tab


def test_first_run_of_new_version_selects_no_dns():
    assert make_tab()._initial_unchecked({}) == set(FakeModel.ips(FakeModel()))


def test_saved_unchecked_servers_are_restored():
    settings = {"selection_initialized": True, "unchecked": ["1.1.1.1"]}
    assert make_tab()._initial_unchecked(settings) == {"1.1.1.1"}


def test_legacy_selected_servers_still_migrate_after_initialization():
    settings = {"selection_initialized": True, "selected": ["8.8.8.8"]}
    assert make_tab()._initial_unchecked(settings) == {"1.1.1.1", "9.9.9.9"}


def test_missing_saved_selection_defaults_to_none_selected():
    assert make_tab()._initial_unchecked({"selection_initialized": True}) == set(
        FakeModel.ips(FakeModel()))


def test_selection_change_keeps_display_order_and_does_not_repack():
    tab = make_tab()
    tab.verdicts = {}
    tab.sort = SimpleNamespace(mode=server_list.SORT_CUSTOM)
    tab.rows = {ip: SimpleNamespace(selected=FakeVar(False)) for ip in tab.model.ips()}
    tab.display = []
    tab.repacks = 0
    tab._repack = lambda: setattr(tab, "repacks", tab.repacks + 1)

    tab._relayout()
    original = list(tab.display)
    tab.rows[original[0]].selected.set(True)
    tab._relayout()

    assert tab.display == original
    assert tab.repacks == 1
