"""Jet-black (dark) and white (light) colour themes, switchable live in every window and
remembered for the next window. Presentation only. Skipped where Tk has no display."""

import json
import os
import time
import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
import gui.security_dashboard as dashboard
from gui import theme as theme_module
from gui.theme import PALETTES, Theme, contrast_ratio, is_no_display_error


def test_both_palettes_have_the_same_keys_and_map_unambiguously():
    assert set(PALETTES["dark"]) == set(PALETTES["light"])
    assert PALETTES["dark"]["bg_app"] == "#000000", "dark is jet black"
    assert PALETTES["light"]["bg_app"].lower() in ("#ffffff", "#fefefe"), "light is white"
    for a, b in (("dark", "light"), ("light", "dark")):
        seen = {}
        for key, value in PALETTES[a].items():
            assert seen.setdefault(value, PALETTES[b][key]) == PALETTES[b][key], (a, key)


def test_preference_round_trip_and_bad_files_fall_back_to_dark(tmp_path, monkeypatch):
    path = tmp_path / "prefs.json"
    monkeypatch.setenv("SECURECHAT_UI_PREFS", str(path))
    assert theme_module.load_theme_preference() == "dark"
    theme_module.save_theme_preference("light")
    assert json.loads(path.read_text()) == {"theme": "light"}
    assert theme_module.load_theme_preference() == "light"
    path.write_text("not json")
    assert theme_module.load_theme_preference() == "dark"


@pytest.fixture()
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    r.update()
    yield r
    r.update()
    r.destroy()


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_every_text_pair_meets_wcag_aa_in_both_themes(root, mode):
    t = Theme(root, mode)
    failures = [(f, b) for f, b in t.TEXT_PAIRS if contrast_ratio(f, b) < 4.5]
    assert not failures


@pytest.fixture()
def chat():
    try:
        window = chat_gui.ChatGUI(theme="dark")
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    window.geometry("1040x660+10000+10000")
    window.update()
    yield window
    window.update()
    window.destroy()


def _colours(widget):
    out = set()
    for w in [widget] + list(_walk(widget)):
        try:
            out.add(str(w.cget("background")).lower())
        except tk.TclError:
            pass
    return out


def _walk(widget):
    for child in widget.winfo_children():
        yield child
        yield from _walk(child)


def test_switching_repaints_the_chat_window_live_and_keeps_the_conversation(chat):
    chat.username, chat.peer = "alice", "bob"
    chat._handle_event(
        "auth_success",
        {
            "username": "alice",
            "peer": "bob",
            "lab_mode": False,
            "own_fingerprint": "AAAA",
            "peer_key_found": True,
        },
    )
    chat._handoff_to_chat()
    chat._handle_event("handshake_established", {"peer": "bob"})
    chat._handle_event(
        "message_received",
        {"sender": "bob", "message": "hi", "timestamp": time.time(), "receipt": {}},
    )
    chat.update()
    items = list(chat._items)
    assert PALETTES["dark"]["bg_app"] in _colours(chat)

    chat.set_theme("light")
    chat.update()
    colours = _colours(chat)
    dark_only = {v for k, v in PALETTES["dark"].items() if v != PALETTES["light"][k]}
    assert not (colours & dark_only), f"left in dark colours: {colours & dark_only}"
    assert chat._items == items, "nothing in the conversation is lost"
    assert chat.theme_var.get() == "light"
    assert json.loads(open(os.environ["SECURECHAT_UI_PREFS"]).read()) == {"theme": "light"}

    chat.toggle_theme()
    assert chat.theme.mode == "dark"


def test_the_switch_is_in_the_menus_and_on_the_login_screen(chat):
    labels = [
        chat.settings_menu.entrycget(i, "label") for i in range(chat.settings_menu.index("end") + 1)
    ]
    assert any(label.startswith("Dark theme") for label in labels)
    assert any(label.startswith("Light theme") for label in labels)
    assert chat.login_theme_button.cget("text").endswith("Light mode")
    chat.login_theme_button.event_generate("<Button-1>")
    assert chat.theme.mode == "light" and chat.login_theme_button.cget("text").endswith("Dark mode")


def test_a_new_window_opens_in_the_remembered_theme(chat):
    chat.set_theme("light")
    window = dashboard.SecurityDashboard()
    try:
        window.geometry("+10000+10000")
        window.update()
        assert window.theme.mode == "light"
        window.set_theme("dark")
        window.update()
        assert window.theme_var.get() == "dark"
        assert PALETTES["dark"]["bg_app"] in _colours(window)
    finally:
        window.update()
        window.destroy()
