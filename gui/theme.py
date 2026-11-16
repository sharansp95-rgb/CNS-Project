"""Design system shared by every Tkinter window in this project
(gui/chat_gui.py, gui/security_dashboard.py): palette, spacing scale, type scale,
font fallback and the ttk styles.

Presentation only -- nothing here touches the protocol, crypto or any security check.

Palette: one dark neutral family, ONE brand accent (teal), and three signal colours
used with a fixed meaning everywhere:

    teal   brand / secure / primary action
    green  success: a check passed, session established
    red    danger: something was blocked or failed
    amber  warning: Attack Lab ("lab mode") and "waiting"

Every text-on-background pair listed in `Theme.TEXT_PAIRS` is checked to have a WCAG
contrast ratio of at least 4.5:1 (tests/test_theme.py).

Scales: spacing 4/8/12/16/24/32 (`Theme.sp`) and a type scale -- title, heading, body,
caption, mono (`Theme.fonts`) -- used by every window instead of ad-hoc sizes.

Fonts are *named* tkinter Font objects, so "Presentation mode" (`set_presentation`)
can enlarge every label in a window in place, by reconfiguring the fonts.
"""

import json
import os
import sys
import tkinter.font as tkfont

from gui.rounded import ImageCache

_IS_MAC = sys.platform == "darwin"


def hand_cursor():
    """Return the correct 'pointing hand' cursor name for the current platform.

    macOS Tk supports ``pointinghand``; Windows and Linux Tk use ``hand2``.
    Using the wrong one raises ``_tkinter.TclError: bad cursor spec``.
    """
    return "pointinghand" if _IS_MAC else "hand2"


def is_no_display_error(exc):
    """True only when a TclError means 'no display server at all'.

    GUI tests should skip when Tk can't open a display (headless CI, no X11),
    but must NOT swallow other TclErrors (bad cursor, missing font, etc.) --
    those are real bugs.
    """
    msg = str(exc).lower()
    return ("no display name" in msg
            or "couldn't connect to display" in msg
            or "couldn't connect display" in msg)

# Font fallback. Tk can only use families that are installed, so _pick_font() walks a
# priority list (queryable once a Tk root exists) and takes the first one present.
# On macOS the native UI font (San Francisco, exposed to Tk as ".AppleSystemUIFont" via
# TkDefaultFont) is used first: it is what every modern Mac app is set in. Elsewhere:
# Inter -> Segoe UI Variable / Segoe UI (Windows) -> Poppins -> Helvetica Neue -> Helvetica.
SYSTEM_UI = "<system>"
UI_FONT_PRIORITY = [SYSTEM_UI, "SF Pro Text", "SF Pro", "Inter", "Segoe UI Variable Text",
                    "Segoe UI", "Poppins", "Helvetica Neue", "Helvetica", "Arial"]
MONO_FONT_PRIORITY = ["SF Mono", "JetBrains Mono", "Cascadia Mono", "Menlo", "Consolas",
                      "DejaVu Sans Mono", "Courier New", "Courier"]

# Tk on macOS renders font points at 72 dpi, so a size that reads fine on Windows
# (96 dpi) comes out roughly 25% smaller there; every size is scaled by this.
_FONT_SCALE = 1.25 if sys.platform == "darwin" else 1.0

PRESENTATION_SCALE = 1.25   # "Presentation mode": fonts and padding ~25% larger

# Spacing scale (pixels at normal size).
SPACING = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24, "xxl": 32}

# Corner radii (pixels at normal size): small controls, inputs/buttons, cards.
RADIUS = {"sm": 6, "md": 10, "lg": 14}

# Type scale: role -> (points at normal size, weight, mono?)
TYPE_SCALE = {
    "display":      (24, "bold", False),   # big KPI numbers
    "title":        (18, "bold", False),   # window / screen title
    "heading":      (12, "bold", False),   # section / card headings
    "body":         (10, "normal", False),
    "body_bold":    (10, "bold", False),
    "caption":      (9, "normal", False),
    "caption_bold": (9, "bold", False),
    "overline":     (8, "bold", False),    # small UPPERCASE section labels
    "mono":         (10, "normal", True),  # keys, hashes, ciphertext
    "mono_bold":    (10, "bold", True),
    "mono_small":   (9, "normal", True),
    "mono_small_bold": (9, "bold", True),
}


def _hex_to_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def relative_luminance(color):
    def channel(c):
        c /= 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(c) for c in _hex_to_rgb(color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg, bg):
    """WCAG 2 contrast ratio between two #rrggbb colours (1.0 .. 21.0)."""
    a, b = relative_luminance(fg), relative_luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def _pick_font(priority_list, families):
    for name in priority_list:
        if name == SYSTEM_UI:
            # Only the macOS system font is wanted here; on Linux/Windows TkDefaultFont is a
            # dated sans (DejaVu / MS Sans Serif), so fall through to the named families.
            if sys.platform == "darwin":
                return tkfont.nametofont("TkDefaultFont").actual("family")
            continue
        if name in families:
            return name
    return tkfont.nametofont("TkDefaultFont").actual("family")  # Tk's own default, last resort


# ---------------------------------------------------------------------------------
# Colour themes. Every window can switch between them at runtime (see set_mode).
#
#   dark   jet black surfaces, white text
#   light  white surfaces, near-black text
#
# Both use the same brand teal and the same signal meanings (green ok, red blocked, amber
# lab / waiting). Keys are attribute names on Theme. Two keys that share a colour in one
# theme share it in the other too, so a live switch can recolour widgets by value
# (tests/test_theme.py checks this).
# ---------------------------------------------------------------------------------
_COMMON = {
    "bg_accent": "#0f766e", "bg_accent_hover": "#0b5f58", "fg_on_accent": "#ffffff",
    "bg_danger": "#be123c", "bg_danger_hover": "#9f1239",
    "bg_lab": "#b45309", "bg_lab_hover": "#92400e",
    "fg_on_sent": "#f0fdfa",
}
PALETTES = {
    "dark": dict(_COMMON, **{
        "bg_app": "#000000", "bg_panel": "#0c0c0c", "bg_panel_alt": "#060606",
        "bg_raised": "#181818", "bg_raised_hover": "#242424", "bg_input": "#080808",
        "border": "#202020", "border_strong": "#303030",
        "fg_primary": "#f5f5f5", "fg_secondary": "#b4b4b4", "fg_hint": "#8f8f8f",
        "fg_disabled": "#555555",
        "accent": "#2dd4bf", "bg_accent_soft": "#062522",
        "success": "#4ade80", "bg_success_soft": "#07210f",
        "danger": "#fb7185", "bg_danger_soft": "#2a0a11", "danger_outline": "#5c1a28",
        "warning": "#fbbf24", "bg_warning_soft": "#241b06", "lab_outline": "#5c3d0c",
        "info": "#7cc4ff", "violet": "#c4b5fd", "wire_chat": "#5eead4", "wire_info": "#c2c2c2",
        "scroll_hover": "#4a4a4a", "glow_a": "#10786f", "glow_b": "#3730a3",
        "on_signal": "#000000",
    }),
    "light": dict(_COMMON, **{
        "bg_app": "#fefefe", "bg_panel": "#f9f9fa", "bg_panel_alt": "#f3f3f5",
        "bg_raised": "#ececef", "bg_raised_hover": "#e2e2e6", "bg_input": "#fcfcfd",
        "border": "#e4e4e7", "border_strong": "#d0d0d6",
        "fg_primary": "#0a0a0a", "fg_secondary": "#4f4f58", "fg_hint": "#62626b",
        "fg_disabled": "#a1a1aa",
        "accent": "#0d6b63", "bg_accent_soft": "#e6f6f4",
        "success": "#157a3a", "bg_success_soft": "#eaf7ef",
        "danger": "#b8173f", "bg_danger_soft": "#fdeef1", "danger_outline": "#f3b9c6",
        "warning": "#94470a", "bg_warning_soft": "#fdf4e3", "lab_outline": "#f0cf9a",
        "info": "#1d4ed8", "violet": "#6d28d9", "wire_chat": "#0b6d64", "wire_info": "#45454d",
        "scroll_hover": "#a8a8b0", "glow_a": "#99e6dc", "glow_b": "#c7c2f5",
        "on_signal": "#fefefe",
    }),
}
THEME_LABELS = {"dark": "Dark", "light": "Light"}


def _prefs_path():
    """Where the chosen theme is remembered (one small JSON file per user, outside the
    project; SECURECHAT_UI_PREFS overrides it, e.g. in tests)."""
    return os.environ.get("SECURECHAT_UI_PREFS") or os.path.join(
        os.path.expanduser("~"), ".securechat", "ui.json")


def load_theme_preference(default="dark"):
    try:
        with open(_prefs_path(), encoding="utf-8") as fh:
            mode = json.load(fh).get("theme")
    except (OSError, ValueError, AttributeError):
        return default
    return mode if mode in PALETTES else default


def save_theme_preference(mode):
    """Remember the theme for the next window that opens. Best effort: a read-only home
    directory just means the choice is not remembered."""
    path = _prefs_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"theme": mode}, fh)
    except OSError:
        pass


class Theme:
    """Palette + resolved font families + named fonts + ttk styling.
    Built once a Tk root exists (needed for the font-availability check)."""

    def __init__(self, root, mode=None):
        self.root = root
        families = set(tkfont.families(root))
        self.ui_font = _pick_font(UI_FONT_PRIORITY, families)
        self.mono_font = _pick_font(MONO_FONT_PRIORITY, families)
        self.images = ImageCache(root)

        self.mode = mode if mode in PALETTES else load_theme_preference()
        self._apply_palette(PALETTES[self.mode])

        self.presentation = False
        self.factor = 1.0
        self.fonts = {}
        for role in TYPE_SCALE:
            font = tkfont.Font(root=root, name=f"sc_{role}")
            # Don't delete the Tk font from Font.__del__: it may run after the root has
            # been destroyed (window close, tests) and the interpreter is already gone.
            font.delete_font = False
            self.fonts[role] = font
        self._configure_fonts()
        self._style = None

    def _apply_palette(self, palette):
        for key, value in palette.items():
            setattr(self, key, value)
        self.bg_lab_panel = self.bg_app       # Attack Lab window background
        # message bubbles
        self.bg_bubble_sent = self.bg_accent
        self.bg_bubble_recv = self.bg_raised
        self.fg_on_recv = self.fg_primary
        # Avatar fills (white initials on each, all >= 4.5:1), the same in both themes.
        self.avatar_colors = ["#0f766e", "#4f46e5", "#b45309", "#a21caf", "#1d4ed8", "#b91c1c"]
        # Wire-log tag colours (per message kind; all legible on bg_panel_alt).
        self.wire_handshake = self.violet
        self.wire_alert = self.danger
        self.wire_tls = self.info
        self.wire_auth = self.warning
        # legacy names (kept so older call sites keep working)
        self.fg_accent = self.accent
        self.fg_pending = self.warning
        self.fg_warning = self.danger            # NB: historically the red "warning" text
        self.fg_lab_banner = self.warning
        self.bg_fingerprint = self.bg_accent_soft
        self.bg_pending = self.bg_warning_soft
        self.wire_sent = self.wire_chat
        self.wire_recv = self.wire_handshake
        self.wire_warning = self.danger

    def set_mode(self, mode):
        """Switch the colour theme ("dark" / "light") in place. Returns {old colour: new
        colour} for every palette entry, which gui/widgets.py: recolor_tree uses to repaint
        the widgets that already exist. ttk styles are rebuilt here."""
        if mode not in PALETTES or mode == self.mode:
            return {}
        old, new = PALETTES[self.mode], PALETTES[mode]
        mapping = {old[k].lower(): new[k].lower() for k in old if old[k].lower() != new[k].lower()}
        self.mode = mode
        self._apply_palette(new)
        if self._style is not None:
            self.apply_ttk(self._style)
        return mapping

    # -- every (foreground, background) text pair that must be >= 4.5:1 --------------
    @property
    def TEXT_PAIRS(self):
        surfaces = (self.bg_app, self.bg_panel, self.bg_panel_alt, self.bg_raised)
        pairs = [(fg, bg) for fg in (self.fg_primary, self.fg_secondary, self.fg_hint,
                                      self.accent, self.success, self.danger, self.warning,
                                      self.info, self.violet) for bg in surfaces]
        pairs += [
            (self.fg_on_accent, self.bg_accent), (self.fg_on_accent, self.bg_accent_hover),
            (self.fg_on_sent, self.bg_bubble_sent), (self.fg_on_recv, self.bg_bubble_recv),
            (self.fg_on_accent, self.bg_lab), (self.fg_on_accent, self.bg_lab_hover),
            (self.fg_on_accent, self.bg_danger), (self.fg_on_accent, self.bg_danger_hover),
            (self.fg_primary, self.bg_raised_hover), (self.fg_secondary, self.bg_raised_hover),
            (self.accent, self.bg_accent_soft), (self.success, self.bg_success_soft),
            (self.danger, self.bg_danger_soft), (self.warning, self.bg_warning_soft),
            (self.fg_primary, self.bg_danger_soft), (self.fg_secondary, self.bg_danger_soft),
            (self.fg_primary, self.bg_warning_soft), (self.fg_primary, self.bg_success_soft),
            (self.fg_primary, self.bg_accent_soft), (self.fg_secondary, self.bg_accent_soft),
            (self.fg_primary, self.bg_lab_panel), (self.fg_secondary, self.bg_lab_panel),
            (self.warning, self.bg_lab_panel),
            (self.fg_secondary, self.bg_bubble_recv), (self.accent, self.bg_bubble_recv),
            (self.wire_handshake, self.bg_panel_alt), (self.wire_chat, self.bg_panel_alt),
            (self.wire_info, self.bg_panel_alt),
        ]
        pairs += [(self.fg_on_accent, c) for c in self.avatar_colors]
        return pairs

    # -- scales -----------------------------------------------------------------------
    def sp(self, step):
        """Spacing in pixels for a scale step ("xs".."xxl" or a raw size), scaled for
        Presentation mode."""
        px = SPACING[step] if isinstance(step, str) else step
        return round(px * self.factor)

    def radius(self, step="md"):
        return round(RADIUS[step] * self.factor)

    def size(self, points):
        """Font size for `points`, platform- and presentation-scaled (legacy helper;
        prefer the named `fonts`, which also follow Presentation mode live)."""
        return round(points * _FONT_SCALE * self.factor)

    def font(self, role):
        return self.fonts[role]

    def avatar_color(self, name):
        return self.avatar_colors[sum(ord(c) for c in (name or "?")) % len(self.avatar_colors)]

    def _configure_fonts(self):
        for role, (points, weight, mono) in TYPE_SCALE.items():
            self.fonts[role].configure(
                family=self.mono_font if mono else self.ui_font,
                size=round(points * _FONT_SCALE * self.factor), weight=weight)

    def set_presentation(self, on):
        """Switch Presentation mode on/off: every named font and every ttk style grows
        (or shrinks) ~25%. Returns the ratio new/old so a window can also rescale its
        padding and geometry (see gui/widgets.py: rescale_tree)."""
        old = self.factor
        self.presentation = bool(on)
        self.factor = PRESENTATION_SCALE if on else 1.0
        self._configure_fonts()
        if self._style is not None:
            self.apply_ttk(self._style)
        return self.factor / old

    # -- ttk ----------------------------------------------------------------------------
    # Every button kind: (fill, hover fill, pressed fill, text colour, outline).
    BUTTON_KINDS = {
        "TButton":           ("bg_accent", "bg_accent_hover", "bg_accent_hover", "fg_on_accent", None),
        "Secondary.TButton": ("bg_raised", "bg_raised_hover", "border_strong", "fg_primary", None),
        "Lab.TButton":       ("bg_lab", "bg_lab_hover", "bg_lab_hover", "fg_on_accent", None),
        "Danger.TButton":    ("bg_danger", "bg_danger_hover", "bg_danger_hover", "fg_on_accent", None),
        "Ghost.TButton":     (None, "bg_raised", "bg_raised_hover", "fg_secondary", "border_strong"),
    }

    def _button_element(self, style, name, kind, surface):
        """A rounded image element for one button style (normal / hover / pressed /
        disabled), plus its layout. Corners are transparent, and ttk fills them with the
        style's background, so `surface` is the colour the button sits on. `kind` is a key
        of BUTTON_KINDS ("SecondaryApp.TButton" = the Secondary look on the window bg)."""
        fill, hover, pressed, fg, outline = (getattr(self, k) if k else None
                                             for k in self.BUTTON_KINDS[kind])
        r = self.radius("md")
        img = self.images.nine_slice
        normal = img(r, fill, outline)
        states = [("disabled", img(r, self.bg_raised if fill else None,
                                   self.border if outline else None)),
                  ("pressed", img(r, pressed, outline)),
                  ("active", img(r, hover, outline))]
        element = f"{name}.{self.mode}.{r}.border"
        if element not in style.element_names():
            style.element_create(element, "image", normal, *states, border=r + 2, padding=0,
                                 sticky="nsew")
        style.layout(name, [(element, {"sticky": "nsew", "children": [
            ("Button.padding", {"sticky": "nsew", "children": [
                ("Button.label", {"sticky": "nsew"})]})]})])
        style.configure(name, background=surface, foreground=fg, font=self.fonts["body_bold"],
                        padding=(self.sp("lg"), self.sp("sm") + 1), anchor="center",
                        borderwidth=0, focusthickness=0, relief="flat")
        style.map(name, foreground=[("disabled", self.fg_disabled)],
                  background=[("disabled", surface), ("active", surface)])

    def apply_ttk(self, style):
        """ttk theming covers Frame/Label/Entry/Button/Panedwindow/Scrollbar. It does NOT
        reach raw Tk widgets (Text, Canvas, tk.Label...) -- those get colours directly
        where they are created."""
        self._style = style
        style.theme_use("clam")  # the ttk base theme that honours custom colours
        f = self.fonts
        pad_x, pad_y = self.sp("lg"), self.sp("sm")

        style.configure(".", background=self.bg_app, foreground=self.fg_primary, font=f["body"])
        style.configure("TFrame", background=self.bg_app)
        style.configure("Panel.TFrame", background=self.bg_panel)
        style.configure("TLabel", background=self.bg_app, foreground=self.fg_primary,
                        font=f["body"])
        style.configure("Panel.TLabel", background=self.bg_panel, foreground=self.fg_primary,
                        font=f["body"])
        style.configure("PanelSecondary.TLabel", background=self.bg_panel,
                        foreground=self.fg_secondary, font=f["body"])
        style.configure("Hint.TLabel", background=self.bg_panel, foreground=self.fg_hint,
                        font=f["caption"])
        style.configure("Secondary.TLabel", background=self.bg_app, foreground=self.fg_secondary,
                        font=f["caption"])
        style.configure("Title.TLabel", background=self.bg_app, foreground=self.fg_primary,
                        font=f["title"])
        style.configure("Header.TLabel", background=self.bg_panel, foreground=self.fg_primary,
                        font=f["heading"])
        style.configure("SectionTitle.TLabel", background=self.bg_panel,
                        foreground=self.fg_secondary, font=f["body_bold"])
        style.configure("Warning.TLabel", background=self.bg_app, foreground=self.danger,
                        font=f["caption_bold"])

        style.configure("TEntry", fieldbackground=self.bg_input, foreground=self.fg_primary,
                        insertcolor=self.fg_primary, bordercolor=self.border,
                        lightcolor=self.bg_input, darkcolor=self.bg_input)
        style.map("TEntry", fieldbackground=[("readonly", self.bg_input)],
                  bordercolor=[("focus", self.accent)])

        # Rounded buttons. Most sit on a panel (header, cards, input bar); the ".App"
        # variants are for buttons placed directly on the window background.
        for name in self.BUTTON_KINDS:
            self._button_element(style, name, name, self.bg_panel)
            app_name = "App.TButton" if name == "TButton" else name.replace(".TButton", "App.TButton")
            self._button_element(style, app_name, name, self.bg_app)

        # Slim, arrow-less scrollbars: a rounded thumb on an invisible track.
        thumb = self.images.nine_slice(3, self.border_strong)
        thumb_hover = self.images.nine_slice(3, self.scroll_hover)
        thumb_name = f"Slim.{self.mode}.thumb"
        if thumb_name not in style.element_names():
            style.element_create(thumb_name, "image", thumb, ("active", thumb_hover),
                                 ("pressed", thumb_hover), border=4, padding=0, sticky="nsew")
        style.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "sticky": "ns", "children": [(thumb_name, {"expand": "1", "sticky": "nswe"})]})])
        style.configure("Vertical.TScrollbar", troughcolor=self.bg_panel, background=self.bg_panel,
                        bordercolor=self.bg_panel, lightcolor=self.bg_panel,
                        darkcolor=self.bg_panel, gripcount=0, width=self.sp(10),
                        arrowsize=self.sp(10))
        style.configure("Alt.Vertical.TScrollbar", troughcolor=self.bg_panel_alt,
                        background=self.bg_panel_alt, bordercolor=self.bg_panel_alt,
                        lightcolor=self.bg_panel_alt, darkcolor=self.bg_panel_alt)
        style.layout("Alt.Vertical.TScrollbar", style.layout("Vertical.TScrollbar"))
        style.configure("TScrollbar", background=self.bg_panel, troughcolor=self.bg_panel,
                        bordercolor=self.bg_panel, arrowcolor=self.fg_secondary)

        # A thin, quiet divider between panes.
        style.configure("TPanedwindow", background=self.bg_app)
        style.configure("Sash", sashthickness=self.sp(10), gripcount=0,
                        background=self.bg_app, lightcolor=self.bg_app, bordercolor=self.bg_app)
        style.configure("TMenubutton", background=self.bg_raised, foreground=self.fg_primary,
                        font=f["body_bold"], padding=(pad_x, pad_y), borderwidth=0)
        style.map("TMenubutton", background=[("active", self.bg_raised_hover)])
