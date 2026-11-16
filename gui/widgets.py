"""Small reusable Tkinter widgets and helpers for the project's windows.

Presentation only: nothing here knows about sockets, keys or the protocol. They are
shared by gui/chat_gui.py and gui/security_dashboard.py so both windows look and behave
the same (see gui/theme.py for the palette, spacing and type scales they use).
"""

import sys
import tkinter as tk
from tkinter import ttk

from gui.theme import hand_cursor

# ---------------------------------------------------------------------------------
# Presentation-mode helpers
# ---------------------------------------------------------------------------------


def _scale_pad(value, ratio):
    """Scale a Tk padding value (an int, or an (before, after) pair)."""
    if isinstance(value, (tuple, list)):
        return tuple(round(int(v) * ratio) for v in value)
    return round(int(value) * ratio)


def rescale_tree(widget, ratio):
    """Multiply the padding of `widget` and every descendant by `ratio`: pack/grid
    padx/pady/ipadx/ipady plus the internal padx/pady of Frames and Labels.

    Fonts are NOT handled here -- they are named fonts and follow
    Theme.set_presentation() by themselves. Call this after the theme switched, with the
    ratio it returned, so a window grows consistently (text AND breathing room)."""
    for child in widget.winfo_children():
        rescale_tree(child, ratio)
    manager = widget.winfo_manager()
    try:
        if manager == "pack":
            info = widget.pack_info()
            widget.pack_configure(**{k: _scale_pad(info[k], ratio)
                                     for k in ("padx", "pady", "ipadx", "ipady")})
        elif manager == "grid":
            info = widget.grid_info()
            widget.grid_configure(**{k: _scale_pad(info[k], ratio)
                                     for k in ("padx", "pady", "ipadx", "ipady")})
    except (tk.TclError, KeyError):
        pass
    if hasattr(widget, "on_rescale"):
        widget.on_rescale()
    if isinstance(widget, (tk.Frame, tk.Label, tk.Button, tk.Toplevel)):
        for option in ("padx", "pady"):
            try:
                widget.configure(**{option: _scale_pad(widget.cget(option), ratio)})
            except tk.TclError:
                pass


_COLOR_OPTIONS = ("background", "foreground", "highlightbackground", "highlightcolor",
                  "insertbackground", "selectbackground", "disabledbackground",
                  "activebackground", "activeforeground", "disabledforeground", "troughcolor")


def recolor_tree(widget, mapping):
    """Repaint `widget` and every descendant after a theme switch: any colour option, any
    Canvas item fill/outline and any Text tag colour that equals an old palette colour gets
    the new one (`mapping` comes from Theme.set_mode). Widgets that draw from images
    (rounded frames, pills, logo) redraw themselves through an `on_theme(mapping)` hook."""
    if not mapping:
        return
    for child in widget.winfo_children():
        recolor_tree(child, mapping)

    def swap(value):
        return mapping.get(str(value).lower())

    for option in _COLOR_OPTIONS:
        try:
            new = swap(widget.cget(option))
        except (tk.TclError, AttributeError):
            continue
        if new:
            try:
                widget.configure(**{option: new})
            except tk.TclError:
                pass
    if isinstance(widget, tk.Canvas):
        for item in widget.find_all():
            for option in ("fill", "outline"):
                try:
                    new = swap(widget.itemcget(item, option))
                except tk.TclError:
                    continue
                if new:
                    widget.itemconfigure(item, **{option: new})
    if isinstance(widget, tk.Text):
        for tag in widget.tag_names():
            for option in ("foreground", "background"):
                new = swap(widget.tag_cget(tag, option))
                if new:
                    widget.tag_configure(tag, **{option: new})
    if hasattr(widget, "on_theme"):
        widget.on_theme(mapping)


def copy_to_clipboard(widget, text):
    """Put `text` on the system clipboard (via Tk, no extra dependency)."""
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update_idletasks()


def focus_when_mapped(window):
    """Raise and focus a Toplevel only after its window manager has mapped it.

    X11 discards focus requests for an unmapped window. Binding to ``<Map>``
    keeps Escape-ready dialogs consistent on Linux; the immediate path handles
    an already-visible window, such as a reopened panel.
    """
    def request_focus(_event=None):
        if window.winfo_ismapped():
            window.lift()
            window.focus_set()

    if window.winfo_ismapped():
        request_focus()
    else:
        window.bind("<Map>", request_focus, add="+")


# ---------------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------------


def rounded_rect_points(x1, y1, x2, y2, r):
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    return [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]


def draw_shield(canvas, cx, cy, size, fill, outline="", tags=()):
    """A heraldic shield centred on (cx, cy), `size` px tall."""
    w, h = size * 0.82, size
    x1, y1 = cx - w / 2, cy - h / 2
    pts = [x1, y1 + h * 0.12, cx, y1, x1 + w, y1 + h * 0.12,
           x1 + w, y1 + h * 0.52, cx, y1 + h, x1, y1 + h * 0.52]
    return [canvas.create_polygon(pts, fill=fill, outline=outline, width=1,
                                  tags=tuple(tags) + ("shield",), joinstyle="round")]


def draw_check(canvas, cx, cy, size, color, width=2, tags=()):
    s = size
    return [canvas.create_line(cx - s * 0.30, cy + s * 0.02, cx - s * 0.08, cy + s * 0.24,
                               cx + s * 0.32, cy - s * 0.22, fill=color, width=width,
                               capstyle="round", joinstyle="round", tags=tags)]


def draw_lock(canvas, cx, cy, size, color, bg, tags=()):
    """A small padlock (body + shackle) centred on (cx, cy)."""
    s = size
    bw, bh = s * 0.56, s * 0.40
    top = cy - s * 0.02
    items = [canvas.create_arc(cx - bw * 0.36, top - s * 0.36, cx + bw * 0.36, top + s * 0.12,
                               start=0, extent=180, style="arc", outline=color,
                               width=max(2, round(s * 0.09)), tags=tags),
             canvas.create_rectangle(cx - bw / 2, top, cx + bw / 2, top + bh, fill=color,
                                     outline=color, tags=tags),
             canvas.create_oval(cx - s * 0.05, top + bh * 0.28, cx + s * 0.05, top + bh * 0.28 + s * 0.10,
                                fill=bg, outline=bg, tags=tags)]
    return items


class Logo(tk.Canvas):
    """The app mark: a rounded teal tile with a white shield-and-padlock, drawn on a
    Canvas (no image files)."""

    def __init__(self, parent, theme, size=64, background=None):
        bg = background or parent.cget("background")
        super().__init__(parent, width=size, height=size, background=bg,
                         highlightthickness=0, borderwidth=0)
        self.theme = theme
        self.resize(size)

    def resize(self, size):
        t = self.theme
        self.delete("all")
        self.configure(width=size, height=size)
        self._tile = t.images.get(size, size, round(size * 0.28), t.bg_accent, t.accent)
        self.create_image(0, 0, image=self._tile, anchor="nw")
        draw_shield(self, size / 2, size / 2, size * 0.60, fill="", outline=t.fg_on_accent)
        self.itemconfigure("shield", width=max(2, round(size * 0.045)))
        draw_lock(self, size / 2, size * 0.53, size * 0.34, t.fg_on_accent, t.bg_accent)
        self._size = size

    def on_theme(self, _mapping):
        self.resize(self._size)


class Backdrop(tk.Canvas):
    """A full-window background with two soft colour glows (approximated by concentric
    ovals), used behind the login card so the first screen does not look like an empty
    box. Purely decorative: place it, then lower it below the real content."""

    def __init__(self, parent, theme, glows=None):
        super().__init__(parent, background=theme.bg_app, highlightthickness=0, borderwidth=0,
                         width=1, height=1)
        self.theme = theme
        # (relative x, relative y, radius as a fraction of the larger side, colour, strength)
        # Glows sit in the far corners so the area behind a centred card stays the plain
        # background colour (the card's rounded corners are cut against that colour).
        self._glows = glows
        self.bind("<Configure>", lambda _e: self._draw())

    @property
    def glows(self):
        t = self.theme
        return self._glows or [(0.0, 0.0, 0.46, t.glow_a, 0.42), (1.0, 1.0, 0.42, t.glow_b, 0.34)]

    def on_theme(self, _mapping):
        self.configure(background=self.theme.bg_app)
        self._draw()

    @staticmethod
    def _mix(a, b, k):
        a, b = a.lstrip("#"), b.lstrip("#")
        ca = [int(a[i:i + 2], 16) for i in (0, 2, 4)]
        cb = [int(b[i:i + 2], 16) for i in (0, 2, 4)]
        return "#" + "".join(f"{round(x + (y - x) * k):02x}" for x, y in zip(ca, cb))

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4 or h < 4:
            return
        base, steps = self.theme.bg_app, 64
        side = max(w, h)
        for rx, ry, rr, color, strength in self.glows:
            cx, cy, radius = rx * w, ry * h, rr * side
            for i in range(steps):
                k = i / (steps - 1)                 # 0 = outer edge, 1 = centre
                r = radius * (1 - k)
                if r < 2:
                    break
                tint = self._mix(base, color, strength * (k ** 2.2))
                self.create_oval(cx - r, cy - r, cx + r, cy + r, fill=tint, outline="")


class Avatar(tk.Canvas):
    """A filled circle with the person's initial (the colour comes from the name, so a
    given user is always the same colour in every window)."""

    def __init__(self, parent, theme, name, size=36, background=None):
        super().__init__(parent, width=size, height=size, background=background or theme.bg_panel,
                         highlightthickness=0, borderwidth=0)
        self.theme, self.size, self._name = theme, size, name
        self.set_name(name)

    def resize(self, size):
        self.size = size
        self.configure(width=size, height=size)
        self.set_name(self._name)

    def set_name(self, name):
        self._name = name
        self.delete("all")
        s = self.size
        self.create_oval(1, 1, s - 1, s - 1, fill=self.theme.avatar_color(name), outline="")
        self.create_text(s / 2, s / 2, text=(name or "?")[:1].upper(),
                         fill=self.theme.fg_on_accent, font=self.theme.font("heading"))


class RoundedFrame(tk.Frame):
    """A Frame with rounded corners.

    It is an ordinary tk.Frame -- pack/grid children into it and it sizes itself from
    them as usual -- with a Canvas *placed* behind the children that paints a rounded,
    anti-aliased rectangle (corners are small images, see gui/rounded.py; the straight
    parts are plain rectangles, so any size redraws instantly). Give children
    `background=frame.fill`. `surface` is the colour around the card (the parent's
    background by default), which is what shows outside the rounded corners."""

    def __init__(self, parent, theme, fill=None, outline=None, radius="lg", surface=None,
                 padx=None, pady=None, outline_width=1, **kw):
        surface = surface or parent.cget("background")
        self.theme, self.fill, self.outline, self.surface = theme, fill or theme.bg_panel, outline, surface
        self._radius_step, self._outline_width = radius, outline_width
        super().__init__(parent, background=self.fill,
                         padx=theme.sp(padx) if isinstance(padx, str) else (padx or 0),
                         pady=theme.sp(pady) if isinstance(pady, str) else (pady or 0), **kw)
        self._bg = tk.Canvas(self, background=surface, highlightthickness=0, borderwidth=0,
                             width=1, height=1)
        # bordermode="outside": cover the frame's padding too, not just its interior.
        self._bg.place(x=0, y=0, relwidth=1, relheight=1, bordermode="outside")
        self._bg.tk.call("lower", self._bg._w)   # Canvas.lower() means tag_lower
        self._bg.bind("<Configure>", lambda _e: self._draw())
        # A click on the card's padding should behave like a click on the card.
        self._bg.bind("<Button-1>", lambda e: self.event_generate("<Button-1>", x=e.x, y=e.y))

    @property
    def radius(self):
        step = self._radius_step
        return self.theme.radius(step) if isinstance(step, str) else round(step * self.theme.factor)

    def set_colors(self, fill=None, outline=False):
        """Recolour the card (outline=None removes the border; False keeps it)."""
        if fill is not None:
            self.fill = fill
            self.configure(background=fill)
        if outline is not False:
            self.outline = outline
        self._draw()

    def set_outline(self, color):
        self.set_colors(outline=color)
        # Mirrors the colour in a standard option so it can be inspected like a Frame's
        # highlight border (highlightthickness stays 0, so nothing extra is drawn).
        self.configure(highlightbackground=color or self.fill)

    def on_rescale(self):
        self._draw()

    def on_theme(self, mapping):
        swap = lambda c: mapping.get(c.lower(), c) if c else c
        self.fill, self.outline, self.surface = swap(self.fill), swap(self.outline), swap(self.surface)
        self._bg.configure(background=self.surface)
        tk.Frame.configure(self, background=self.fill)
        self._draw()

    def _draw(self):
        c = self._bg
        w, h = c.winfo_width(), c.winfo_height()
        c.delete("all")
        if w < 2 or h < 2:
            return
        r = max(1, min(self.radius, w // 2, h // 2))
        fill, line = self.fill, self.outline
        c.create_rectangle(r, 0, w - r, h, fill=fill, outline="")
        c.create_rectangle(0, r, w, h - r, fill=fill, outline="")
        tl, tr, bl, br = self.theme.images.corners(r, fill, line, self._outline_width)
        c.create_image(0, 0, image=tl, anchor="nw")
        c.create_image(w - r, 0, image=tr, anchor="nw")
        c.create_image(0, h - r, image=bl, anchor="nw")
        c.create_image(w - r, h - r, image=br, anchor="nw")
        if line:
            ow = self._outline_width
            c.create_rectangle(r, 0, w - r, ow, fill=line, outline="")
            c.create_rectangle(r, h - ow, w - r, h, fill=line, outline="")
            c.create_rectangle(0, r, ow, h - r, fill=line, outline="")
            c.create_rectangle(w - ow, r, w, h - r, fill=line, outline="")

    def accent_bar(self, color, width=None):
        """A short vertical accent stripe on the left edge (used by banners and alerts)."""
        bar = tk.Frame(self, background=color, width=width or self.theme.sp(3))
        return bar


class Pill(tk.Label):
    """A tk.Label drawn as a rounded pill: an exact-size anti-aliased image sits behind
    the text (compound="center"). The image is rebuilt whenever the text, font or wrap
    width changes, so it always hugs the text. Behaves like a normal Label otherwise
    (cget("text"), configure(...), winfo_reqwidth...)."""

    _REFRESH_OPTIONS = {"text", "font", "wraplength", "textvariable"}

    def __init__(self, parent, theme, text="", fill=None, foreground=None, font=None,
                 padx=None, pady=None, radius=None, outline=None, **kw):
        self.theme = theme
        self._fill, self._outline = fill or theme.bg_raised, outline
        self._padx = padx if padx is not None else theme.sp("sm") + 2
        self._pady = pady if pady is not None else 3
        self._radius = radius
        self._ready = False
        surface = kw.pop("background", None) or parent.cget("background")
        super().__init__(parent, text=text, background=surface,
                         foreground=foreground or theme.fg_primary,
                         font=font or theme.font("caption_bold"), compound="center",
                         padx=0, pady=0, borderwidth=0, highlightthickness=0, **kw)
        self._ready = True
        self._refresh()

    def configure(self, cnf=None, **kw):
        result = super().configure(cnf, **kw)
        if self._ready and (self._REFRESH_OPTIONS & set(kw) or
                            (isinstance(cnf, dict) and self._REFRESH_OPTIONS & set(cnf))):
            self._refresh()
        return result

    config = configure

    def set_fill(self, fill, foreground=None, outline=None):
        self._fill, self._outline = fill, outline
        if foreground is not None:
            super().configure(foreground=foreground)
        self._refresh()

    def on_rescale(self):
        self._refresh()

    def on_theme(self, mapping):
        swap = lambda c: mapping.get(c.lower(), c) if c else c
        self._fill, self._outline = swap(self._fill), swap(self._outline)
        self._refresh()

    def _refresh(self):
        # Measure the bare text (no image, no padding), then draw a pill around it.
        super().configure(image="")
        tw, th = super().winfo_reqwidth(), super().winfo_reqheight()
        if not str(self.cget("text")):
            return
        f = self.theme.factor
        w, h = tw + 2 * round(self._padx * f), th + 2 * round(self._pady * f)
        r = self._radius if self._radius is not None else min(h / 2, self.theme.radius("md"))
        self._image = self.theme.images.get(w, h, round(r), self._fill, self._outline)
        super().configure(image=self._image)


class Chip(Pill):
    """A small rounded status pill. kind: "off" (grey), "ok" (green), "info" (teal),
    "warn" (amber), "bad" (red)."""

    KINDS = {
        "off":  ("bg_raised", "fg_secondary"),
        "ok":   ("bg_success_soft", "success"),
        "info": ("bg_accent_soft", "accent"),
        "warn": ("bg_warning_soft", "warning"),
        "bad":  ("bg_danger_soft", "danger"),
        "bad_dark":  ("bg_app", "danger"),     # on top of a red card
        "warn_dark": ("bg_app", "warning"),    # on top of an amber card
    }

    def __init__(self, parent, theme, text, kind="off", mono=False, command=None):
        self.kind = kind
        bg_name, fg_name = self.KINDS[kind]
        super().__init__(parent, theme, text=text, fill=getattr(theme, bg_name),
                         foreground=getattr(theme, fg_name),
                         font=theme.font("mono_small_bold" if mono else "caption_bold"))
        if command:
            self.configure(cursor=hand_cursor())
            self.bind("<Button-1>", lambda _e: command())

    def on_theme(self, _mapping):
        self.set(self.kind)

    def set(self, kind, text=None):
        bg_name, fg_name = self.KINDS[kind]
        self.kind = kind
        if text is not None:
            tk.Label.configure(self, text=text)
        self.set_fill(getattr(self.theme, bg_name), getattr(self.theme, fg_name))


class PlaceholderText(tk.Text):
    """A multi-line input: Enter sends (<<Send>>), Shift+Enter inserts a newline, grows
    with its content up to `max_lines`, and shows grey placeholder text while empty."""

    def __init__(self, parent, theme, placeholder="", max_lines=4, **kw):
        kw.setdefault("background", theme.bg_input)
        super().__init__(parent, wrap="word", height=1, width=10, borderwidth=0, highlightthickness=0,
                         foreground=theme.fg_primary, insertbackground=theme.accent, insertwidth=2,
                         selectbackground=theme.bg_accent, selectforeground="#ffffff",
                         font=theme.font("body"), padx=theme.sp("xs"), pady=theme.sp("sm"),
                         undo=True, **kw)
        self.theme, self.placeholder, self.max_lines = theme, placeholder, max_lines
        self._showing_placeholder = False
        self.tag_configure("placeholder", foreground=theme.fg_hint)
        # The placeholder stays visible while the empty box has focus and goes away on the
        # first keystroke (or paste).
        self.bind("<FocusIn>", lambda _e: self.mark_set("insert", "1.0") if self._showing_placeholder else None)
        self.bind("<FocusOut>", lambda _e: self._show_placeholder())
        self.bind("<KeyPress>", self._on_keypress)
        self.bind("<<Paste>>", lambda _e: self._hide_placeholder(), add="+")
        self.bind("<KeyRelease>", lambda _e: self._autogrow())
        self.bind("<Return>", self._on_return)
        self.bind("<Shift-Return>", self._on_shift_return)
        self._show_placeholder()

    # --- text access that ignores the placeholder ---
    def get_text(self):
        return "" if self._showing_placeholder else self.get("1.0", "end-1c")

    def set_text(self, text):
        self._hide_placeholder()
        self.delete("1.0", "end")
        self.insert("1.0", text)
        self._autogrow()
        if not text:
            self._show_placeholder()

    def set_placeholder(self, text):
        was_showing = self._showing_placeholder
        if was_showing:
            self._hide_placeholder()
        self.placeholder = text
        if was_showing:
            self._show_placeholder()

    def _show_placeholder(self):
        if not self._showing_placeholder and not self.get("1.0", "end-1c"):
            self.insert("1.0", self.placeholder, ("placeholder",))
            self._showing_placeholder = True
            self.mark_set("insert", "1.0")

    def _hide_placeholder(self):
        if self._showing_placeholder:
            self.delete("1.0", "end")
            self._showing_placeholder = False

    def _autogrow(self):
        text = self.get("1.0", "end-1c")
        lines = 1
        if text and not self._showing_placeholder:
            try:
                counted = self.count("1.0", "end-1c", "displaylines")
                lines = int(counted[0]) if counted else text.count("\n") + 1
            except (tk.TclError, TypeError, ValueError, IndexError):
                lines = text.count("\n") + 1
        self.configure(height=max(1, min(self.max_lines, lines)))

    def _on_keypress(self, event):
        if not self._showing_placeholder:
            return None
        if event.keysym in ("BackSpace", "Delete"):
            return "break"
        if event.char and event.char.isprintable():
            self._hide_placeholder()
        return None

    def _on_return(self, _event):
        self.event_generate("<<Send>>")
        return "break"

    def _on_shift_return(self, _event):
        self._hide_placeholder()
        self.insert("insert", "\n")
        self._autogrow()
        return "break"


class StepList(tk.Frame):
    """A vertical progress list: each step is pending, active, done, error or waiting.
    The login screen ticks these off as the REAL connection steps complete."""

    GLYPH = {"pending": "○", "active": "◔", "done": "✓", "error": "✕", "waiting": "◑"}

    def __init__(self, parent, theme, background=None):
        bg = background or theme.bg_panel
        super().__init__(parent, background=bg)
        self.theme, self.bg = theme, bg
        self._rows = []

    def set_steps(self, texts):
        for row in self._rows:
            row[0].destroy()
        self._rows = []
        t = self.theme
        for text in texts:
            frame = tk.Frame(self, background=self.bg)
            frame.pack(fill="x", pady=(0, t.sp("xs")))
            glyph = tk.Label(frame, text=self.GLYPH["pending"], width=2, background=self.bg,
                             foreground=t.fg_hint, font=t.font("body_bold"))
            glyph.pack(side="left")
            label = tk.Label(frame, text=text, background=self.bg, foreground=t.fg_hint,
                             font=t.font("body"), anchor="w", justify="left", wraplength=360)
            label.pack(side="left", fill="x", expand=True)
            self._rows.append((frame, glyph, label))

    def set(self, index, state, text=None):
        t = self.theme
        if index >= len(self._rows):      # no steps shown (e.g. the list was never started)
            return
        _frame, glyph, label = self._rows[index]
        color = {"pending": t.fg_hint, "active": t.accent, "done": t.success,
                 "error": t.danger, "waiting": t.warning}[state]
        glyph.configure(text=self.GLYPH[state], foreground=color)
        label.configure(foreground=t.fg_primary if state in ("done", "active", "waiting")
                        else (t.danger if state == "error" else t.fg_hint),
                        font=t.font("body_bold" if state in ("active", "error") else "body"))
        if text is not None:
            label.configure(text=text)

    def state(self, index):
        if index >= len(self._rows):
            return "pending"
        glyph = self._rows[index][1].cget("text")
        return next(k for k, v in self.GLYPH.items() if v == glyph)


def make_card(parent, theme, background=None, border=None, padx=None, pady=None, radius="lg"):
    """A rounded card with a hairline border (the one 'card' look used by login, receipt,
    Attack Lab, dashboard...)."""
    return RoundedFrame(parent, theme, fill=background or theme.bg_panel,
                        outline=border or theme.border, radius=radius,
                        padx=padx or "lg", pady=pady or "lg")


def flat_button(parent, theme, text, command, kind="secondary", **kw):
    """A small rounded clickable pill; used where a ttk.Button would be too heavy (copy
    buttons, banner dismiss)."""
    fills = {"secondary": (theme.bg_raised, theme.bg_raised_hover, theme.fg_primary),
             "ghost": (None, theme.bg_raised, theme.fg_secondary)}
    fill, hover, fg = fills[kind]
    parent_bg = kw.pop("background", None) or parent.cget("background")
    label = Pill(parent, theme, text=text, fill=fill or parent_bg, foreground=fg,
                 background=parent_bg, cursor=hand_cursor(), **kw)
    label.bind("<Button-1>", lambda _e: command())
    colours = {"rest": fill or parent_bg, "hover": hover}
    label.bind("<Enter>", lambda _e: label.set_fill(colours["hover"]))
    label.bind("<Leave>", lambda _e: label.set_fill(colours["rest"]))
    label._hover_colours = colours

    def on_theme(mapping, _orig=label.on_theme):
        for key, value in colours.items():
            colours[key] = mapping.get(value.lower(), value)
        _orig(mapping)
    label.on_theme = on_theme
    return label


def scrolled_frame(parent, theme, background=None):
    """A vertically scrolling frame. Returns (outer, inner): pack `outer`, put content in
    `inner`."""
    bg = background or theme.bg_panel
    outer = tk.Frame(parent, background=bg)
    canvas = tk.Canvas(outer, background=bg, borderwidth=0, highlightthickness=0)
    bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, background=bg)
    window = canvas.create_window((0, 0), window=inner, anchor="nw")
    inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
    canvas.configure(yscrollcommand=bar.set)
    canvas.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    return outer, inner


class Field(RoundedFrame):
    """A single-line input in a rounded box whose border turns teal on focus and red on
    error, with an optional trailing control (e.g. the show/hide-password toggle)."""

    def __init__(self, parent, theme, textvariable, show="", width=30, trailing=None):
        super().__init__(parent, theme, fill=theme.bg_input, outline=theme.border_strong,
                         radius="md")
        self.error = False
        self.entry = tk.Entry(self, textvariable=textvariable, show=show, width=width,
                              borderwidth=0, highlightthickness=0, background=theme.bg_input,
                              foreground=theme.fg_primary, insertbackground=theme.accent,
                              insertwidth=2, disabledbackground=theme.bg_input,
                              font=theme.font("body"),
                              selectbackground=theme.bg_accent, selectforeground="#ffffff")
        self.entry.pack(side="left", fill="x", expand=True, padx=(theme.sp("md"), theme.sp("xs")),
                        pady=theme.sp("sm") + 2)
        if trailing is not None:
            trailing(self).pack(side="right", padx=(0, theme.sp("md")))
        self.entry.bind("<FocusIn>", lambda _e: self._paint(True))
        self.entry.bind("<FocusOut>", lambda _e: self._paint(False))
        self.bind("<Button-1>", lambda _e: self.entry.focus_set())

    def _paint(self, focused):
        t = self.theme
        self.set_outline(t.danger if self.error else (t.accent if focused else t.border_strong))

    def set_error(self, flag):
        self.error = bool(flag)
        self._paint(self.focus_get() is self.entry)


# ---------------------------------------------------------------------------------
# Presentation mode plumbing shared by every window
# ---------------------------------------------------------------------------------

_MAC = sys.platform == "darwin"


def presentation_accelerator():
    """Display label for the platform's presentation-mode shortcut."""
    return "⌘⇧P" if _MAC else "Ctrl+Shift+P"


def install_presentation_shortcuts(window, toggle):
    """Bind Cmd+Shift+P (Ctrl+Shift+P elsewhere) to `toggle()` in this window."""
    prefix = "Command" if _MAC else "Control"
    for letter in ("P", "p"):
        window.bind_all(f"<{prefix}-Shift-{letter}>", lambda _e: (toggle(), "break")[1])


def theme_accelerator():
    return "⌘⇧L" if _MAC else "Ctrl+Shift+L"


def install_theme_shortcuts(window, toggle):
    """Bind Cmd+Shift+L (Ctrl+Shift+L elsewhere) to `toggle()`: switch light / dark."""
    prefix = "Command" if _MAC else "Control"
    for letter in ("L", "l"):
        window.bind_all(f"<{prefix}-Shift-{letter}>", lambda _e: (toggle(), "break")[1])


def scale_window(window, ratio, margin=24):
    """Grow/shrink a window and its minimum size by `ratio`, never past the screen."""
    window.update_idletasks()
    screen_w, screen_h = window.winfo_screenwidth(), window.winfo_screenheight()
    max_w, max_h = screen_w - margin, screen_h - margin - 33     # menu bar
    min_w, min_h = window.minsize()
    window.minsize(min(round(min_w * ratio), max_w), min(round(min_h * ratio), max_h))
    width = max(window.winfo_width(), min_w)
    height = max(window.winfo_height(), min_h)
    window.geometry(f"{min(round(width * ratio), max_w)}x{min(round(height * ratio), max_h)}")
