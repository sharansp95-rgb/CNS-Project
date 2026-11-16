"""Anti-aliased rounded-rectangle images for plain Tkinter, with no image files and no
third-party libraries.

Tk has no border-radius, but Tk 8.6 reads PNG (with alpha) natively. This module builds
tiny PNGs in pure Python (zlib + struct) and hands them to tk.PhotoImage. They are used:

  * as ttk "image" elements (9-slice: the corners stay crisp, the middle stretches), which
    gives real rounded ttk.Buttons with hover / pressed / disabled states;
  * as exact-size backgrounds behind a tk.Label (status chips, small pills).

Presentation only -- nothing here knows about the protocol, crypto or security checks.
"""

import base64
import math
import struct
import zlib

import tkinter as tk


def _rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def _coverage(x, y, w, h, r):
    """How much of pixel (x, y) lies inside the rounded rectangle [0,w]x[0,h], radius r
    (0..1, with a one-pixel soft edge for anti-aliasing)."""
    if w <= 0 or h <= 0:
        return 0.0
    px, py = x + 0.5, y + 0.5
    if px < 0 or py < 0 or px > w or py > h:
        return 0.0
    if r <= 0:
        return 1.0
    in_x_corner = px < r or px > w - r
    in_y_corner = py < r or py > h - r
    if not (in_x_corner and in_y_corner):
        # straight edges: soften by the distance to the edge
        return max(0.0, min(1.0, min(px, py, w - px, h - py) + 0.5))
    cx = min(max(px, r), w - r)
    cy = min(max(py, r), h - r)
    return max(0.0, min(1.0, r - math.hypot(px - cx, py - cy) + 0.5))


def rounded_png(width, height, radius, fill=None, outline=None, outline_width=1):
    """PNG bytes of a rounded rectangle. `fill` and/or `outline` are #rrggbb (None =
    transparent); everything outside the shape is fully transparent."""
    width, height = max(1, int(width)), max(1, int(height))
    radius = max(0, min(radius, width / 2, height / 2))
    f = _rgb(fill) if fill else None
    o = _rgb(outline) if outline else None
    ow = outline_width if o else 0
    rows = []
    for y in range(height):
        row = bytearray(b"\x00")
        for x in range(width):
            outer = _coverage(x, y, width, height, radius)
            if outer <= 0:
                row += b"\x00\x00\x00\x00"
                continue
            inner = (_coverage(x - ow, y - ow, width - 2 * ow, height - 2 * ow, max(radius - ow, 0))
                     if ow else outer)
            inner = min(inner, outer)
            ring = outer - inner
            if f and o:
                mix = inner / outer
                rgb = tuple(round(f[i] * mix + o[i] * (1 - mix)) for i in range(3))
                alpha = outer
            elif f:
                rgb, alpha = f, outer
            else:
                rgb, alpha = o, ring
            row += bytes(rgb) + bytes((round(alpha * 255),))
        rows.append(bytes(row))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)   # 8-bit RGBA
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))


class ImageCache:
    """PhotoImages keyed by their parameters, kept alive for the lifetime of the root
    (Tk forgets an image as soon as Python drops the last reference to it)."""

    def __init__(self, root):
        self.root = root
        self._images = {}

    def get(self, width, height, radius, fill=None, outline=None, outline_width=1):
        key = (int(width), int(height), round(radius), fill, outline, outline_width)
        image = self._images.get(key)
        if image is None:
            data = base64.b64encode(rounded_png(*key))
            image = tk.PhotoImage(master=self.root, data=data)
            self._images[key] = image
        return image

    def corners(self, radius, fill=None, outline=None, outline_width=1):
        """Four radius x radius corner tiles (top-left, top-right, bottom-left,
        bottom-right) cut from one anti-aliased rounded square."""
        r = max(1, round(radius))
        key = ("corners", r, fill, outline, outline_width)
        tiles = self._images.get(key)
        if tiles is None:
            full = self.get(2 * r, 2 * r, r, fill, outline, outline_width)
            tiles = []
            for x, y in ((0, 0), (r, 0), (0, r), (r, r)):
                tile = tk.PhotoImage(master=self.root, width=r, height=r)
                tile.tk.call(tile, "copy", full, "-from", x, y, x + r, y + r)
                tiles.append(tile)
            self._images[key] = tiles
        return tiles

    def nine_slice(self, radius, fill=None, outline=None, outline_width=1):
        """A small square image meant for a ttk image element with border=radius."""
        size = 2 * (round(radius) + 2) + 4      # crisp corners + a stretchable middle
        return self.get(size, size, radius, fill, outline, outline_width)
