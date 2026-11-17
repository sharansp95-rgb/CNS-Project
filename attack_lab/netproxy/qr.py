"""Tiny QR Code encoder (byte mode, error-correction level M, versions 1-6) for the terminal.

Only used to print the phone URL in the demo launcher, so it supports just what that needs
(up to 106 bytes) and has no dependencies. The output was checked by decoding rendered images
with a real QR reader (see tests/test_network_attacker.py for the structural checks).
"""

from __future__ import annotations

# version -> (data codewords, EC codewords per block, number of equal blocks); level M
_VERSIONS = {
    1: (16, 10, 1),
    2: (28, 16, 1),
    3: (44, 26, 1),
    4: (64, 18, 2),
    5: (86, 24, 2),
    6: (108, 16, 4),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34]}
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs_remainder(data: list[int], degree: int) -> list[int]:
    gen = [1]
    for i in range(degree):  # product of (x - alpha^i)
        nxt = [0] * (len(gen) + 1)
        for j, coef in enumerate(gen):
            nxt[j] ^= coef
            nxt[j + 1] ^= _mul(coef, _EXP[i])
        gen = nxt
    rem = [0] * degree
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for i in range(degree):
            rem[i] ^= _mul(gen[i + 1], factor)
    return rem


def _codewords(payload: bytes) -> tuple[int, list[int]]:
    for version, (data_cw, ec_cw, blocks) in _VERSIONS.items():
        if len(payload) + 2 <= data_cw:  # 4-bit mode + 8-bit count + data, rounded up
            break
    else:
        raise ValueError("text too long for this tiny QR encoder")
    bits = "0100" + format(len(payload), "08b") + "".join(format(b, "08b") for b in payload)
    bits += "0" * min(4, data_cw * 8 - len(bits))
    bits += "0" * (-len(bits) % 8)
    data = [int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    while len(data) < data_cw:
        data.append(pad[(len(data) - len(bits) // 8) % 2])
    size = data_cw // blocks
    chunks = [data[i * size : (i + 1) * size] for i in range(blocks)]
    ecs = [_rs_remainder(c, ec_cw) for c in chunks]
    out = [chunks[b][i] for i in range(size) for b in range(blocks)]
    out += [ecs[b][i] for i in range(ec_cw) for b in range(blocks)]
    return version, out


def _format_bits(mask: int) -> int:
    data = (0b00 << 3) | mask  # level M = 00
    rem = data << 10
    for i in range(4, -1, -1):
        if rem >> (i + 10) & 1:
            rem ^= 0x537 << i
    return ((data << 10) | rem) ^ 0x5412


def _build(version: int, codewords: list[int], mask: int):
    n = 17 + 4 * version
    mod = [[False] * n for _ in range(n)]
    func = [[False] * n for _ in range(n)]

    def put(r, c, dark, is_func=True):
        if 0 <= r < n and 0 <= c < n:
            mod[r][c] = dark
            func[r][c] = is_func

    for r0, c0 in ((0, 0), (0, n - 7), (n - 7, 0)):  # finders with separators
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                ring = max(abs(dr - 3), abs(dc - 3))
                put(r0 + dr, c0 + dc, ring != 2 and ring != 4 and 0 <= dr < 7 and 0 <= dc < 7)
    for i in range(8, n - 8):  # timing
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    pos = _ALIGN[version]
    for r in pos:
        for c in pos:
            if func[r][c]:
                continue  # overlaps a finder
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    put(r + dr, c + dc, max(abs(dr), abs(dc)) != 1)
    put(n - 8, 8, True)  # dark module
    fmt = _format_bits(mask)
    for i in range(15):
        bit = bool(fmt >> i & 1)
        # first copy, around the top-left finder
        if i < 6:
            put(i, 8, bit)
        elif i < 8:
            put(i + 1, 8, bit)
        elif i == 8:
            put(8, 7, bit)
        else:
            put(8, 14 - i, bit)
        # second copy, split between the other two finders
        if i < 8:
            put(8, n - 1 - i, bit)
        else:
            put(n - 15 + i, 8, bit)
    bits = [b >> s & 1 for b in codewords for s in range(7, -1, -1)]
    i = 0
    col, up = n - 1, True
    while col > 0:
        if col == 6:
            col -= 1
        for step in range(n):
            r = n - 1 - step if up else step
            for c in (col, col - 1):
                if not func[r][c]:
                    dark = bool(bits[i]) if i < len(bits) else False
                    i += 1
                    flip = (
                        (r + c) % 2 == 0,
                        r % 2 == 0,
                        c % 3 == 0,
                        (r + c) % 3 == 0,
                        (r // 2 + c // 3) % 2 == 0,
                        (r * c) % 2 + (r * c) % 3 == 0,
                        ((r * c) % 2 + (r * c) % 3) % 2 == 0,
                        ((r + c) % 2 + (r * c) % 3) % 2 == 0,
                    )[mask]
                    mod[r][c] = dark != flip
        up = not up
        col -= 2
    return mod


def _penalty(m) -> int:
    n = len(m)
    score = 0
    for grid in (m, [list(col) for col in zip(*m)]):
        for row in grid:
            run = 1
            for i in range(1, n):
                if row[i] == row[i - 1]:
                    run += 1
                    if run == 5:
                        score += 3
                    elif run > 5:
                        score += 1
                else:
                    run = 1
            s = "".join("1" if v else "0" for v in row)
            score += 40 * (s.count("10111010000") + s.count("00001011101"))
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r + 1][c] == m[r][c + 1] == m[r + 1][c + 1]:
                score += 3
    dark = sum(v for row in m for v in row)
    score += 10 * (abs(dark * 100 // (n * n) - 50) // 5)
    return score


def encode(text: str) -> list[list[bool]]:
    """Return the QR module matrix (True = dark)."""
    version, words = _codewords(text.encode("utf-8"))
    return min((_build(version, words, mask) for mask in range(8)), key=_penalty)


def render_terminal(text: str, quiet: int = 3) -> str:
    """Black-on-white QR using half-block characters; explicit colours work on any theme."""
    m = encode(text)
    n = len(m)
    size = n + 2 * quiet
    grid = [[False] * size for _ in range(size)]
    for r in range(n):
        for c in range(n):
            grid[r + quiet][c + quiet] = m[r][c]
    if size % 2:
        grid.append([False] * size)
    lines = []
    for r in range(0, len(grid), 2):
        row = ""
        for c in range(size):
            top, bottom = grid[r][c], grid[r + 1][c]
            row += f"\x1b[{30 if top else 37};{40 if bottom else 47}m▀"
        lines.append(row + "\x1b[0m")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    print(render_terminal(sys.argv[1]))
