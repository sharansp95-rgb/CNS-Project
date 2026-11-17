"""Minimal TLS record-layer framing: enough to cut a byte stream into records.

A record is ``type(1) | legacy_version(2) | length(2) | payload``. Nothing here
decrypts anything; the proxy has no keys. In TLS 1.3 everything after the
ServerHello is wrapped as type 23 ("Application Data") whatever it really is, so
the type shown to Mallory is the outer, public one.
"""

from __future__ import annotations

HEADER = 5
# RFC 8446: a protected record's payload is at most 2^14 + 256 bytes.
MAX_PAYLOAD = 16384 + 256
TYPE_NAMES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
}
HANDSHAKE_NAMES = {1: "ClientHello", 2: "ServerHello"}


def type_name(content_type: int, payload: bytes = b"") -> str:
    name = TYPE_NAMES.get(content_type, f"type {content_type}")
    if content_type == 22 and payload[:1]:
        sub = HANDSHAKE_NAMES.get(payload[0])
        if sub:
            return f"{name} ({sub})"
    return name


def plausible_header(buf) -> bool | None:
    """True if ``buf`` starts like a TLS record header, False if it cannot, None if undecided."""
    if not buf:
        return None
    if buf[0] not in TYPE_NAMES:
        return False
    if len(buf) >= 2 and buf[1] != 3:
        return False
    if len(buf) >= 3 and buf[2] > 4:
        return False
    if len(buf) >= HEADER:
        length = int.from_bytes(buf[3:5], "big")
        return 0 < length <= MAX_PAYLOAD
    return None


def take_record(buf: bytearray):
    """Remove and return one complete record from ``buf``.

    Returns ``bytes`` for a complete record, ``None`` if more input is needed, or
    ``False`` if the stream is not TLS (the caller then passes it through untouched).
    """
    ok = plausible_header(buf)
    if ok is False:
        return False
    if ok is None:
        return None
    total = HEADER + int.from_bytes(buf[3:5], "big")
    if len(buf) < total:
        return None
    record = bytes(buf[:total])
    del buf[:total]
    return record


def flip_bytes(record: bytes, count: int = 1, offset: int | None = None) -> bytes:
    """Flip bits in ``count`` payload bytes (header untouched, so framing stays valid)."""
    payload_len = len(record) - HEADER
    if payload_len <= 0:
        return record
    out = bytearray(record)
    start = payload_len // 2 if offset is None else max(0, min(offset, payload_len - 1))
    for i in range(max(1, count)):
        out[HEADER + (start + i) % payload_len] ^= 0xFF if i else 0x01
    return bytes(out)


def hex_preview(record: bytes, payload_bytes: int = 16) -> str:
    head = record[:HEADER].hex(" ")
    body = record[HEADER : HEADER + payload_bytes].hex(" ")
    return f"{head} | {body}"


def ascii_preview(record: bytes, payload_bytes: int = 16) -> str:
    return "".join(
        chr(b) if 32 <= b < 127 else "·" for b in record[HEADER : HEADER + payload_bytes]
    )
