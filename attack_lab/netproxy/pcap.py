"""Write what Mallory captured as a classic .pcap that Wireshark opens.

The proxy sees a byte stream, not packets, so each captured TLS record is framed
as one TCP segment (raw IPv4, LINKTYPE_RAW) with correct sequence numbers and
checksums. Payload bytes are exactly the bytes the proxy received from the victims
and the server; nothing is added or decrypted.
"""

from __future__ import annotations

import struct

LINKTYPE_RAW = 101
LOOP = bytes([127, 0, 0, 1])


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _segment(sport, dport, seq, ack, payload, ident):
    tcp = struct.pack(
        "!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, 0x18, 65535, 0, 0
    )
    pseudo = LOOP + LOOP + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        ident & 0xFFFF,
        0,
        64,
        6,
        0,
        LOOP,
        LOOP,
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + tcp + payload


def write_pcap(records, path, server_port) -> int:
    """records: iterable of (ts, conn_id, client_port, direction, bytes). Returns packet count."""
    seqs: dict = {}
    count = 0
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        for ts, conn, cport, direction, raw in records:
            seq = seqs.get((conn, direction), 1000)
            ack = seqs.get((conn, "s2c" if direction == "c2s" else "c2s"), 1000)
            sport, dport = (cport, server_port) if direction == "c2s" else (server_port, cport)
            packet = _segment(sport, dport, seq, ack, raw, count + 1)
            seqs[(conn, direction)] = seq + len(raw)
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(packet), len(packet)))
            fh.write(packet)
            count += 1
    return count
