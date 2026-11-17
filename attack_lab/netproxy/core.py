"""TLS-blind man-in-the-middle TCP proxy ("fake Wi-Fi").

Victims connect here instead of the server. Every byte passes through, cut into TLS
records. The proxy has no key, so it can only forward, alter, drop, replay or delay
whole ciphertext records. Every *outcome* is whatever the real TLS stacks of the
victims and the server do; the proxy only observes who closes the connection and when.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from . import records as tls

ACTIONS = ("forward", "alter", "drop", "replay", "delay")
KEEP_RAW = 500  # captured records whose bytes stay available for replay / pcap
LABEL_RE = re.compile(r"CNS_DEMO_LABEL=([A-Za-z0-9_-]{1,20})")


@dataclass
class Conn:
    id: int
    label: str
    client_port: int
    opened: float
    state: str = "open"  # open | closed
    closed_by: str | None = None
    close_detail: str | None = None
    c2s_app: int = 0
    last_tamper: tuple | None = None  # (record_id, action, monotonic ts, direction)
    last_activity: float = 0.0
    writers: dict = field(default_factory=dict)
    seq: dict = field(default_factory=lambda: {"c2s": 0, "s2c": 0})

    def view(self):
        return {
            "id": self.id,
            "label": self.label,
            "port": self.client_port,
            "state": self.state,
            "closed_by": self.closed_by,
            "detail": self.close_detail,
        }


@dataclass
class Rec:
    id: int
    conn: int
    direction: str
    ts: float
    ctype: int
    kind: str
    size: int
    hex: str
    ascii: str
    status: str = "forwarded"  # pending | forwarded | altered | dropped | replayed | delayed
    note: str = ""
    raw: bytes | None = None
    app_phase: bool = False


class NetProxy:
    def __init__(
        self,
        listen=("127.0.0.1", 0),
        upstream=("127.0.0.1", 5000),
        *,
        identify=False,
        delay_seconds=3.0,
        stall_seconds=3.0,
        auto_resume=True,
        max_records=3000,
    ):
        if listen[0] not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the attacker proxy listens on loopback only")
        self.listen, self.upstream = listen, upstream
        self.identify, self.delay_seconds, self.stall_seconds = (
            identify,
            delay_seconds,
            stall_seconds,
        )
        self.auto_resume = auto_resume
        self.intercept = False
        self.port = listen[1]
        self._lock = threading.RLock()
        self._records: deque[Rec] = deque(maxlen=max_records)
        self._by_id: dict[int, Rec] = {}
        self._feed: deque[dict] = deque(maxlen=300)
        self._conns: dict[int, Conn] = {}
        self._pending: dict[int, tuple] = {}  # record id -> (future, loop)
        self._next_rec = self._next_conn = self._next_feed = 1
        self._loop = None
        self._server = None
        self._tasks: set = set()
        self.t0 = time.time()

    # ------------------------------------------------------------------ lifecycle
    async def start(self):
        self._loop = asyncio.get_running_loop()
        self._server = await asyncio.start_server(self._accept, *self.listen)
        self.port = self._server.sockets[0].getsockname()[1]
        self.event(
            "info",
            f"Mallory's proxy listening on {self.listen[0]}:{self.port}, "
            f"relaying to {self.upstream[0]}:{self.upstream[1]} (no TLS key, no TLS termination)",
        )

    async def stop(self):
        if self._server:
            self._server.close()
        for conn in list(self._conns.values()):
            for w in conn.writers.values():
                w.close()
        self.release_all()
        for t in list(self._tasks):
            t.cancel()

    # ------------------------------------------------------------------ public API (thread safe)
    def event(self, level, text, conn=None):
        with self._lock:
            self._feed.append(
                {
                    "id": self._next_feed,
                    "t": round(time.time() - self.t0, 3),
                    "level": level,
                    "text": text,
                    "conn": conn,
                }
            )
            self._next_feed += 1

    def set_intercept(self, on: bool):
        with self._lock:
            self.intercept = bool(on)
        self.event(
            "info",
            f"Intercept {'ON: application records wait for your decision' if on else 'OFF: everything is forwarded (and still captured)'}",
        )
        if not on:
            self.release_all()

    def pending_ids(self):
        with self._lock:
            return sorted(self._pending)

    def release_all(self):
        for rid in self.pending_ids():
            self.decide(rid, "forward")

    def decide(self, record_id, action, delay=None):
        if action not in ACTIONS:
            raise ValueError("unknown action")
        with self._lock:
            item = self._pending.pop(record_id, None)
        if item is None:
            raise KeyError("record is not waiting for a decision")
        fut, loop = item
        loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result((action, delay)))

    def replay(self, record_id, times=1):
        """Resend a previously captured record into its original direction, right now."""
        with self._lock:
            rec = self._by_id.get(record_id)
            conn = self._conns.get(rec.conn) if rec else None
        if rec is None or rec.raw is None:
            raise KeyError("record bytes are no longer available")
        if conn is None or conn.state != "open":
            raise ValueError(
                "that connection is closed; a new connection cannot accept an old record"
            )
        self._loop.call_soon_threadsafe(self._inject, conn, rec, times)

    def label_conn(self, conn_id, label):
        label = re.sub(r"[^A-Za-z0-9 _-]", "", label)[:20] or "Client"
        with self._lock:
            if conn_id in self._conns:
                self._conns[conn_id].label = label

    def clear(self):
        with self._lock:
            self._records.clear()
            self._by_id.clear()
            self._feed.clear()

    def snapshot(self, limit=300):
        with self._lock:
            recs = list(self._records)[-limit:]
            return {
                "intercept": self.intercept,
                "listen": f"{self.listen[0]}:{self.port}",
                "upstream": f"{self.upstream[0]}:{self.upstream[1]}",
                "conns": [c.view() for c in self._conns.values()],
                "pending": sorted(self._pending),
                "records": [self._rec_view(r) for r in recs],
                "feed": list(self._feed)[-120:],
                "delay_seconds": self.delay_seconds,
                "auto_resume": self.auto_resume,
            }

    def _rec_view(self, r):
        c = self._conns.get(r.conn)
        label = c.label if c else f"Client {r.conn}"
        arrow = f"{label} → server" if r.direction == "c2s" else f"server → {label}"
        return {
            "id": r.id,
            "conn": r.conn,
            "dir": r.direction,
            "arrow": arrow,
            "t": round(r.ts - self.t0, 3),
            "kind": r.kind,
            "ctype": r.ctype,
            "size": r.size,
            "hex": r.hex,
            "ascii": r.ascii,
            "status": r.status,
            "note": r.note,
            "app_phase": r.app_phase,
            "replayable": r.raw is not None and bool(c and c.state == "open"),
        }

    def raw_records(self):
        """(ts, conn id, client port, direction, bytes) of the bytes as received, for pcap export."""
        with self._lock:
            return [
                (r.ts, r.conn, self._conns[r.conn].client_port, r.direction, r.raw)
                for r in self._records
                if r.raw is not None and r.conn in self._conns
            ]

    # ------------------------------------------------------------------ connection handling
    def _spawn(self, coro):
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _accept(self, creader, cwriter):
        peer = cwriter.get_extra_info("peername") or ("?", 0)
        me = asyncio.current_task()
        self._tasks.add(me)
        me.add_done_callback(self._tasks.discard)
        with self._lock:
            cid = self._next_conn
            self._next_conn += 1
            conn = Conn(cid, f"Client {cid}", peer[1], time.time())
            self._conns[cid] = conn
        try:
            sreader, swriter = await asyncio.wait_for(asyncio.open_connection(*self.upstream), 5)
        except (OSError, asyncio.TimeoutError):
            self.event(
                "warn",
                f"{conn.label} (:{peer[1]}) connected but the real server is unreachable",
                cid,
            )
            conn.state = "closed"
            cwriter.close()
            return
        conn.writers = {"c2s": swriter, "s2c": cwriter}
        self.event(
            "info",
            f"New connection: {conn.label} (:{peer[1]}) ↔ server. Mallory sees only TLS records.",
            cid,
        )
        if self.identify:
            self._spawn(self._identify(conn))
        t1 = self._spawn(self._pump(conn, "c2s", creader, swriter))
        t2 = self._spawn(self._pump(conn, "s2c", sreader, cwriter))
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        await asyncio.sleep(0)
        for w in (swriter, cwriter):
            try:
                w.close()
            except Exception:
                pass
        await asyncio.wait({t1, t2}, timeout=2)
        conn.state = "closed"

    async def _identify(self, conn):
        loop = asyncio.get_running_loop()
        label = await loop.run_in_executor(None, identify_label, conn.client_port, self.port)
        if label:
            conn.label = label
            self.event("info", f"Connection {conn.id} is {label}", conn.id)

    async def _pump(self, conn, direction, reader, writer):
        buf = bytearray()
        passthrough = False
        side = "client" if direction == "c2s" else "server"
        detail = "EOF"
        try:
            while True:
                try:
                    data = await reader.read(65536)
                except (ConnectionError, OSError) as exc:
                    detail = type(exc).__name__
                    break
                if not data:
                    break
                conn.last_activity = time.monotonic()
                if passthrough:
                    await self._write(writer, data)
                    continue
                buf += data
                while True:
                    raw = tls.take_record(buf)
                    if raw is None:
                        break
                    if raw is False:
                        passthrough = True
                        self.event(
                            "warn",
                            f"{conn.label}: bytes that are not TLS; passing through unchanged",
                            conn.id,
                        )
                        await self._write(writer, bytes(buf))
                        buf.clear()
                        break
                    await self._process(conn, direction, raw, writer)
        finally:
            if conn.closed_by is None:
                conn.closed_by, conn.close_detail = side, detail
                self._report_close(conn, side, detail)
            try:
                writer.close()
            except Exception:
                pass

    async def _write(self, writer, data):
        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionError, OSError):
            pass

    def _inject(self, conn, rec, times):
        w = conn.writers.get(rec.direction)
        if w is None:
            return
        for _ in range(times):
            w.write(rec.raw)
        conn.last_tamper = (rec.id, "replay", time.monotonic(), rec.direction)
        self.event(
            "attack",
            f"REPLAY: record #{rec.id} ({rec.size} bytes, {rec.direction}) sent again",
            conn.id,
        )

    # ------------------------------------------------------------------ one record
    async def _process(self, conn, direction, raw, writer):
        payload = raw[tls.HEADER :]
        ctype = raw[0]
        if direction == "c2s" and ctype == 23:
            conn.c2s_app += 1
        # The first client application record is the TLS Finished; later ones carry chat data.
        app_phase = conn.c2s_app >= 2
        with self._lock:
            rid = self._next_rec
            self._next_rec += 1
            rec = Rec(
                rid,
                conn.id,
                direction,
                time.time(),
                ctype,
                tls.type_name(ctype, payload),
                len(raw),
                tls.hex_preview(raw),
                tls.ascii_preview(raw),
                raw=raw,
                app_phase=app_phase,
            )
            if len(self._records) == self._records.maxlen:
                self._by_id.pop(self._records[0].id, None)
            self._records.append(rec)
            self._by_id[rid] = rec
            for old in list(self._records)[:-KEEP_RAW]:
                old.raw = None
            hold = self.intercept and app_phase
        action, delay = "forward", None
        if hold:
            fut = asyncio.get_running_loop().create_future()
            with self._lock:
                self._pending[rid] = (fut, asyncio.get_running_loop())
                rec.status = "pending"
            try:
                action, delay = await fut
            except asyncio.CancelledError:
                rec.status = "abandoned"
                raise
        await self._apply(conn, direction, rec, raw, writer, action, delay)

    async def _apply(self, conn, direction, rec, raw, writer, action, delay):
        who = rec.kind
        if action == "forward":
            rec.status = "forwarded"
            await self._write(writer, raw)
            return
        conn.last_tamper = (rec.id, action, time.monotonic(), direction)
        if self.auto_resume and action in ("alter", "replay", "drop"):
            # Otherwise Mallory would hold the victims' TLS alerts and nothing visible would happen.
            if self.intercept:
                self.set_intercept(False)
                self.event(
                    "info",
                    "Intercept switched OFF after the attack so the real TLS reaction is visible",
                    conn.id,
                )
        if action == "alter":
            changed = tls.flip_bytes(raw)
            rec.status, rec.note = "altered", "1 ciphertext byte flipped"
            self.event(
                "attack",
                f"ALTER: flipped one ciphertext byte in record #{rec.id} ({rec.size} bytes, {direction}) and forwarded it",
                conn.id,
            )
            await self._write(writer, changed)
        elif action == "replay":
            rec.status, rec.note = "replayed", "forwarded, then sent a second time"
            self.event(
                "attack",
                f"REPLAY: record #{rec.id} forwarded, then the same bytes sent again",
                conn.id,
            )
            await self._write(writer, raw)
            await self._write(writer, raw)
        elif action == "drop":
            rec.status, rec.note = "dropped", "never forwarded"
            self.event(
                "attack",
                f"DROP: record #{rec.id} ({rec.size} bytes, {who}) was NOT forwarded",
                conn.id,
            )
            self._spawn(self._watch_stall(conn, rec))
        elif action == "delay":
            secs = float(delay if delay is not None else self.delay_seconds)
            rec.status, rec.note = "delayed", f"held {secs:g} s"
            self.event("attack", f"DELAY: record #{rec.id} held for {secs:g} s", conn.id)
            await asyncio.sleep(secs)
            await self._write(writer, raw)
            self.event("info", f"Delayed record #{rec.id} released", conn.id)

    async def _watch_stall(self, conn, rec):
        marker = conn.last_activity
        await asyncio.sleep(self.stall_seconds)
        if conn.state == "open" and conn.closed_by is None and conn.last_activity <= marker + 0.001:
            self.event(
                "result",
                f"STALLED: nothing arrived for {self.stall_seconds:g} s after dropping record "
                f"#{rec.id}. The message never reached its destination and nobody was told.",
                conn.id,
            )

    # ------------------------------------------------------------------ outcome reporting
    def _report_close(self, conn, side, detail):
        conn.state = "closed"
        tamper = conn.last_tamper
        now = time.monotonic()
        how = "reset" if detail != "EOF" else "closed"
        if tamper and now - tamper[2] < 30:
            rid, action, ts, direction = tamper
            ms = round((now - ts) * 1000)
            receiver = "server" if direction == "c2s" else "client"
            text = f"{conn.label}: connection {how} by the {side} {ms} ms after {action.upper()} on record #{rid}."
            if action in ("alter", "replay") and side == receiver:
                text += (
                    " The receiving TLS stack could not authenticate that record (AEAD tag check failed, "
                    "TLS bad_record_mac) and shut the connection down. This is the real TLS failure, not a simulation."
                )
            elif action == "drop":
                text += " The records after the gap no longer match TLS sequence numbers, so decryption failed."
            self.event("result", text, conn.id)
        else:
            self.event(
                "info",
                f"{conn.label}: connection {how} by the {side} (no tampering involved)",
                conn.id,
            )


def identify_label(client_port, proxy_port):
    """Best effort (macOS/Linux): name the victim from CNS_DEMO_LABEL in its environment."""
    try:
        out = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{proxy_port}", "-sTCP:ESTABLISHED", "-Fpn"],
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout
        pid = None
        cur = None
        for line in out.splitlines():
            if line.startswith("p"):
                cur = line[1:]
            elif line.startswith("n") and f":{client_port}->" in line:
                pid = cur
        if not pid:
            return None
        env = subprocess.run(
            ["ps", "eww", "-p", pid], capture_output=True, text=True, timeout=3
        ).stdout
        match = LABEL_RE.search(env)
        return match.group(1) if match else None
    except (OSError, subprocess.SubprocessError):
        return None


class ProxyRunner:
    """Runs a NetProxy (and optionally its UI) on a private event loop thread."""

    def __init__(self, proxy: NetProxy):
        self.proxy = proxy
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True, name="netproxy")
        self.extra = []

    def start(self):
        self.thread.start()
        asyncio.run_coroutine_threadsafe(self.proxy.start(), self.loop).result(10)
        return self.proxy.port

    def stop(self):
        try:
            asyncio.run_coroutine_threadsafe(self.proxy.stop(), self.loop).result(10)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(5)
