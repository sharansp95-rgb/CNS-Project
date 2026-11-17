"""Message-level Mallory on the existing lab relay.

The relay sees only ciphertext envelopes. Mallory arms DROP, TAMPER or REPLAY for a sender; that
sender's *next* chat message gets the treatment. Nothing here decides whether an attack "worked":
the outcome feed repeats only what the receiving clients report themselves (their own
`security_alert` envelopes after their own hash-chain, AES-GCM and freshness checks).
"""

from __future__ import annotations

import time
from copy import deepcopy

from attack_lab.relay import RogueRelay

ACTIONS = ("drop", "tamper", "replay")
_LAB_ACTION = {"drop": "drop_next", "tamper": "tamper_next"}
_VERB = {
    "drop": "dropped",
    "tamper": "altered (one ciphertext byte flipped)",
    "replay": "sent twice",
}
# What the *receiving client* reports, in words. The key is the client's own reason code.
CLIENT_WORDS = {
    "chain_gap": "message missing (hash-chain gap)",
    "decryption_failed": "message was altered, rejected (AES-GCM tag failed)",
    "replay_duplicate": "duplicate or old message, rejected",
    "chain_broken": "message out of order, rejected",
}


def short(text: str, head: int = 26) -> str:
    return text if len(text) <= head else f"{text[:head]}…"


class SimpleRelay(RogueRelay):
    def __init__(self, *args, **kwargs):
        self.rows: list[dict] = []
        self.replay_armed: set[str] = set()
        self._row_id = 1
        super().__init__(*args, **kwargs)

    # ------------------------------------------------------------------ attacks
    def arm_simple(self, action: str, sender: str):
        if action not in ACTIONS:
            raise ValueError("Unknown attack")
        if not isinstance(sender, str) or not sender:
            raise ValueError("Unknown sender")
        if action == "replay":
            with self.attack_lock:
                self.pending.pop(sender, None)
                self.replay_armed.add(sender)
            self.log_event("lab_attack_armed", action="replay_next", target=sender)
        else:
            with self.attack_lock:
                self.replay_armed.discard(sender)
            self.arm(_LAB_ACTION[action], sender)  # the lab relay's own tamper_next / drop_next
        return {"armed": action, "sender": sender}

    def intercept(self, envelope, sender):
        if envelope.get("type") != "chat":
            return super().intercept(envelope, sender)
        original = deepcopy(envelope)
        with self.attack_lock:
            replay = sender in self.replay_armed
            self.replay_armed.discard(sender)
        result = super().intercept(envelope, sender)
        status = "delivered"
        if not result:
            status = "dropped"
        elif result[0].get("ciphertext") != original.get("ciphertext"):
            status = "tampered"
        elif replay:
            result = [result[0], deepcopy(result[0])]  # same bytes, same nonce, again
            status = "replayed"
            self.log_event("lab_attack_performed", action="replay_next", target=sender)
        with self.attack_lock:
            self.rows.append(
                {
                    "id": self._row_id,
                    "ts": time.time(),
                    "from": sender,
                    "to": original.get("to", ""),
                    "ct": short(original.get("ciphertext", "")),
                    "bytes": len(original.get("ciphertext", "")) * 3 // 4,
                    "status": status,
                }
            )
            self._row_id += 1
            self.rows[:] = self.rows[-200:]
        return result

    def reset_view(self):
        with self.attack_lock:
            self.rows.clear()
            self.events.clear()
            self.wire.clear()
            self.pending.clear()
            self.replay_armed.clear()
            self.held.clear()
            self.last.clear()
            self.last_large.clear()

    # ------------------------------------------------------------------ view
    def feed(self):
        out = []
        for e in list(self.events):
            kind, who = e.get("event"), e.get("target")
            if kind == "lab_attack_armed":
                name = {"drop_next": "drop", "tamper_next": "tamper", "replay_next": "replay"}.get(
                    e.get("action"), e.get("action")
                )
                out.append(
                    (
                        e["ts"],
                        "armed",
                        f"{name.upper()} armed: {who}'s next message will be {_VERB.get(name, name)}.",
                    )
                )
            elif kind == "lab_attack_performed" and e.get("action") != "replay_next":
                name = {"drop_next": "drop", "tamper_next": "tamper"}.get(e.get("action"))
                if name:
                    out.append((e["ts"], "did", f"Mallory {_VERB[name]} {who}'s message."))
            elif kind == "lab_attack_performed":
                out.append((e["ts"], "did", f"Mallory sent {who}'s message twice."))
            elif kind == "security_alert":
                reason = e.get("reason") or e.get("alert")
                words = CLIENT_WORDS.get(reason, f"reported {reason}")
                out.append((e["ts"], "result", f"{e.get('reported_by')}'s own client: {words}."))
        return [{"t": t, "kind": k, "text": x} for t, k, x in out[-40:]]

    def state(self):
        with self.attack_lock:
            armed = {s: "replay" for s in self.replay_armed}
            for s, a in self.pending.items():
                armed[s] = {"drop_next": "drop", "tamper_next": "tamper"}.get(a, a)
            rows = list(self.rows)[-60:]
        return {"rows": rows, "armed": armed, "feed": self.feed(), "online": sorted(self.clients)}
