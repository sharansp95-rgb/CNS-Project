"""Lab-only control labels and interpretation of real client reports."""

from gui.explain import HANDSHAKE_SIGNATURE as HANDSHAKE_SIGNATURE
from gui.explain import REJECTIONS

# --- Attack Lab cards -----------------------------------------------------------------
#
# What each one-shot relay attack is, which defence is EXPECTED to catch it, and which
# report from the victim's client proves it was. The attacker's own client is never told
# whether the victim caught the attack; the victim's client reports its real detection to
# the server (a `security_alert`), which logs it. `find_lab_detection` looks for exactly
# that record -- it never decides anything itself.

LAB_ATTACKS = [
    {
        "action": "tamper_next",
        "label": "Tamper next message",
        "title": "Tamper",
        "glyph": "✂",
        "desc": "The relay flips one byte of your next message in transit.",
        "check": REJECTIONS["decryption_failed"]["check"],
        "alert": "message_rejected",
        "reason": "decryption_failed",
        "armed": "Armed: send a message now",
    },
    {
        "action": "replay_last",
        "label": "Replay last message",
        "title": "Replay",
        "glyph": "↻",
        "desc": "The relay immediately resends your most recent message a second time.",
        "check": REJECTIONS["replay_duplicate"]["check"],
        "alert": "message_rejected",
        "reason": "replay_duplicate",
        "armed": "Armed: replaying now",
    },
    {
        "action": "drop_next",
        "label": "Drop next message",
        "title": "Drop",
        "glyph": "⊘",
        "desc": "The relay silently discards your next message; it never reaches your peer.",
        "check": REJECTIONS["chain_gap"]["check"],
        "alert": "chain_warning",
        "reason": "chain_gap",
        "armed": "Armed: send two messages (the gap shows on the second)",
    },
]
LAB_BY_ACTION = {a["action"]: a for a in LAB_ATTACKS}
LAB_SILENT_AFTER_SECONDS = 10


def find_lab_detection(action, events, victim, since):
    """The victim's own report of catching `action`, from the security log, or None.

    `events` are security-log records; a match must be a `security_alert` reported by
    `victim`, logged at or after `since`, with the alert kind (and reason, where the
    attack has one) that this attack should trigger."""
    attack = LAB_BY_ACTION[action]
    for event in events:
        if (
            event.get("event") == "security_alert"
            and event.get("reported_by") == victim
            and float(event.get("ts", 0)) >= since
            and event.get("alert") == attack["alert"]
            and (attack["reason"] is None or event.get("reason") == attack["reason"])
        ):
            return event
    return None


def lab_status(state, action, peer, detail=None):
    """(chip kind, text) for an Attack Lab card. `state` is idle, arming, armed, fired,
    caught, silent or rejected."""
    attack = LAB_BY_ACTION[action]
    return {
        "idle": ("off", "Not armed"),
        "arming": ("warn", "Arming..."),
        "armed": ("warn", attack["armed"]),
        "fired": ("warn", f"Fired. Waiting for {peer}'s check..."),
        "caught": ("ok", f"Caught by {attack['check']} (reported by {peer})"),
        "silent": ("warn", f"No report from {peer} yet. Watch {peer}'s window."),
        "rejected": ("bad", f"Rejected: {detail}"),
    }[state]
