"""Voice-call signaling messages, as seen by Python tools and the desktop client.

Calls happen only in the web client. Their signaling travels as ordinary chat
messages (``securechat-call/v1:{...}``), so it is signed, encrypted, hash-chained
and part of evidence. The desktop client shows :data:`PLACEHOLDER` instead and
keeps the verbatim text for chain verification. Mirrors
``web/frontend/src/calls/signal.ts``.
"""

import json
import re

PREFIX = "securechat-call/v1:"
PLACEHOLDER = "[call — web client only]"
TYPES = ("invite", "accept", "decline", "busy", "cancel", "hangup", "record")
OUTCOMES = (
    "completed",
    "no_answer",
    "missed",
    "declined",
    "busy",
    "canceled",
    "failed",
    "security_alert",
)
_HEX32 = re.compile(r"[0-9a-f]{32}")
_FP = re.compile(r"^a=fingerprint:([A-Za-z0-9-]+) ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)\s*$", re.M)


def is_call_message(message):
    return isinstance(message, str) and message.startswith(PREFIX)


def signed_fingerprint(sdp):
    found = _FP.findall(sdp)
    if not found or any(a.lower() != "sha-256" for a, _ in found):
        return None
    values = {v.upper() for _, v in found}
    return values.pop() if len(values) == 1 and len(next(iter(values)).split(":")) == 32 else None


def valid_sdp(sdp):
    if not isinstance(sdp, str) or not sdp.startswith("v=0") or len(sdp) > 24 * 1024:
        return False
    media = [line for line in sdp.splitlines() if line.startswith("m=")]
    return (
        len(media) == 1 and media[0].startswith("m=audio ") and signed_fingerprint(sdp) is not None
    )


def parse_signal(message):
    """Validate an untrusted call message; returns a dict or None."""
    if not is_call_message(message) or len(message) > 40 * 1024:
        return None
    try:
        s = json.loads(message[len(PREFIX) :])
        if not isinstance(s, dict) or s.get("v") != 1 or s.get("type") not in TYPES:
            return None
        if not isinstance(s.get("call"), str) or not _HEX32.fullmatch(s["call"]):
            return None
        if "reason" in s and (not isinstance(s["reason"], str) or len(s["reason"]) > 80):
            return None
        if s["type"] in ("invite", "accept"):
            if not valid_sdp(s.get("sdp")):
                return None
        elif "sdp" in s:
            return None
        if s["type"] == "record":

            def isint(v):
                return type(v) is int and v >= 0

            ok = (
                s.get("role") in ("caller", "callee")
                and s.get("outcome") in OUTCOMES
                and isint(s.get("started"))
                and isint(s.get("ended"))
                and isint(s.get("duration"))
                and s["duration"] <= 86400
                and s.get("fp_match") in ("yes", "no", "n/a")
                and isinstance(s.get("sas_confirmed"), bool)
                and s.get("conn") in ("direct", "relay", "none")
            )
            if not ok:
                return None
        return s
    except (ValueError, TypeError, RecursionError):
        return None
