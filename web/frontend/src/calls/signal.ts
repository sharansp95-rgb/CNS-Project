// Call signaling is the text of ordinary chat messages (`securechat-call/v1:{...}`).
// Each one is therefore signed with the sender's RSA identity, AES-GCM encrypted,
// hash-chained, freshness/replay checked and part of exported evidence. The relay
// sees only ciphertext. Signals are never trusted before that verification.
import { canonical } from "../crypto";
import { validateSdp } from "./sdp";

export const CALL_PREFIX = "securechat-call/v1:";
export type SignalType =
  "invite" | "accept" | "decline" | "busy" | "cancel" | "hangup" | "record";
export const OUTCOMES = [
  "completed",
  "no_answer",
  "missed",
  "declined",
  "busy",
  "canceled",
  "failed",
  "security_alert",
] as const;
export type Outcome = (typeof OUTCOMES)[number];
export interface Signal {
  v: 1;
  call: string; // 32 hex chars, chosen by the caller
  type: SignalType;
  sdp?: string;
  reason?: string;
  // `record` only: metadata about the call, never audio.
  role?: "caller" | "callee";
  outcome?: Outcome;
  started?: number; // epoch seconds the media connected (0 = never)
  ended?: number;
  duration?: number;
  fp_match?: "yes" | "no" | "n/a";
  sas_confirmed?: boolean;
  conn?: "direct" | "relay" | "none";
}
export const isCallMessage = (m: string) => m.startsWith(CALL_PREFIX);
export const encodeSignal = (s: Signal) => CALL_PREFIX + canonical(s);
const HEX32 = /^[0-9a-f]{32}$/;
const int = (v: unknown) =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
/** Strictly validate an untrusted (but already signature-verified) signal. */
export function parseSignal(message: string): Signal | null {
  if (!isCallMessage(message) || message.length > 40 * 1024) return null;
  try {
    const s = JSON.parse(message.slice(CALL_PREFIX.length));
    if (
      !s ||
      typeof s !== "object" ||
      s.v !== 1 ||
      typeof s.call !== "string" ||
      !HEX32.test(s.call)
    )
      return null;
    if (
      ![
        "invite",
        "accept",
        "decline",
        "busy",
        "cancel",
        "hangup",
        "record",
      ].includes(s.type)
    )
      return null;
    if (
      s.reason !== undefined &&
      (typeof s.reason !== "string" || s.reason.length > 80)
    )
      return null;
    if (s.type === "invite" || s.type === "accept") {
      if (validateSdp(s.sdp)) return null;
    } else if (s.sdp !== undefined) return null;
    if (s.type === "record") {
      const ok =
        (s.role === "caller" || s.role === "callee") &&
        (OUTCOMES as readonly string[]).includes(s.outcome) &&
        int(s.started) &&
        int(s.ended) &&
        int(s.duration) &&
        s.duration <= 86400 &&
        ["yes", "no", "n/a"].includes(s.fp_match) &&
        typeof s.sas_confirmed === "boolean" &&
        ["direct", "relay", "none"].includes(s.conn);
      if (!ok) return null;
    }
    return s as Signal;
  } catch {
    return null;
  }
}
