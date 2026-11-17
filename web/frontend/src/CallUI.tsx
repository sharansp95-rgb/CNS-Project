import React, { useEffect, useState } from "react";
import type { Session } from "./session";
import { parseSignal, isCallMessage, type Signal } from "./calls/signal";

const clock = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
const OUTCOME: Record<string, string> = {
  completed: "Call", no_answer: "No answer", missed: "Missed call", declined: "Call declined",
  busy: "Peer was busy", canceled: "Call canceled", failed: "Call failed", security_alert: "Call ended: security alert",
};
export function callLine(sig: Signal): string {
  const parts = [OUTCOME[sig.outcome!] ?? "Call"];
  if (sig.duration) parts.push(clock(sig.duration));
  if (sig.conn && sig.conn !== "none") parts.push(sig.conn === "relay" ? "via relay" : "direct");
  parts.push(sig.fp_match === "yes" ? (sig.sas_confirmed ? "verified" : "fingerprint checked") : sig.fp_match === "no" ? "FINGERPRINT MISMATCH" : "unverified");
  return "📞 " + parts.join(" · ");
}
/** Signaling messages are hidden; only your own call records appear as chat log lines. */
export function callLogEntry(session: Session, item: { sender: string; message: string }, key: number) {
  if (!isCallMessage(item.message)) return undefined;
  const sig = parseSignal(item.message);
  if (sig?.type !== "record" || item.sender !== session.username) return null;
  return (
    <div key={key} className="call-log" data-testid="call-log">
      {callLine(sig)}
    </div>
  );
}
export function CallButton({ session, onError }: { session: Session; onError: (m: string) => void }) {
  return (
    <button
      aria-label="Start voice call"
      disabled={!session.calls.canCall}
      onClick={() => session.calls.start().catch((e) => onError((e as Error).message))}
    >
      📞 Call
    </button>
  );
}
export function CallOverlay({ session }: { session: Session }) {
  const call = session.calls.info,
    [, tick] = useState(0),
    [dismissed, setDismissed] = useState("");
  useEffect(() => {
    if (call?.state !== "active") return;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [call?.state]);
  const ended = session.calls.lastEnded;
  if (!call) {
    if (ended?.alert && dismissed !== ended.id)
      return (
        <div className="call-panel call-alert" role="alert">
          <strong>{ended.alert}</strong>
          <button onClick={() => setDismissed(ended.id)}>Dismiss</button>
        </div>
      );
    if (session.calls.lastError)
      return (
        <div className="call-panel call-alert" role="alert">
          <strong>{session.calls.lastError}</strong>
          <button onClick={() => { session.calls.lastError = ""; tick((n) => n + 1); }}>Dismiss</button>
        </div>
      );
    return null;
  }
  const seconds = call.startedAt ? Math.floor(Date.now() / 1000) - call.startedAt : 0;
  const verified = call.fpStatus === "match" && call.sasConfirmed;
  return (
    <section className="call-panel" role="dialog" aria-label="Voice call" data-state={call.state} data-inbound-bytes={call.inboundBytes} data-track-enabled={String(call.trackEnabled)} onClick={() => session.calls.resumeAudio()}>
      <div className="eyebrow">VOICE CALL · END-TO-END ENCRYPTED SIGNALING · DTLS-SRTP MEDIA</div>
      <h3>
        {call.state === "ringing" && `Incoming call from ${session.peer}`}
        {call.state === "calling" && `Calling ${session.peer}…`}
        {call.state === "connecting" && "Connecting…"}
        {call.state === "active" && `On a call with ${session.peer}`}
      </h3>
      {call.state === "active" && <p className="call-timer" aria-label="Call duration">{clock(seconds)}</p>}
      {call.state === "ringing" && (
        <div className="call-actions">
          <button className="primary" onClick={() => void session.calls.accept()}>Accept</button>
          <button onClick={() => session.calls.decline()}>Decline</button>
        </div>
      )}
      {(call.state === "calling" || call.state === "connecting") && (
        <div className="call-actions"><button onClick={() => session.calls.hangup()}>Cancel</button></div>
      )}
      {call.state === "active" && (
        <>
          <ul className="call-facts">
            <li data-testid="call-conn">
              {call.conn === "relay"
                ? "Connection: via relay (TURN). The relay forwards only encrypted audio (SRTP) and cannot listen."
                : call.conn === "direct"
                  ? "Connection: direct (peer to peer)"
                  : "Connection: detecting…"}
            </li>
            <li data-testid="call-fp">
              {call.fpStatus === "match" && "✓ DTLS certificate matches the fingerprint your contact signed"}
              {call.fpStatus === "pending" && "Checking DTLS certificate…"}
              {call.fpStatus === "unavailable" && "⚠ Certificate check unavailable in this browser"}
              {call.fpStatus === "mismatch" && "✗ Certificate mismatch"}
            </li>
            <li data-testid="call-quality">Network quality: {call.quality}</li>
            {call.turn === "unavailable" && <li>Relay unavailable: this call can connect directly only.</li>}
          </ul>
          <div className="call-sas">
            <span>Read these words aloud. They must be identical on both screens:</span>
            <strong data-testid="call-words">{call.words.join(" · ")}</strong>
            {verified ? (
              <span className="call-verified" data-testid="call-verified">✓ Call verified</span>
            ) : (
              <button onClick={() => session.calls.confirmSas()} disabled={call.fpStatus !== "match"}>
                The words match
              </button>
            )}
          </div>
          <div className="call-actions">
            <button onClick={() => session.calls.toggleMute()} aria-pressed={call.muted}>{call.muted ? "Unmute" : "Mute"}</button>
            {call.outputs.length > 0 && (
              <select aria-label="Audio output" onChange={(e) => void session.calls.setOutput(e.target.value)}>
                {call.outputs.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
              </select>
            )}
            <button className="hangup" onClick={() => session.calls.hangup()}>Hang up</button>
          </div>
        </>
      )}
      {call.note && <p className="small">{call.note}</p>}
    </section>
  );
}
