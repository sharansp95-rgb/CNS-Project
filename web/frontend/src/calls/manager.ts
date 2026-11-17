// One-to-one audio calls over WebRTC (DTLS-SRTP, peer to peer).
//
// Security model: every signaling message is a normal E2E chat message (signed,
// encrypted, hash-chained, replay protected). The SDP inside carries each side's
// DTLS fingerprint, therefore authenticated by the peer's RSA identity. After the
// media connects we read the REAL remote certificate fingerprint via getStats and
// compare it with the fingerprint from the signed SDP; a mismatch ends the call.
// Both sides also see a short authentication string derived from both fingerprints.
import { api } from "../attachments/transfer";
import {
  connectionType, fingerprintMatches, remoteCertificateFingerprint, signedFingerprint, validateSdp,
} from "./sdp";
import { sas } from "./sas";
import { encodeSignal, type Outcome, type Signal } from "./signal";

export const RING_SECONDS = 30;
export type CallState = "idle" | "calling" | "ringing" | "connecting" | "active";
export type FpStatus = "pending" | "match" | "mismatch" | "unavailable";
export interface IceConfig {
  iceServers: RTCIceServer[];
  turn: "available" | "unavailable" | "not_configured";
}
export interface CallInfo {
  id: string;
  role: "caller" | "callee";
  state: CallState;
  startedAt: number; // epoch seconds when media connected, 0 before
  localFp: string;
  remoteFp: string; // from the SIGNED SDP
  observedFp: string; // from getStats (real DTLS certificate)
  fpStatus: FpStatus;
  words: string[];
  sasConfirmed: boolean;
  conn: "direct" | "relay" | "unknown";
  quality: "good" | "fair" | "poor" | "unknown";
  muted: boolean;
  turn: IceConfig["turn"];
  note: string;
  alert: string; // non-empty after a security failure
  inboundBytes: number;
  trackEnabled: boolean; // is the microphone track really sending audio (not muted)
  outputs: { id: string; label: string }[];
}
export interface CallHost {
  username: string;
  peer: string;
  apiToken: string;
  key?: CryptoKey;
  peerOnline: boolean;
  send(text: string): Promise<unknown>;
  changed(): void;
  note(type: string, fields: Record<string, unknown>): void;
  securityAlert(kind: string, reason: string): void;
}
const hex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");
export function micMessage(e: unknown): string {
  const name = (e as DOMException)?.name;
  if (!window.isSecureContext || !navigator.mediaDevices)
    return "Calls need a secure (HTTPS) page and a browser with microphone support.";
  if (name === "NotAllowedError" || name === "SecurityError")
    return "Microphone permission was denied. Allow microphone access for this site in your browser settings, then try again.";
  if (name === "NotFoundError" || name === "OverconstrainedError")
    return "No microphone was found. Connect one and try again.";
  if (name === "NotReadableError" || name === "AbortError")
    return "The microphone is in use by another app or could not be started.";
  return "Could not access the microphone: " + ((e as Error)?.message || name || "unknown error");
}
function gathered(pc: RTCPeerConnection, ms = 4000) {
  return new Promise<void>((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    const done = () => {
      clearTimeout(timer);
      pc.removeEventListener("icegatheringstatechange", check);
      resolve();
    };
    const check = () => pc.iceGatheringState === "complete" && done();
    const timer = setTimeout(done, ms);
    pc.addEventListener("icegatheringstatechange", check);
  });
}
export class CallManager {
  info?: CallInfo;
  private pc?: RTCPeerConnection;
  private local?: MediaStream;
  private audio?: HTMLAudioElement;
  private offer?: string;
  private ringTimer?: ReturnType<typeof setTimeout>;
  private poll?: ReturnType<typeof setInterval>;
  private ring?: { stop(): void };
  private ended = false;
  private statsMisses = 0;
  private lastLost = 0;
  private lastRecv = 0;
  constructor(private s: CallHost) {}

  get busy() {
    return !!this.info;
  }
  get canCall() {
    return !!this.s.key && this.s.peerOnline && !this.info;
  }
  private ui() {
    this.s.changed();
  }
  private signal(s: Omit<Signal, "v">) {
    void this.s.send(encodeSignal({ v: 1, ...s } as Signal)).catch(() => {});
  }
  // Metered needs up to ~2 minutes before a NEW TURN credential works, so the ICE
  // configuration is fetched as soon as the secure session exists and reused for any call
  // within CACHE_MS (credentials live 10 minutes). A call placed right after login simply
  // may not get a relay candidate yet and then relies on a direct path.
  private cache?: { cfg: IceConfig; at: number };
  private fetching?: Promise<IceConfig>;
  static readonly CACHE_MS = 8 * 60 * 1000;
  prefetch() {
    void this.ice().catch(() => {});
  }
  private ice(): Promise<IceConfig> {
    if (this.cache && Date.now() - this.cache.at < CallManager.CACHE_MS) return Promise.resolve(this.cache.cfg);
    this.fetching ??= api<IceConfig>(this.s.apiToken, "GET", "/api/calls/ice")
      .catch((): IceConfig => ({ iceServers: [], turn: "unavailable" }))
      .then((cfg) => {
        if (cfg.turn !== "unavailable" || !this.cache) this.cache = { cfg, at: Date.now() };
        return cfg;
      })
      .finally(() => (this.fetching = undefined));
    return this.fetching;
  }
  /** Drop the cache when the session ends: credentials belong to this login. */
  forgetIce() {
    this.cache = undefined;
  }
  private newInfo(id: string, role: "caller" | "callee", cfg: IceConfig): CallInfo {
    return {
      id, role, state: role === "caller" ? "calling" : "ringing", startedAt: 0, localFp: "", remoteFp: "",
      observedFp: "", fpStatus: "pending", words: [], sasConfirmed: false, conn: "unknown", quality: "unknown",
      muted: false, turn: cfg.turn, note: "", alert: "", inboundBytes: 0, trackEnabled: true, outputs: [],
    };
  }
  private async mic() {
    this.local = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    });
  }
  private connect(cfg: IceConfig) {
    // Open the site as /?relay=1 to force every media path through the TURN relay
    // (hides your IP address from the peer; the relay still only sees encrypted SRTP).
    const relayOnly = new URLSearchParams(location.search).get("relay") === "1";
    const pc = new RTCPeerConnection({
      iceServers: cfg.iceServers,
      bundlePolicy: "max-bundle",
      iceTransportPolicy: relayOnly ? "relay" : "all",
    });
    if (relayOnly && this.info) this.info.note = "Relay-only mode: all audio goes through the TURN relay.";
    this.pc = pc;
    for (const track of this.local!.getAudioTracks()) pc.addTrack(track, this.local!);
    const audio = (this.audio = document.createElement("audio"));
    audio.autoplay = true;
    audio.setAttribute("playsinline", "");
    audio.dataset.testid = "call-audio";
    audio.style.display = "none";
    document.body.append(audio);
    pc.ontrack = (e) => {
      audio.srcObject = e.streams[0] ?? new MediaStream([e.track]);
      void audio.play().catch(() => {
        if (this.info) this.info.note = "Tap the call screen to start audio (browser autoplay rules).";
        this.ui();
      });
    };
    pc.onconnectionstatechange = () => {
      const st = pc.connectionState;
      if (!this.info) return;
      if (st === "connected" && this.info.state !== "active") this.onConnected();
      else if (st === "failed") void this.finish("failed", "connection_failed");
      else if (st === "disconnected") {
        this.info.note = "Connection interrupted… trying to recover.";
        this.ui();
        setTimeout(() => {
          if (this.pc === pc && pc.connectionState === "disconnected") void this.finish("failed", "connection_lost");
        }, 10000);
      }
    };
    this.refreshOutputs();
  }
  private async refreshOutputs() {
    try {
      if (!("setSinkId" in HTMLMediaElement.prototype)) return;
      const devices = await navigator.mediaDevices.enumerateDevices();
      if (this.info)
        this.info.outputs = devices.filter((d) => d.kind === "audiooutput").map((d) => ({ id: d.deviceId, label: d.label || "Speaker" }));
      this.ui();
    } catch {
      /* output selection is optional */
    }
  }
  async setOutput(id: string) {
    try {
      await (this.audio as any)?.setSinkId(id);
    } catch {
      if (this.info) this.info.note = "Could not switch the audio output.";
      this.ui();
    }
  }
  private armRing(outcome: Outcome) {
    this.ringTimer = setTimeout(() => {
      if (!this.info || !["calling", "ringing"].includes(this.info.state)) return;
      if (this.info.role === "caller") this.signal({ call: this.info.id, type: "cancel", reason: "timeout" });
      void this.finish(outcome, "ring_timeout", false);
    }, RING_SECONDS * 1000);
  }

  /** Caller: must be invoked from a user gesture (permission prompt + autoplay rules). */
  async start() {
    if (!this.canCall) throw Error(this.info ? "You are already in a call." : "Wait for a secure session with an online peer.");
    const id = hex(16);
    this.info = this.newInfo(id, "caller", { iceServers: [], turn: "unavailable" });
    this.ended = false;
    this.ui();
    try {
      await this.mic();
    } catch (e) {
      this.info = undefined;
      this.ui();
      throw Error(micMessage(e));
    }
    try {
      const cfg = await this.ice();
      this.info.turn = cfg.turn;
      this.connect(cfg);
      const pc = this.pc!;
      await pc.setLocalDescription(await pc.createOffer({ offerToReceiveAudio: true }));
      await gathered(pc);
      const sdp = pc.localDescription!.sdp;
      const err = validateSdp(sdp);
      if (err) throw Error("Could not build a valid call offer: " + err);
      this.info.localFp = signedFingerprint(sdp)!;
      this.signal({ call: id, type: "invite", sdp });
      this.s.note("call_fingerprints", { call: id, local_dtls_sha256: this.info.localFp, note: "Sent inside the signed, encrypted invite" });
      this.armRing("no_answer");
      this.ui();
    } catch (e) {
      await this.finish("failed", "setup_failed", false);
      throw e;
    }
  }

  /** Called for every verified, fresh call message from the peer. Never awaits chat sends. */
  async onSignal(sig: Signal) {
    const cur = this.info;
    try {
      if (sig.type === "invite") {
        if (cur || !this.s.key) {
          this.signal({ call: sig.call, type: "busy" });
          this.s.note("call_busy", { call: sig.call, note: "Rejected an incoming call: already in a call" });
          return;
        }
        const cfg: IceConfig = { iceServers: [], turn: "not_configured" };
        this.info = this.newInfo(sig.call, "callee", cfg);
        this.ended = false;
        this.offer = sig.sdp;
        this.info.remoteFp = signedFingerprint(sig.sdp!)!;
        this.s.note("call_fingerprints", { call: sig.call, remote_dtls_sha256: this.info.remoteFp, note: "From the signed invite" });
        this.startRinging();
        this.armRing("missed");
        this.ui();
        return;
      }
      if (!cur || cur.id !== sig.call) return; // stale / unrelated call id: ignore
      if (sig.type === "accept" && cur.role === "caller" && cur.state === "calling") {
        cur.remoteFp = signedFingerprint(sig.sdp!)!;
        this.s.note("call_fingerprints", { call: cur.id, remote_dtls_sha256: cur.remoteFp, note: "From the signed answer" });
        cur.state = "connecting";
        clearTimeout(this.ringTimer);
        await this.pc!.setRemoteDescription({ type: "answer", sdp: sig.sdp! });
        cur.words = await sas(cur.localFp, cur.remoteFp, cur.id);
        this.ui();
      } else if (sig.type === "decline" && cur.role === "caller") await this.finish("declined", "peer_declined", false);
      else if (sig.type === "busy" && cur.role === "caller") await this.finish("busy", "peer_busy", false);
      else if (sig.type === "cancel" && cur.role === "callee" && cur.state === "ringing") await this.finish("missed", "caller_canceled", false);
      else if (sig.type === "hangup") await this.finish(cur.state === "active" ? "completed" : "failed", sig.reason || "peer_hangup", false);
    } catch (e) {
      await this.finish("failed", "signaling_error", true, (e as Error).message);
    }
  }

  /** Callee: must be invoked from a user gesture. */
  async accept() {
    const cur = this.info;
    if (!cur || cur.role !== "callee" || cur.state !== "ringing") return;
    this.stopRinging();
    clearTimeout(this.ringTimer);
    cur.state = "connecting";
    this.ui();
    try {
      await this.mic();
    } catch (e) {
      cur.note = micMessage(e);
      this.signal({ call: cur.id, type: "decline", reason: "no_microphone" });
      this.lastError = cur.note;
      await this.finish("failed", "no_microphone", false);
      return;
    }
    try {
      const cfg = await this.ice();
      cur.turn = cfg.turn;
      this.connect(cfg);
      const pc = this.pc!;
      await pc.setRemoteDescription({ type: "offer", sdp: this.offer! });
      await pc.setLocalDescription(await pc.createAnswer());
      await gathered(pc);
      const sdp = pc.localDescription!.sdp;
      const err = validateSdp(sdp);
      if (err) throw Error(err);
      cur.localFp = signedFingerprint(sdp)!;
      cur.words = await sas(cur.localFp, cur.remoteFp, cur.id);
      this.signal({ call: cur.id, type: "accept", sdp });
      this.s.note("call_fingerprints", { call: cur.id, local_dtls_sha256: cur.localFp, note: "Sent inside the signed, encrypted answer" });
      this.ui();
    } catch (e) {
      await this.finish("failed", "setup_failed", true);
    }
  }
  lastError = "";
  decline() {
    const cur = this.info;
    if (!cur || cur.role !== "callee" || cur.state !== "ringing") return;
    this.signal({ call: cur.id, type: "decline" });
    void this.finish("declined", "declined", false);
  }
  hangup() {
    const cur = this.info;
    if (!cur) return;
    if (cur.state === "calling") this.signal({ call: cur.id, type: "cancel", reason: "user" });
    else this.signal({ call: cur.id, type: "hangup", reason: "user" });
    void this.finish(cur.state === "active" ? "completed" : cur.role === "caller" && cur.state === "calling" ? "canceled" : "failed", "user", false);
  }
  toggleMute() {
    if (!this.info || !this.local) return;
    this.info.muted = !this.info.muted;
    this.local.getAudioTracks().forEach((t) => (t.enabled = !this.info!.muted));
    this.info.trackEnabled = !this.info.muted;
    this.ui();
  }
  confirmSas() {
    if (this.info && this.info.state === "active") {
      this.info.sasConfirmed = true;
      this.ui();
    }
  }
  resumeAudio() {
    void this.audio?.play().then(() => {
      if (this.info) this.info.note = "";
      this.ui();
    });
  }

  private onConnected() {
    const cur = this.info!;
    cur.state = "active";
    cur.startedAt = Math.floor(Date.now() / 1000);
    this.statsMisses = 0;
    this.poll = setInterval(() => void this.stats(), 1000);
    void this.stats();
    this.ui();
  }
  private async stats() {
    const cur = this.info,
      pc = this.pc;
    if (!cur || !pc) return;
    let report: RTCStatsReport;
    try {
      report = await pc.getStats();
    } catch {
      return;
    }
    if (this.info !== cur) return;
    const type = connectionType(report);
    if (type) cur.conn = type;
    cur.trackEnabled = !!this.local?.getAudioTracks().some((t) => t.enabled);
    let recv = 0,
      lost = 0,
      jitter = 0,
      rtt = 0;
    report.forEach((r: any) => {
      if (r.type === "inbound-rtp" && r.kind === "audio") {
        recv = r.packetsReceived ?? 0;
        lost = r.packetsLost ?? 0;
        jitter = r.jitter ?? 0;
        cur.inboundBytes = r.bytesReceived ?? 0;
      }
      if (r.type === "candidate-pair" && r.state === "succeeded" && r.nominated) rtt = r.currentRoundTripTime ?? rtt;
    });
    const dRecv = recv - this.lastRecv,
      dLost = lost - this.lastLost;
    this.lastRecv = recv;
    this.lastLost = lost;
    const loss = dRecv + dLost > 0 ? dLost / (dRecv + dLost) : 0;
    cur.quality = recv === 0 ? "unknown" : loss > 0.1 || jitter > 0.08 || rtt > 0.6 ? "poor" : loss > 0.03 || jitter > 0.03 || rtt > 0.3 ? "fair" : "good";
    if (cur.fpStatus === "pending") {
      const observed = remoteCertificateFingerprint(report);
      if (observed) {
        cur.observedFp = observed;
        this.s.note("call_fingerprints", { call: cur.id, observed_remote_dtls_sha256: observed, signed_remote_dtls_sha256: cur.remoteFp });
        if (fingerprintMatches(cur.remoteFp, observed)) cur.fpStatus = "match";
        else {
          cur.fpStatus = "mismatch";
          cur.alert = "SECURITY ALERT: the DTLS certificate of this call does not match the fingerprint your contact signed. The call was ended.";
          this.s.securityAlert("call_fingerprint_mismatch", "fingerprint_mismatch");
          this.signal({ call: cur.id, type: "hangup", reason: "fingerprint_mismatch" });
          await this.finish("security_alert", "fingerprint_mismatch", false);
          return;
        }
      } else if (++this.statsMisses >= 6) {
        cur.fpStatus = "unavailable";
        cur.note = "This browser could not report the DTLS certificate, so only the signed fingerprint and the words below protect this call.";
      }
    }
    this.ui();
  }

  private startRinging() {
    try {
      const Ctx = window.AudioContext || (window as any).webkitAudioContext;
      const ctx = new Ctx();
      const beep = () => {
        const o = ctx.createOscillator(),
          g = ctx.createGain();
        o.frequency.value = 440;
        g.gain.value = 0.08;
        o.connect(g).connect(ctx.destination);
        o.start();
        o.stop(ctx.currentTime + 0.4);
      };
      void ctx.resume().catch(() => {});
      beep();
      const timer = setInterval(beep, 2000);
      this.ring = { stop: () => (clearInterval(timer), void ctx.close().catch(() => {})) };
    } catch {
      /* Autoplay may block the ringtone; the on-screen prompt remains. */
    }
  }
  private stopRinging() {
    this.ring?.stop();
    this.ring = undefined;
  }

  /** End the call locally and (optionally) record it as a signed chat event. */
  private async finish(outcome: Outcome, reason: string, sendHangup = false, detail = "") {
    const cur = this.info;
    if (!cur || this.ended) return;
    this.ended = true;
    if (sendHangup) this.signal({ call: cur.id, type: "hangup", reason });
    const now = Math.floor(Date.now() / 1000);
    const started = cur.startedAt,
      duration = started ? now - started : 0;
    this.releaseMedia();
    const record: Omit<Signal, "v"> = {
      call: cur.id, type: "record", role: cur.role, outcome, started, ended: started ? now : 0, duration,
      fp_match: cur.fpStatus === "match" ? "yes" : cur.fpStatus === "mismatch" ? "no" : "n/a",
      sas_confirmed: cur.sasConfirmed && cur.fpStatus === "match",
      conn: started && cur.conn !== "unknown" ? cur.conn : "none",
    };
    this.lastEnded = { ...cur, note: detail || cur.note };
    this.info = undefined;
    this.signal(record);
    this.ui();
  }
  lastEnded?: CallInfo;
  private releaseMedia() {
    clearTimeout(this.ringTimer);
    clearInterval(this.poll);
    this.stopRinging();
    this.local?.getTracks().forEach((t) => t.stop());
    this.local = undefined;
    this.pc?.close();
    this.pc = undefined;
    this.audio?.remove();
    this.audio = undefined;
    this.offer = undefined;
  }
  /** Session lost (socket closed, peer left): end without sending anything. */
  teardown(reason: string) {
    this.forgetIce();
    if (!this.info) return;
    this.ended = true;
    this.releaseMedia();
    this.lastEnded = { ...this.info, note: reason };
    this.info = undefined;
    this.ui();
  }
}
