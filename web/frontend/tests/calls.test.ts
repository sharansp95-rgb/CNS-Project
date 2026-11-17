import { describe, it, expect } from "vitest";
import {
  fingerprints, signedFingerprint, validateSdp, fingerprintMatches,
  remoteCertificateFingerprint, connectionType,
} from "../src/calls/sdp";
import { sas, WORDS } from "../src/calls/sas";
import { encodeSignal, parseSignal, CALL_PREFIX, type Signal } from "../src/calls/signal";

const FP = Array.from({ length: 32 }, (_, i) => ((i * 7 + 3) % 256).toString(16).padStart(2, "0")).join(":").toUpperCase();
const FP2 = Array.from({ length: 32 }, (_, i) => ((i * 11 + 5) % 256).toString(16).padStart(2, "0")).join(":").toUpperCase();
const sdp = (fp = FP, extra = "") =>
  ["v=0", "o=- 1 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0", "m=audio 9 UDP/TLS/RTP/SAVPF 111",
   "c=IN IP4 0.0.0.0", `a=fingerprint:sha-256 ${fp}`, "a=setup:actpass", "a=rtpmap:111 opus/48000/2", extra, ""].filter((l, i, a) => l || i === a.length - 1).join("\r\n");

describe("SDP fingerprints", () => {
  it("extracts and normalizes the DTLS fingerprint", () => {
    expect(fingerprints(sdp(FP.toLowerCase()))).toEqual([{ algorithm: "sha-256", value: FP }]);
    expect(signedFingerprint(sdp())).toBe(FP);
  });
  it("rejects ambiguous, missing or non-SHA-256 fingerprints", () => {
    expect(signedFingerprint(sdp(FP, `a=fingerprint:sha-256 ${FP2}`))).toBeNull();
    expect(signedFingerprint("v=0\r\nm=audio 9 X\r\n")).toBeNull();
    expect(signedFingerprint(sdp().replace("sha-256", "sha-1"))).toBeNull();
    expect(signedFingerprint(sdp("AA:BB"))).toBeNull();
  });
  it("tolerates the same fingerprint repeated (session + media level)", () => {
    expect(signedFingerprint(sdp(FP, `a=fingerprint:sha-256 ${FP}`))).toBe(FP);
  });
  it("accepts audio-only SDP and rejects video, data channels, oversize and junk", () => {
    expect(validateSdp(sdp())).toBeNull();
    expect(validateSdp(sdp(FP, "m=video 9 UDP/TLS/RTP/SAVPF 96"))).not.toBeNull();
    expect(validateSdp(sdp(FP, "m=application 9 UDP/DTLS/SCTP webrtc-datachannel"))).not.toBeNull();
    expect(validateSdp(sdp() + "a=x:" + "y".repeat(30000))).not.toBeNull();
    expect(validateSdp("hello")).not.toBeNull();
    expect(validateSdp(undefined)).not.toBeNull();
  });
  it("compares observed and signed fingerprints, case-insensitively, failing closed", () => {
    expect(fingerprintMatches(FP, FP.toLowerCase())).toBe(true);
    expect(fingerprintMatches(FP, FP2)).toBe(false);
    expect(fingerprintMatches(FP, null)).toBe(false);
    expect(fingerprintMatches(FP, "")).toBe(false);
  });
});

const report = (entries: Record<string, any>) => new Map(Object.entries(entries)) as unknown as RTCStatsReport;
describe("getStats parsing", () => {
  it("finds the remote certificate fingerprint and the connection type", () => {
    const r = report({
      t: { type: "transport", remoteCertificateId: "c", selectedCandidatePairId: "p" },
      c: { type: "certificate", fingerprint: FP.toLowerCase(), fingerprintAlgorithm: "sha-256" },
      p: { type: "candidate-pair", localCandidateId: "l", remoteCandidateId: "r" },
      l: { type: "local-candidate", candidateType: "host" },
      r: { type: "remote-candidate", candidateType: "srflx" },
    });
    expect(remoteCertificateFingerprint(r)).toBe(FP);
    expect(connectionType(r)).toBe("direct");
    const relayed = report({
      t: { type: "transport", selectedCandidatePairId: "p" },
      p: { type: "candidate-pair", localCandidateId: "l", remoteCandidateId: "r" },
      l: { type: "local-candidate", candidateType: "relay" },
      r: { type: "remote-candidate", candidateType: "host" },
    });
    expect(connectionType(relayed)).toBe("relay");
  });
  it("returns null when the data is not available", () => {
    expect(remoteCertificateFingerprint(report({}))).toBeNull();
    expect(connectionType(report({}))).toBeNull();
    const sha1 = report({ t: { type: "transport", remoteCertificateId: "c" }, c: { type: "certificate", fingerprint: FP, fingerprintAlgorithm: "sha-1" } });
    expect(remoteCertificateFingerprint(sha1)).toBeNull();
  });
});

describe("short authentication string", () => {
  const id = "a".repeat(32);
  it("has 256 distinct words and gives four of them", async () => {
    expect(WORDS.length).toBe(256);
    expect(new Set(WORDS).size).toBe(256);
    const words = await sas(FP, FP2, id);
    expect(words).toHaveLength(4);
    words.forEach((w) => expect(WORDS).toContain(w));
  });
  it("is identical for both parties regardless of argument order", async () => {
    expect(await sas(FP, FP2, id)).toEqual(await sas(FP2, FP, id));
  });
  it("changes when either fingerprint or the call id changes (MITM sees other words)", async () => {
    const base = (await sas(FP, FP2, id)).join(" ");
    const mitm = Array.from({ length: 32 }, (_, i) => ((i * 13 + 1) % 256).toString(16).padStart(2, "0")).join(":").toUpperCase();
    expect((await sas(FP, mitm, id)).join(" ")).not.toBe(base);
    expect((await sas(mitm, FP2, id)).join(" ")).not.toBe(base);
    expect((await sas(FP, FP2, "b".repeat(32))).join(" ")).not.toBe(base);
  });
});

const call = "c".repeat(32);
const record: Signal = { v: 1, call, type: "record", role: "caller", outcome: "completed", started: 1800000000, ended: 1800000100, duration: 100, fp_match: "yes", sas_confirmed: true, conn: "direct" };
describe("signaling messages", () => {
  it("round-trips every type", () => {
    for (const s of [
      { v: 1, call, type: "invite", sdp: sdp() }, { v: 1, call, type: "accept", sdp: sdp(FP2) },
      { v: 1, call, type: "decline" }, { v: 1, call, type: "busy" }, { v: 1, call, type: "cancel" },
      { v: 1, call, type: "hangup", reason: "user" }, record,
    ] as Signal[])
      expect(parseSignal(encodeSignal(s))).toEqual(s);
  });
  it("rejects malformed or hostile signals", () => {
    const bad: any[] = [
      { type: "invite" }, { type: "invite", sdp: "junk" }, { type: "invite", sdp: sdp(FP, "m=video 9 X") },
      { type: "decline", sdp: sdp() }, { type: "hangup", reason: "x".repeat(200) }, { call: "short" },
      { type: "bogus" }, { v: 2 }, { type: "record", outcome: "won" }, { type: "record", duration: -1 },
      { type: "record", duration: 99999999 }, { type: "record", conn: "magic" },
    ];
    for (const patch of bad)
      expect(parseSignal(CALL_PREFIX + JSON.stringify({ v: 1, call, type: "decline", ...patch }))).toBeNull();
    expect(parseSignal(CALL_PREFIX + "{nope")).toBeNull();
    expect(parseSignal("hello")).toBeNull();
    expect(parseSignal(CALL_PREFIX + "null")).toBeNull();
  });
});
