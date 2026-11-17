// SDP handling for audio-only calls. The SDP travels inside signed, encrypted chat
// messages, so the DTLS fingerprint in it is authenticated by the peer's RSA identity.
export const MAX_SDP = 24 * 1024;
const FP =
  /^a=fingerprint:([A-Za-z0-9-]+) ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)\s*$/;
export const normalizeFp = (v: string) => v.trim().toUpperCase();
export interface Fingerprint {
  algorithm: string;
  value: string; // upper-case colon-separated hex
}
export function fingerprints(sdp: string): Fingerprint[] {
  const out: Fingerprint[] = [];
  for (const line of sdp.split(/\r?\n/)) {
    const m = FP.exec(line);
    if (m)
      out.push({ algorithm: m[1].toLowerCase(), value: normalizeFp(m[2]) });
  }
  return out;
}
/** The one SHA-256 fingerprint of this SDP, or null if absent, ambiguous or another hash. */
export function signedFingerprint(sdp: string): string | null {
  const all = fingerprints(sdp);
  if (!all.length || all.some((f) => f.algorithm !== "sha-256")) return null;
  const distinct = new Set(all.map((f) => f.value));
  if (distinct.size !== 1) return null;
  const value = [...distinct][0];
  return value.split(":").length === 32 ? value : null;
}
/** Reject SDP that is not a plain audio-only call description. Returns an error or null. */
export function validateSdp(sdp: unknown): string | null {
  if (typeof sdp !== "string" || !sdp) return "missing SDP";
  if (sdp.length > MAX_SDP) return "SDP too large";
  if (!sdp.startsWith("v=0")) return "not an SDP";
  const media = sdp.split(/\r?\n/).filter((l) => l.startsWith("m="));
  if (media.length !== 1 || !media[0].startsWith("m=audio "))
    return "calls are audio only";
  if (signedFingerprint(sdp) === null)
    return "missing or ambiguous DTLS fingerprint";
  return null;
}
/** Constant-shape comparison of a certificate fingerprint seen on the wire with the signed one. */
export function fingerprintMatches(
  signed: string,
  observed: string | null | undefined,
): boolean {
  return !!observed && normalizeFp(observed) === normalizeFp(signed);
}
/** Pull the remote DTLS certificate fingerprint out of an RTCStatsReport. */
export function remoteCertificateFingerprint(
  report: RTCStatsReport,
): string | null {
  let cert: string | undefined;
  report.forEach((s: any) => {
    if (s.type === "transport" && s.remoteCertificateId)
      cert = s.remoteCertificateId;
  });
  if (!cert) return null;
  const entry: any = report.get(cert);
  return entry?.fingerprint &&
    String(entry.fingerprintAlgorithm).toLowerCase() === "sha-256"
    ? normalizeFp(entry.fingerprint)
    : null;
}
/** "direct" unless either side of the selected candidate pair is a TURN relay. */
export function connectionType(
  report: RTCStatsReport,
): "direct" | "relay" | null {
  let pairId: string | undefined;
  report.forEach((s: any) => {
    if (s.type === "transport" && s.selectedCandidatePairId)
      pairId = s.selectedCandidatePairId;
  });
  let pair: any = pairId ? report.get(pairId) : undefined;
  if (!pair)
    report.forEach((s: any) => {
      if (s.type === "candidate-pair" && s.nominated && s.state === "succeeded")
        pair = s;
    });
  if (!pair) return null;
  const types = [pair.localCandidateId, pair.remoteCandidateId].map(
    (id: string) => (report.get(id) as any)?.candidateType,
  );
  if (types.some((t) => !t)) return null;
  return types.includes("relay") ? "relay" : "direct";
}
