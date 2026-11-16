/** Offline verification. This module performs no network requests. */
import * as c from "./crypto";
export interface Failure {
  index: number | null;
  check: string;
  detail: string;
}
export interface Verification {
  valid: boolean;
  failures: Failure[];
  messages: { index: number; valid: boolean }[];
  receipt: "not supplied" | "valid" | "invalid";
}
const hashOK = (v: unknown) =>
  typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
export async function verifyReceipt(
  receipt: any,
  bytes: Uint8Array,
  publicPem: string,
): Promise<boolean> {
  try {
    const fields = [
      "receipt_version",
      "file_sha256",
      "server_time",
      "key_id",
      "corroborated",
      "total",
      "signature",
    ];
    if (
      !receipt ||
      Object.keys(receipt).sort().join() !== fields.sort().join() ||
      receipt.receipt_version !== 1 ||
      receipt.file_sha256 !== c.hex(await c.sha(bytes))
    )
      return false;
    if (
      typeof receipt.server_time !== "string" ||
      !receipt.server_time.endsWith("Z") ||
      !Number.isFinite(Date.parse(receipt.server_time))
    )
      return false;
    if (
      !Number.isSafeInteger(receipt.total) ||
      receipt.total < 0 ||
      (receipt.corroborated !== "not available" &&
        (!Number.isSafeInteger(receipt.corroborated) ||
          receipt.corroborated < 0 ||
          receipt.corroborated > receipt.total))
    )
      return false;
    const file = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    if (
      file &&
      ["securechat-evidence/v1", "securechat-evidence/v2"].includes(file.format)
    ) {
      if (!Array.isArray(file.records) || receipt.total !== file.records.length)
        return false;
      if (
        file.format === "securechat-evidence/v1" &&
        receipt.corroborated !== "not available"
      )
        return false;
      if (
        file.format === "securechat-evidence/v2" &&
        !Number.isSafeInteger(receipt.corroborated)
      )
        return false;
    }
    const der = c.un64(publicPem.replace(/-----[^-]+-----|\s/g, ""));
    const key = await crypto.subtle.importKey(
      "spki",
      c.raw(der),
      "Ed25519",
      true,
      ["verify"],
    );
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    if (c.hex(await c.sha(raw)) !== receipt.key_id) return false;
    const { signature, ...body } = receipt;
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      c.raw(c.un64(signature)),
      c.raw(c.utf8(c.canonical(body))),
    );
  } catch {
    return false;
  }
}
export async function verifyEvidence(
  bytes: Uint8Array,
  receipt?: any,
  tsaPem?: string,
  expectedFingerprints: string[] = [],
): Promise<Verification> {
  const result: Verification = {
    valid: false,
    failures: [],
    messages: [],
    receipt: receipt ? "invalid" : "not supplied",
  };
  const bad = (index: number | null, check: string, detail: string) =>
    result.failures.push({ index, check, detail });
  let data: any;
  try {
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    bad(null, "format", "Unreadable JSON");
    return result;
  }
  if (
    !data ||
    !["securechat-evidence/v1", "securechat-evidence/v2"].includes(data.format)
  ) {
    bad(null, "format", "Unsupported evidence format");
    return result;
  }
  if (data.format === "securechat-evidence/v2" && data.format_version !== 2)
    bad(null, "format version", "v2 requires format_version=2");
  try {
    const names = Object.keys(data.participants),
      session = data.session;
    if (
      names.length !== 2 ||
      !names.includes(session.initiator) ||
      !names.includes(session.responder) ||
      !Array.isArray(data.records)
    )
      throw Error("Malformed structure");
    const keys: Record<string, CryptoKey> = {},
      fps: Record<string, string> = {};
    for (const name of names) {
      try {
        const info = data.participants[name];
        keys[name] = await c.publicKey(info.public_key_pem);
        fps[name] = await c.fingerprint(info.public_key_pem);
        if (fps[name] !== info.fingerprint)
          bad(null, "fingerprint", `${name}: fingerprint mismatch`);
      } catch {
        bad(null, "public key", `${name}: invalid public key`);
      }
    }
    for (const pin of expectedFingerprints)
      if (!Object.values(fps).includes(pin.trim().toUpperCase()))
        bad(null, "pinned fingerprint", "Trusted fingerprint not present");
    const heads: Record<string, { seq: number; head: string }> = {};
    try {
      const ip = c.un64(session.ecdh_public_keys.initiator),
        rp = c.un64(session.ecdh_public_keys.responder);
      for (const role of ["initiator", "responder"]) {
        const pub = role === "initiator" ? ip : rp;
        if (
          !keys[session[role]] ||
          !(await c.verify(
            keys[session[role]],
            pub,
            c.un64(session.handshake_signatures[role]),
          ))
        )
          bad(null, "handshake signature", `${role}: invalid signed handshake`);
      }
      for (const name of names)
        heads[name] = { seq: 1, head: await c.genesis(ip, rp, name) };
    } catch {
      bad(null, "handshake", "Malformed handshake");
    }
    for (let i = 0; i < data.records.length; i++) {
      const row = data.records[i],
        index = i + 1,
        start = result.failures.length;
      try {
        const rec = c.record(
          row.sender,
          row.recipient,
          row.seq,
          row.timestamp,
          row.message,
          row.prev_hash,
        );
        if (
          data.format === "securechat-evidence/v2" &&
          !hashOK(row.envelope_sha256)
        )
          bad(index, "envelope hash", "Missing or malformed envelope_sha256");
        if (
          !keys[row.sender] ||
          !names.includes(row.recipient) ||
          row.sender === row.recipient
        )
          bad(index, "participants", "Invalid sender/recipient");
        else if (
          !(await c.verify(
            keys[row.sender],
            c.utf8(c.canonical(rec)),
            c.un64(row.signature),
          ))
        )
          bad(index, "signature", "Sender signature does not verify");
        const hash = await c.hash(rec);
        if (hash !== row.record_hash)
          bad(index, "record hash", "Record hash mismatch");
        const state = heads[row.sender];
        if (state) {
          if (row.seq !== state.seq || row.prev_hash !== state.head)
            bad(
              index,
              "chain",
              `Expected sequence ${state.seq}; got ${row.seq}. Missing, reordered or broken predecessor.`,
            );
          if (Number.isSafeInteger(row.seq)) {
            state.seq = row.seq + 1;
            state.head = hash;
          }
        }
      } catch {
        bad(index, "record format", "Malformed record");
      }
      result.messages.push({ index, valid: result.failures.length === start });
    }
    for (const name of names)
      if (heads[name] && data.chain_heads?.[name] !== heads[name].head)
        bad(null, "chain head", `${name}: final chain head mismatch`);
    const { exporter_signature, ...body } = data;
    try {
      if (
        !keys[data.exported_by] ||
        !(await c.verify(
          keys[data.exported_by],
          c.utf8(c.canonical(body)),
          c.un64(exporter_signature),
        ))
      )
        bad(null, "export signature", "Exporter signature does not verify");
    } catch {
      bad(null, "export signature", "Malformed exporter signature");
    }
  } catch {
    bad(null, "structure", "Malformed evidence structure");
  }
  if (receipt) {
    if (tsaPem && (await verifyReceipt(receipt, bytes, tsaPem))) {
      result.receipt = "valid";
    } else
      bad(
        null,
        "timestamp receipt",
        "Receipt signature, key, or exact file hash does not match",
      );
  }
  result.valid = result.failures.length === 0;
  return result;
}
