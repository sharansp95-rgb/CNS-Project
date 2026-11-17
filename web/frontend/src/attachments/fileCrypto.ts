// Chunked AES-256-GCM file encryption.
//
// Object layout: for each chunk i of the plaintext (CHUNK bytes, last one shorter)
//   nonce (12 random bytes) || AES-GCM(ciphertext) || tag (16)
// AAD = "securechat-attachment/v1\0<file id>\0<chunk index>\0<1 if last else 0>".
// The AAD binds each chunk to its file, position and finality, so chunks cannot
// be reordered, swapped between files, dropped or truncated undetected. The file
// key is fresh per file and travels only inside the signed, end-to-end encrypted
// chat message.
import { b64, hex, raw, sha, un64, utf8 } from "../crypto";

export const CHUNK = 1024 * 1024;
export const OVERHEAD = 28; // nonce + tag
export type Failure =
  | "ciphertext_hash"
  | "chunk_auth"
  | "plaintext_hash"
  | "size"
  | "download"
  | "type";
export class AttachmentError extends Error {
  constructor(
    public code: Failure,
    message: string,
  ) {
    super(message);
  }
}
export interface FileSecrets {
  id: string; // 32 lowercase hex chars
  key: string; // base64 32 bytes
  chunk: number;
  size: number;
  ct_size: number;
  ct_sha256: string;
  pt_sha256: string;
}
export const chunkCount = (size: number, chunk = CHUNK) =>
  Math.max(1, Math.ceil(size / chunk));
export const ciphertextSize = (size: number, chunk = CHUNK) =>
  size + chunkCount(size, chunk) * OVERHEAD;
export const newFileId = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const aad = (id: string, index: number, last: boolean) =>
  utf8(`securechat-attachment/v1\0${id}\0${index}\0${last ? 1 : 0}`);
const importKey = (key: Uint8Array, use: KeyUsage) =>
  crypto.subtle.importKey("raw", raw(key), "AES-GCM", false, [use]);
const tick = () => new Promise<void>((r) => setTimeout(r, 0));

export async function encryptFile(
  plain: Uint8Array,
  opts: {
    id?: string;
    chunk?: number;
    onProgress?: (done: number, total: number) => void;
    signal?: AbortSignal;
  } = {},
): Promise<{ ciphertext: Uint8Array; secrets: FileSecrets }> {
  const chunk = opts.chunk ?? CHUNK,
    id = opts.id ?? newFileId();
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const key = await importKey(keyBytes, "encrypt");
  const n = chunkCount(plain.length, chunk);
  const out = new Uint8Array(ciphertextSize(plain.length, chunk));
  let at = 0;
  for (let i = 0; i < n; i++) {
    if (opts.signal?.aborted) throw new DOMException("Cancelled", "AbortError");
    const part = plain.subarray(
      i * chunk,
      Math.min((i + 1) * chunk, plain.length),
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const box = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          tagLength: 128,
          additionalData: raw(aad(id, i, i === n - 1)),
        },
        key,
        raw(part),
      ),
    );
    out.set(nonce, at);
    out.set(box, at + 12);
    at += 12 + box.length;
    opts.onProgress?.(i + 1, n);
    await tick();
  }
  const secrets: FileSecrets = {
    id,
    key: b64(keyBytes),
    chunk,
    size: plain.length,
    ct_size: out.length,
    ct_sha256: hex(await sha(out)),
    pt_sha256: hex(await sha(plain)),
  };
  keyBytes.fill(0);
  return { ciphertext: out, secrets };
}

/** Verify ciphertext hash → authenticate every chunk → verify plaintext hash. */
export async function decryptFile(
  ciphertext: Uint8Array,
  s: FileSecrets,
  opts: {
    onProgress?: (done: number, total: number) => void;
    signal?: AbortSignal;
  } = {},
): Promise<Uint8Array> {
  if (
    ciphertext.length !== s.ct_size ||
    s.ct_size !== ciphertextSize(s.size, s.chunk)
  )
    throw new AttachmentError(
      "size",
      "Attachment tampered or corrupted: size does not match the signed message",
    );
  if (hex(await sha(ciphertext)) !== s.ct_sha256)
    throw new AttachmentError(
      "ciphertext_hash",
      "Attachment tampered or corrupted: ciphertext hash mismatch",
    );
  const key = await importKey(un64(s.key), "decrypt");
  const n = chunkCount(s.size, s.chunk);
  const plain = new Uint8Array(s.size);
  let at = 0,
    out = 0;
  for (let i = 0; i < n; i++) {
    if (opts.signal?.aborted) throw new DOMException("Cancelled", "AbortError");
    const plainLen = Math.min(s.chunk, s.size - i * s.chunk);
    const nonce = ciphertext.subarray(at, at + 12);
    const box = ciphertext.subarray(at + 12, at + 12 + plainLen + 16);
    try {
      const part = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: raw(nonce),
            tagLength: 128,
            additionalData: raw(aad(s.id, i, i === n - 1)),
          },
          key,
          raw(box),
        ),
      );
      plain.set(part, out);
      out += part.length;
    } catch {
      throw new AttachmentError(
        "chunk_auth",
        `Attachment tampered or corrupted: chunk ${i + 1} failed authentication`,
      );
    }
    at += 12 + plainLen + 16;
    opts.onProgress?.(i + 1, n);
    await tick();
  }
  if (hex(await sha(plain)) !== s.pt_sha256)
    throw new AttachmentError(
      "plaintext_hash",
      "Attachment tampered or corrupted: plaintext hash mismatch",
    );
  return plain;
}
