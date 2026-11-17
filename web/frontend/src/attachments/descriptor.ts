// The attachment descriptor is the *text of an ordinary chat message*. It is
// therefore signed, AES-GCM encrypted, hash-chained, replay-protected and part
// of exported evidence exactly like any other message.
import { canonical } from "../crypto";
import { ALLOWED_MIME } from "./media";
import { CHUNK, ciphertextSize, type FileSecrets } from "./fileCrypto";

export const PREFIX = "securechat-attachment/v1:";
export interface Descriptor extends FileSecrets {
  v: 1;
  name: string;
  mime: string;
  kind: "image" | "video";
  thumb?: string; // base64 JPEG, ≤ MAX_THUMB bytes
  stripped?: boolean; // metadata removal was applied before encryption
}
export const MAX_THUMB = 12 * 1024;
const HEX = (n: number) => new RegExp(`^[0-9a-f]{${n}}$`);
export const encodeDescriptor = (d: Descriptor) => PREFIX + canonical(d);
export const isAttachmentMessage = (m: string) => m.startsWith(PREFIX);
/** Strictly validate an untrusted descriptor; returns null if anything is off. */
export function parseDescriptor(message: string): Descriptor | null {
  if (!isAttachmentMessage(message) || message.length > 64 * 1024) return null;
  try {
    const d = JSON.parse(message.slice(PREFIX.length));
    const ok =
      d && typeof d === "object" && d.v === 1 &&
      typeof d.id === "string" && HEX(32).test(d.id) &&
      typeof d.key === "string" && d.key.length === 44 &&
      typeof d.name === "string" && d.name.length <= 200 &&
      ALLOWED_MIME.includes(d.mime) &&
      (d.kind === "image" || d.kind === "video") &&
      d.mime.startsWith(d.kind + "/") &&
      Number.isSafeInteger(d.size) && d.size > 0 &&
      Number.isSafeInteger(d.chunk) && d.chunk >= 4096 && d.chunk <= 8 * CHUNK &&
      d.ct_size === ciphertextSize(d.size, d.chunk) &&
      typeof d.ct_sha256 === "string" && HEX(64).test(d.ct_sha256) &&
      typeof d.pt_sha256 === "string" && HEX(64).test(d.pt_sha256) &&
      (d.thumb === undefined ||
        (typeof d.thumb === "string" && d.thumb.length <= Math.ceil((MAX_THUMB * 4) / 3) + 4 && /^[A-Za-z0-9+/=]*$/.test(d.thumb)));
    return ok ? (d as Descriptor) : null;
  } catch {
    return null;
  }
}
export const describe = (d: Descriptor) =>
  `${d.kind === "image" ? "🖼" : "🎞"} ${d.name}`;
