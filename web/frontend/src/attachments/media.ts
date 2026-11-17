// Magic-byte type detection, metadata stripping and filename sanitising for
// attachments. Pure byte functions: no DOM, so they run under Vitest too.
export type Kind = "image" | "video";
export interface Sniffed {
  kind: Kind;
  mime: string;
  ext: string;
}
const ascii = (b: Uint8Array, at: number, len: number) =>
  String.fromCharCode(...b.slice(at, at + len));
const startsWith = (b: Uint8Array, sig: number[]) =>
  b.length >= sig.length && sig.every((v, i) => b[i] === v);
const MP4_BRANDS = new Set([
  "isom", "iso2", "iso3", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1",
  "dash", "M4V ", "mmp4", "f4v ",
]);
/** Decide the type from content alone. The declared MIME / extension are ignored. */
export function sniff(b: Uint8Array): Sniffed | null {
  if (startsWith(b, [0xff, 0xd8, 0xff]))
    return { kind: "image", mime: "image/jpeg", ext: "jpg" };
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    return { kind: "image", mime: "image/png", ext: "png" };
  if (b.length > 6 && ["GIF87a", "GIF89a"].includes(ascii(b, 0, 6)))
    return { kind: "image", mime: "image/gif", ext: "gif" };
  if (b.length > 12 && ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 4) === "WEBP")
    return { kind: "image", mime: "image/webp", ext: "webp" };
  if (b.length > 12 && ascii(b, 4, 4) === "ftyp" && MP4_BRANDS.has(ascii(b, 8, 4)))
    return { kind: "video", mime: "video/mp4", ext: "mp4" };
  if (startsWith(b, [0x1a, 0x45, 0xdf, 0xa3])) {
    // EBML: accept the "webm" DocType only (Matroska .mkv is not allowed).
    const head = ascii(b, 0, Math.min(b.length, 64));
    if (head.includes("webm") && !head.includes("matroska"))
      return { kind: "video", mime: "video/webm", ext: "webm" };
  }
  return null;
}
export const ALLOWED_MIME = [
  "image/jpeg", "image/png", "image/webp", "image/gif", "video/mp4", "video/webm",
];

const concatBytes = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};

// ---- JPEG: drop Exif/XMP/IPTC/comments, keep a minimal Orientation tag ----
function exifOrientation(app1: Uint8Array): number {
  // app1 = payload after the 2-byte length. Expect "Exif\0\0" + TIFF header.
  if (ascii(app1, 0, 4) !== "Exif") return 1;
  const t = 6;
  const little = ascii(app1, t, 2) === "II";
  const dv = new DataView(app1.buffer, app1.byteOffset, app1.byteLength);
  try {
    const ifd = t + dv.getUint32(t + 4, little);
    const count = dv.getUint16(ifd, little);
    for (let i = 0; i < count; i++) {
      const e = ifd + 2 + i * 12;
      if (dv.getUint16(e, little) === 0x0112) {
        const v = dv.getUint16(e + 8, little);
        return v >= 1 && v <= 8 ? v : 1;
      }
    }
  } catch {
    /* malformed Exif: treat as no orientation */
  }
  return 1;
}
function orientationSegment(value: number): Uint8Array {
  // APP1 "Exif\0\0" + big-endian TIFF with exactly one IFD0 entry (Orientation).
  const tiff = [
    0x4d, 0x4d, 0x00, 0x2a, 0, 0, 0, 8, 0, 1,
    0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, value, 0, 0, 0, 0, 0, 0,
  ];
  const payload = [0x45, 0x78, 0x69, 0x66, 0, 0, ...tiff];
  const len = payload.length + 2;
  return Uint8Array.from([0xff, 0xe1, len >> 8, len & 255, ...payload]);
}
export function stripJpeg(b: Uint8Array): Uint8Array {
  const out: Uint8Array[] = [b.slice(0, 2)];
  let i = 2,
    orientation = 1;
  while (i + 4 <= b.length) {
    if (b[i] !== 0xff) break;
    const marker = b[i + 1];
    if (marker === 0xff) {
      i++;
      continue;
    }
    if (marker === 0xda) break; // start of scan: the rest is entropy-coded data
    if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
      out.push(b.slice(i, i + 2));
      i += 2;
      continue;
    }
    const len = (b[i + 2] << 8) | b[i + 3];
    if (len < 2 || i + 2 + len > b.length) return b; // malformed: leave untouched
    const segment = b.slice(i, i + 2 + len);
    const payload = segment.slice(4);
    // APP1 (Exif, XMP), APP13 (IPTC/Photoshop), other APPn (except ICC APP2,
    // Adobe APP14 and JFIF APP0) and COM carry metadata: drop them.
    const keep =
      marker === 0xe0 ||
      marker === 0xee ||
      (marker === 0xe2 && ascii(payload, 0, 11) === "ICC_PROFILE") ||
      !(marker >= 0xe1 && marker <= 0xef) && marker !== 0xfe;
    if (marker === 0xe1 && ascii(payload, 0, 4) === "Exif")
      orientation = exifOrientation(payload);
    if (keep) out.push(segment);
    i += 2 + len;
  }
  out.push(b.slice(i));
  const result = concatBytes(out);
  if (orientation === 1) return result;
  // Keep display orientation (no location, no camera data) right after SOI.
  return concatBytes([result.slice(0, 2), orientationSegment(orientation), result.slice(2)]);
}

// ---- PNG ----
const PNG_DROP = new Set(["eXIf", "tEXt", "iTXt", "zTXt", "tIME"]);
export function stripPng(b: Uint8Array): Uint8Array {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: Uint8Array[] = [b.slice(0, 8)];
  let i = 8;
  while (i + 12 <= b.length) {
    const len = dv.getUint32(i);
    const type = ascii(b, i + 4, 4);
    if (i + 12 + len > b.length) return b;
    if (!PNG_DROP.has(type)) out.push(b.slice(i, i + 12 + len));
    i += 12 + len;
    if (type === "IEND") break;
  }
  return concatBytes(out);
}

// ---- GIF: drop comment, plain-text and non-NETSCAPE application extensions ----
export function stripGif(b: Uint8Array): Uint8Array {
  const out: Uint8Array[] = [];
  const flags = b[10];
  let i = 13 + (flags & 0x80 ? 3 * (1 << ((flags & 7) + 1)) : 0);
  out.push(b.slice(0, i));
  const skipBlocks = (at: number) => {
    while (at < b.length && b[at] !== 0) at += b[at] + 1;
    return at + 1;
  };
  while (i < b.length) {
    const t = b[i];
    if (t === 0x3b) {
      out.push(b.slice(i, i + 1));
      return concatBytes(out);
    }
    if (t === 0x21) {
      const label = b[i + 1];
      let end: number;
      if (label === 0xff) {
        // application extension header is 11 bytes: keep only NETSCAPE/ANIMEXTS (loop count)
        const app = ascii(b, i + 3, 11);
        end = skipBlocks(i + 2 + 1 + b[i + 2]);
        if (app.startsWith("NETSCAPE") || app.startsWith("ANIMEXTS"))
          out.push(b.slice(i, end));
      } else {
        end = skipBlocks(i + 2);
        if (label === 0xf9) out.push(b.slice(i, end)); // graphic control: timing/transparency
      }
      i = end;
    } else if (t === 0x2c) {
      let j = i + 10;
      const lf = b[i + 9];
      if (lf & 0x80) j += 3 * (1 << ((lf & 7) + 1));
      j = skipBlocks(j + 1); // LZW min code size byte, then sub-blocks
      out.push(b.slice(i, j));
      i = j;
    } else return b; // unexpected block: leave the file untouched
  }
  return concatBytes(out);
}

// ---- WebP (RIFF): drop EXIF and XMP chunks and clear their VP8X flags ----
export function stripWebp(b: Uint8Array): Uint8Array {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: Uint8Array[] = [b.slice(0, 12)];
  let i = 12;
  while (i + 8 <= b.length) {
    const type = ascii(b, i, 4);
    const len = dv.getUint32(i + 4, true);
    const total = 8 + len + (len & 1);
    if (i + total > b.length + 1) return b;
    let chunk = b.slice(i, Math.min(i + total, b.length));
    if (type === "EXIF" || type === "XMP ") {
      i += total;
      continue;
    }
    if (type === "VP8X" && chunk.length >= 9) {
      chunk = chunk.slice();
      chunk[8] &= ~(0x08 | 0x04); // EXIF + XMP present bits
    }
    out.push(chunk);
    i += total;
  }
  const result = concatBytes(out);
  new DataView(result.buffer).setUint32(4, result.length - 8, true);
  return result;
}

/** Remove location/camera/author metadata without re-encoding the pixels. */
export function stripMetadata(b: Uint8Array, mime: string): Uint8Array {
  try {
    if (mime === "image/jpeg") return stripJpeg(b);
    if (mime === "image/png") return stripPng(b);
    if (mime === "image/gif") return stripGif(b);
    if (mime === "image/webp") return stripWebp(b);
  } catch {
    /* fall through: never lose the user's file because stripping failed */
  }
  return b;
}
/** True if a JPEG still carries GPS data (Exif GPS IFD pointer or XMP GPS tags). */
export function jpegHasGps(b: Uint8Array): boolean {
  let i = 2;
  while (i + 4 <= b.length && b[i] === 0xff && b[i + 1] !== 0xda) {
    const len = (b[i + 2] << 8) | b[i + 3];
    const payload = b.slice(i + 4, i + 2 + len);
    if (b[i + 1] === 0xe1) {
      if (ascii(payload, 0, 4) === "Exif") {
        const little = ascii(payload, 6, 2) === "II";
        const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
        const ifd = 6 + dv.getUint32(10, little);
        const count = dv.getUint16(ifd, little);
        for (let n = 0; n < count; n++)
          if (dv.getUint16(ifd + 2 + n * 12, little) === 0x8825) return true;
      } else if (new TextDecoder("latin1").decode(payload).includes("GPS")) return true;
    }
    i += 2 + len;
  }
  return false;
}

/** A safe display/download name: no paths, controls, bidi overrides; right extension. */
export function sanitizeFilename(name: string, ext: string): string {
  let base = String(name ?? "")
    .normalize("NFC")
    .replace(/[\\/]+/g, "_")
    .replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩​-‏﻿]/g, "")
    .replace(/[<>:"|?*]/g, "_")
    .trim();
  base = base.replace(/\.[A-Za-z0-9]{1,5}$/, "").replace(/^\.+/, "").trim();
  base = Array.from(base).slice(0, 80).join("");
  if (!base) base = "attachment";
  return `${base}.${ext}`;
}
