import { describe, it, expect } from "vitest";
import {
  encryptFile,
  decryptFile,
  AttachmentError,
  CHUNK,
  OVERHEAD,
  ciphertextSize,
  newFileId,
} from "../src/attachments/fileCrypto";
import {
  sniff,
  stripMetadata,
  stripJpeg,
  stripPng,
  stripGif,
  stripWebp,
  jpegHasGps,
  sanitizeFilename,
} from "../src/attachments/media";
import {
  encodeDescriptor,
  parseDescriptor,
  isAttachmentMessage,
  type Descriptor,
} from "../src/attachments/descriptor";
import * as c from "../src/crypto";

const bytes = (...v: number[]) => Uint8Array.from(v);
const text = (s: string) => new TextEncoder().encode(s);
const cat = (...p: Uint8Array[]) => c.concat(...p);
const rand = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536)
    crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
};
const SMALL = 4096; // small chunks keep multi-chunk tests quick

describe("chunked AES-GCM file encryption", () => {
  it("round-trips multi-chunk files and reports the exact ciphertext size", async () => {
    const plain = rand(SMALL * 3 + 123);
    const { ciphertext, secrets } = await encryptFile(plain, { chunk: SMALL });
    expect(ciphertext.length).toBe(plain.length + 4 * OVERHEAD);
    expect(secrets.ct_size).toBe(ciphertext.length);
    expect(secrets.ct_sha256).toBe(c.hex(await c.sha(ciphertext)));
    expect(secrets.pt_sha256).toBe(c.hex(await c.sha(plain)));
    expect(await decryptFile(ciphertext, secrets)).toEqual(plain);
  });
  it("round-trips an exact multiple of the chunk size and a one-byte file", async () => {
    for (const n of [SMALL * 2, 1]) {
      const plain = rand(n);
      const { ciphertext, secrets } = await encryptFile(plain, {
        chunk: SMALL,
      });
      expect(await decryptFile(ciphertext, secrets)).toEqual(plain);
    }
  });
  it("uses the default 1 MiB chunk size", async () => {
    const plain = rand(CHUNK + 10);
    const { ciphertext, secrets } = await encryptFile(plain);
    expect(secrets.chunk).toBe(CHUNK);
    expect(ciphertext.length).toBe(ciphertextSize(plain.length));
    expect(await decryptFile(ciphertext, secrets)).toEqual(plain);
  });
  it("uses a fresh key, nonces and ciphertext for the same plaintext", async () => {
    const plain = rand(SMALL * 2);
    const a = await encryptFile(plain, { chunk: SMALL }),
      b = await encryptFile(plain, { chunk: SMALL });
    expect(a.secrets.key).not.toBe(b.secrets.key);
    expect(a.secrets.ct_sha256).not.toBe(b.secrets.ct_sha256);
    expect(a.ciphertext.slice(0, 12)).not.toEqual(
      a.ciphertext.slice(SMALL + OVERHEAD, SMALL + OVERHEAD + 12),
    );
  });
  it("does not contain the plaintext", async () => {
    const marker = text("ATTACHMENT-PLAINTEXT-MARKER-1234567890");
    const plain = cat(marker, rand(SMALL));
    const { ciphertext } = await encryptFile(plain, { chunk: SMALL });
    const hay = new TextDecoder("latin1").decode(ciphertext);
    expect(hay.includes("ATTACHMENT-PLAINTEXT-MARKER")).toBe(false);
  });
  it("rejects reordered chunks (AAD binds the chunk index)", async () => {
    const plain = rand(SMALL * 3);
    const { ciphertext, secrets } = await encryptFile(plain, { chunk: SMALL });
    const rec = SMALL + OVERHEAD;
    const swapped = cat(
      ciphertext.slice(rec, 2 * rec),
      ciphertext.slice(0, rec),
      ciphertext.slice(2 * rec),
    );
    // The attacker also fixes up the ciphertext hash the way a malicious storage could.
    const forged = { ...secrets, ct_sha256: c.hex(await c.sha(swapped)) };
    await expect(decryptFile(swapped, forged)).rejects.toMatchObject({
      code: "chunk_auth",
    });
  });
  it("rejects a dropped chunk and a truncated final chunk", async () => {
    const plain = rand(SMALL * 3);
    const { ciphertext, secrets } = await encryptFile(plain, { chunk: SMALL });
    const rec = SMALL + OVERHEAD;
    const dropped = cat(ciphertext.slice(0, rec), ciphertext.slice(2 * rec));
    await expect(decryptFile(dropped, secrets)).rejects.toMatchObject({
      code: "size",
    });
    // Same lengths as the signed message claim, but the file was shortened and the
    // descriptor edited to match: the final chunk's is_last AAD still fails.
    const short = ciphertext.slice(0, 2 * rec);
    const forged: typeof secrets = {
      ...secrets,
      size: SMALL * 2,
      ct_size: short.length,
      ct_sha256: c.hex(await c.sha(short)),
      pt_sha256: c.hex(await c.sha(plain.slice(0, SMALL * 2))),
    };
    await expect(decryptFile(short, forged)).rejects.toMatchObject({
      code: "chunk_auth",
    });
  });
  it("rejects chunks moved between files with the same key (AAD binds the file id)", async () => {
    const plain = rand(SMALL * 2);
    const a = await encryptFile(plain, { chunk: SMALL, id: newFileId() });
    const asOther = { ...a.secrets, id: newFileId() };
    await expect(decryptFile(a.ciphertext, asOther)).rejects.toMatchObject({
      code: "chunk_auth",
    });
  });
  it("detects any single flipped ciphertext byte via the ciphertext hash", async () => {
    const { ciphertext, secrets } = await encryptFile(rand(SMALL * 2), {
      chunk: SMALL,
    });
    const bad = ciphertext.slice();
    bad[bad.length >> 1] ^= 1;
    await expect(decryptFile(bad, secrets)).rejects.toMatchObject({
      code: "ciphertext_hash",
    });
  });
  it("detects tampering even if the hash is bypassed (GCM tag)", async () => {
    const { ciphertext, secrets } = await encryptFile(rand(SMALL * 2), {
      chunk: SMALL,
    });
    const bad = ciphertext.slice();
    bad[40] ^= 0x80;
    const forged = { ...secrets, ct_sha256: c.hex(await c.sha(bad)) };
    await expect(decryptFile(bad, forged)).rejects.toMatchObject({
      code: "chunk_auth",
    });
  });
  it("detects a wrong plaintext hash and a wrong key", async () => {
    const { ciphertext, secrets } = await encryptFile(rand(SMALL), {
      chunk: SMALL,
    });
    await expect(
      decryptFile(ciphertext, { ...secrets, pt_sha256: "0".repeat(64) }),
    ).rejects.toMatchObject({ code: "plaintext_hash" });
    const other = await encryptFile(rand(SMALL), { chunk: SMALL });
    await expect(
      decryptFile(ciphertext, { ...secrets, key: other.secrets.key }),
    ).rejects.toMatchObject({ code: "chunk_auth" });
    expect(new AttachmentError("size", "x")).toBeInstanceOf(Error);
  });
  it("honours cancellation and reports progress", async () => {
    const seen: number[] = [];
    await encryptFile(rand(SMALL * 3), {
      chunk: SMALL,
      onProgress: (d) => seen.push(d),
    });
    expect(seen).toEqual([1, 2, 3]);
    const ctl = new AbortController();
    ctl.abort();
    await expect(
      encryptFile(rand(SMALL * 2), { chunk: SMALL, signal: ctl.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });
});

// ---- magic bytes ------------------------------------------------------
const JPEG_HEAD = bytes(0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0);
const PNG_SIG = bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
const mp4 = (brand: string) =>
  cat(bytes(0, 0, 0, 0x18), text("ftyp" + brand), new Uint8Array(12));
describe("magic-byte sniffing", () => {
  it("accepts the six allowed types by content", () => {
    expect(sniff(JPEG_HEAD)?.mime).toBe("image/jpeg");
    expect(sniff(cat(PNG_SIG, new Uint8Array(8)))?.mime).toBe("image/png");
    expect(sniff(cat(text("GIF89a"), new Uint8Array(8)))?.mime).toBe(
      "image/gif",
    );
    expect(
      sniff(cat(text("RIFF"), bytes(0, 0, 0, 0), text("WEBPVP8 ")))?.mime,
    ).toBe("image/webp");
    expect(sniff(mp4("isom"))).toMatchObject({
      kind: "video",
      mime: "video/mp4",
    });
    expect(
      sniff(
        cat(
          bytes(0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x82, 0x84),
          text("webm"),
          new Uint8Array(8),
        ),
      )?.mime,
    ).toBe("video/webm");
  });
  it("rejects SVG, HTML, scripts, Matroska, HEIC and empty/short input regardless of extension", () => {
    for (const bad of [
      text(
        '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      ),
      text("<!doctype html><script>1</script>"),
      text("GIF89"),
      text("#!/bin/sh\necho"),
      mp4("heic"),
      mp4("avif"),
      cat(
        bytes(0x1a, 0x45, 0xdf, 0xa3, 0x93, 0x42, 0x82, 0x88),
        text("matroska"),
        new Uint8Array(8),
      ),
      new Uint8Array(0),
      bytes(0xff, 0xd8),
    ])
      expect(sniff(bad)).toBeNull();
  });
  it("trusts content, not a lying name: a script named .jpg is rejected", () => {
    expect(sniff(text("<script>alert(1)</script>"))).toBeNull();
  });
});

// ---- metadata stripping -------------------------------------------------
function exifSegment(orientation: number, withGps: boolean, little = false) {
  const u16 = (v: number) => (little ? [v & 255, v >> 8] : [v >> 8, v & 255]);
  const u32 = (v: number) =>
    little
      ? [v & 255, (v >> 8) & 255, (v >> 16) & 255, v >>> 24]
      : [v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255];
  const entries = [
    [0x0112, 3, 1, orientation],
    ...(withGps ? [[0x8825, 4, 1, 0x40]] : []),
  ];
  const ifd = [...u16(entries.length)];
  for (const [tag, type, count, value] of entries)
    ifd.push(
      ...u16(tag),
      ...u16(type),
      ...u32(count),
      ...(type === 3 ? [...u16(value), 0, 0] : u32(value)),
    );
  ifd.push(0, 0, 0, 0);
  const tiff = [
    ...(little ? [0x49, 0x49, 0x2a, 0] : [0x4d, 0x4d, 0, 0x2a]),
    ...u32(8),
    ...ifd,
  ];
  while (tiff.length < 0x40 + 20) tiff.push(0);
  const payload = [...text("Exif\0\0"), ...tiff];
  return bytes(
    0xff,
    0xe1,
    (payload.length + 2) >> 8,
    (payload.length + 2) & 255,
    ...payload,
  );
}
const seg = (marker: number, body: Uint8Array) =>
  bytes(0xff, marker, (body.length + 2) >> 8, (body.length + 2) & 255, ...body);
function fakeJpeg(extra: Uint8Array[]) {
  const scan = bytes(0xff, 0xda, 0, 4, 1, 0, 0xaa, 0xbb, 0xcc, 0xff, 0xd9);
  return cat(
    bytes(0xff, 0xd8),
    seg(0xe0, text("JFIF\0\x01\x01\0\0\x01\0\x01\0\0")),
    ...extra,
    seg(0xdb, new Uint8Array(65)),
    scan,
  );
}
describe("metadata stripping", () => {
  it("removes Exif GPS, XMP, IPTC and comments from JPEGs but keeps the image data", () => {
    const original = fakeJpeg([
      exifSegment(1, true),
      seg(
        0xe1,
        text(
          "http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>GPSLatitude</x:xmpmeta>",
        ),
      ),
      seg(0xed, text("Photoshop 3.0\0IPTC")),
      seg(0xfe, text("taken at home")),
    ]);
    expect(jpegHasGps(original)).toBe(true);
    const out = stripJpeg(original);
    expect(jpegHasGps(out)).toBe(false);
    const s = new TextDecoder("latin1").decode(out);
    for (const gone of ["GPS", "xmpmeta", "Photoshop", "taken at home"])
      expect(s.includes(gone)).toBe(false);
    expect(s.includes("JFIF")).toBe(true);
    expect(out.slice(-9)).toEqual(original.slice(-9)); // scan data + EOI untouched
    expect(out.length).toBeLessThan(original.length);
  });
  it("keeps only the display orientation (no GPS) when the photo is rotated", () => {
    for (const little of [false, true]) {
      const out = stripJpeg(fakeJpeg([exifSegment(6, true, little)]));
      expect(jpegHasGps(out)).toBe(false);
      const view = new TextDecoder("latin1").decode(out);
      expect(view.includes("Exif")).toBe(true);
      // Re-parse our own minimal Exif: orientation 6 survives, and exactly one IFD entry.
      const i = view.indexOf("Exif");
      expect(out[i + 6 + 9]).toBe(1); // exactly one IFD entry
      expect([out[i + 6 + 10], out[i + 6 + 11]]).toEqual([0x01, 0x12]); // Orientation tag
      expect(out[i + 6 + 19]).toBe(6);
    }
  });
  it("removes Exif entirely when orientation is the default", () => {
    const out = stripJpeg(fakeJpeg([exifSegment(1, true)]));
    expect(new TextDecoder("latin1").decode(out).includes("Exif")).toBe(false);
  });
  it("is idempotent and leaves a malformed JPEG untouched", () => {
    const once = stripJpeg(fakeJpeg([exifSegment(1, true)]));
    expect(stripJpeg(once)).toEqual(once);
    const broken = cat(
      bytes(0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff),
      text("garbage"),
    );
    expect(stripJpeg(broken)).toEqual(broken);
  });
  it("drops PNG text/time/eXIf chunks and keeps pixel chunks", () => {
    const chunk = (type: string, body: Uint8Array) => {
      const len = bytes(
        body.length >>> 24,
        (body.length >> 16) & 255,
        (body.length >> 8) & 255,
        body.length & 255,
      );
      return cat(len, text(type), body, bytes(1, 2, 3, 4));
    };
    const png = cat(
      PNG_SIG,
      chunk("IHDR", new Uint8Array(13)),
      chunk("eXIf", text("GPS here")),
      chunk("tEXt", text("Author\0Sam")),
      chunk("tIME", new Uint8Array(7)),
      chunk("IDAT", text("pixels")),
      chunk("IEND", new Uint8Array(0)),
    );
    const out = stripPng(png);
    const s = new TextDecoder("latin1").decode(out);
    expect(
      s.includes("eXIf") ||
        s.includes("tEXt") ||
        s.includes("tIME") ||
        s.includes("Sam"),
    ).toBe(false);
    expect(s.includes("IHDR") && s.includes("IDAT") && s.includes("IEND")).toBe(
      true,
    );
  });
  it("drops GIF comments but keeps frames and the animation loop block", () => {
    const gif = cat(
      text("GIF89a"),
      bytes(1, 0, 1, 0, 0x00, 0, 0),
      bytes(0x21, 0xff, 11),
      text("NETSCAPE2.0"),
      bytes(3, 1, 0, 0, 0),
      bytes(0x21, 0xfe, 9),
      text("my secret"),
      bytes(0),
      bytes(0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 1, 0),
      bytes(0x3b),
    );
    const out = stripGif(gif);
    const s = new TextDecoder("latin1").decode(out);
    expect(s.includes("my secret")).toBe(false);
    expect(s.includes("NETSCAPE2.0")).toBe(true);
    expect(out[out.length - 1]).toBe(0x3b);
    expect(sniff(out)?.mime).toBe("image/gif");
  });
  it("drops WebP EXIF/XMP chunks, clears VP8X flags and fixes the RIFF size", () => {
    const riffChunk = (id: string, body: Uint8Array) => {
      const padded = body.length & 1 ? cat(body, bytes(0)) : body;
      return cat(
        text(id),
        bytes(body.length & 255, (body.length >> 8) & 255, 0, 0),
        padded,
      );
    };
    const vp8x = riffChunk("VP8X", bytes(0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    const body = cat(
      text("WEBP"),
      vp8x,
      riffChunk("EXIF", text("GPS data!")),
      riffChunk("XMP ", text("xmp")),
      riffChunk("VP8 ", text("pixeldata")),
    );
    const webp = cat(
      text("RIFF"),
      bytes(body.length & 255, body.length >> 8, 0, 0),
      body,
    );
    const out = stripWebp(webp);
    const s = new TextDecoder("latin1").decode(out);
    expect(
      s.includes("EXIF") || s.includes("GPS data") || s.includes("XMP "),
    ).toBe(false);
    expect(s.includes("pixeldata")).toBe(true);
    expect(out[20] & 0x0c).toBe(0);
    expect(out[4] | (out[5] << 8)).toBe(out.length - 8);
  });
  it("stripMetadata dispatches by sniffed mime and passes video through", () => {
    const j = fakeJpeg([exifSegment(1, true)]);
    expect(jpegHasGps(stripMetadata(j, "image/jpeg"))).toBe(false);
    const v = mp4("isom");
    expect(stripMetadata(v, "video/mp4")).toBe(v);
  });
});

describe("QuickTime content detection", () => {
  it("accepts the exact QuickTime brand and keeps the existing MP4/WebM rules", () => {
    expect(sniff(mp4("qt  "))).toEqual({
      kind: "video",
      mime: "video/quicktime",
      ext: "mov",
    });
    expect(sniff(mp4("qtXX"))).toBeNull();
    expect(sniff(mp4("zzzz"))).toBeNull();
    expect(sniff(text("fake.mov ftyp qt"))).toBeNull();
  });
});

describe("filenames and descriptors", () => {
  it("sanitises paths, control and bidi characters and forces the verified extension", () => {
    expect(sanitizeFilename("../../etc/passwd.html", "jpg")).not.toMatch(
      /[\\/]/,
    );
    expect(sanitizeFilename("a\u202egpj.exe", "png")).not.toMatch(/[\u202e]/);
    expect(sanitizeFilename("C:\\Users\\me\\cat.png", "png")).not.toMatch(
      /[\\/:]/,
    );
    expect(sanitizeFilename("", "mp4")).toBe("attachment.mp4");
    expect(sanitizeFilename(".htaccess", "gif")).toBe("htaccess.gif");
    expect(
      sanitizeFilename("x".repeat(500) + ".png", "png").length,
    ).toBeLessThanOrEqual(84);
    expect(sanitizeFilename("evil<script>.svg", "png")).toBe(
      "evil_script_.png",
    );
  });
  const valid = async (): Promise<Descriptor> => {
    const { secrets } = await encryptFile(rand(SMALL), { chunk: SMALL });
    return {
      v: 1,
      ...secrets,
      name: "cat.jpg",
      mime: "image/jpeg",
      kind: "image",
    };
  };
  it("round-trips and recognises the message prefix", async () => {
    const d = await valid();
    const m = encodeDescriptor(d);
    expect(isAttachmentMessage(m)).toBe(true);
    expect(parseDescriptor(m)).toEqual(d);
    expect(parseDescriptor("hello")).toBeNull();
  });
  it("rejects malformed or hostile descriptors", async () => {
    const d = await valid();
    const bad: Array<Partial<Descriptor> | Record<string, unknown>> = [
      { mime: "image/svg+xml" },
      { mime: "text/html" },
      { kind: "video" },
      { id: "../x" },
      { key: "short" },
      { size: 0 },
      { size: 1.5 },
      { chunk: 1 },
      { ct_size: d.ct_size + 1 },
      { ct_sha256: "xyz" },
      { thumb: "<script>" },
      { thumb: "A".repeat(40000) },
      { v: 2 },
    ];
    for (const patch of bad)
      expect(
        parseDescriptor(
          "securechat-attachment/v1:" + JSON.stringify({ ...d, ...patch }),
        ),
      ).toBeNull();
    expect(parseDescriptor("securechat-attachment/v1:{not json")).toBeNull();
    expect(parseDescriptor("securechat-attachment/v1:null")).toBeNull();
  });
});

// ---- Python <-> browser byte compatibility ---------------------------------
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../../../", import.meta.url)),
  corpus = root + "tests/fixtures/evidence_corpus/";
describe("Python <-> browser attachment compatibility", () => {
  it("the browser decrypts the Python-encrypted corpus object from its signed descriptor", async () => {
    const evidence = JSON.parse(
      readFileSync(corpus + "valid_v2_attachment.json", "utf8"),
    );
    const d = parseDescriptor(evidence.records[1].message)!;
    expect(d).not.toBeNull();
    const plain = await decryptFile(
      new Uint8Array(readFileSync(corpus + "attachment_sample.enc")),
      d,
    );
    expect(plain).toEqual(
      new Uint8Array(readFileSync(corpus + "attachment_sample.png")),
    );
    expect(sniff(plain)?.mime).toBe("image/png");
  });
  it("Python decrypts a multi-chunk browser-encrypted file", async () => {
    const plain = rand(SMALL * 2 + 77);
    const { ciphertext, secrets } = await encryptFile(plain, { chunk: SMALL });
    const code = `import sys,json,base64;sys.path.insert(0,sys.argv[1]);from crypto_engine.attachment_tools import decrypt_file;d=json.load(sys.stdin);out=decrypt_file(base64.b64decode(d['ct']),d['s']);print(base64.b64encode(out).decode())`;
    const out = execFileSync(root + ".venv/bin/python", ["-c", code, root], {
      input: JSON.stringify({ ct: c.b64(ciphertext), s: secrets }),
      encoding: "utf8",
    });
    expect(c.un64(out.trim())).toEqual(plain);
  });
});
