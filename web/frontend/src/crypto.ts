import { x25519 } from "@noble/curves/ed25519.js";
import type { pki } from "node-forge";
const fallbackPrivate = new WeakMap<CryptoKey, pki.rsa.PrivateKey>();
const publicPem = new WeakMap<CryptoKey, string>();
const binary = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => String.fromCharCode(b)).join("");
const forge = async () => (await import("node-forge")).default;
export const utf8 = (s: string) => new TextEncoder().encode(s);
export const b64 = (b: Uint8Array) =>
  btoa(Array.from(b, (v) => String.fromCharCode(v)).join(""));
export const un64 = (s: string) =>
  Uint8Array.from(atob(s), (v) => v.charCodeAt(0));
export const raw = (b: Uint8Array): ArrayBuffer => new Uint8Array(b).buffer;
export const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};
export function compare(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0)!),
    y = Array.from(b, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(x.length, y.length); i++)
    if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}
// Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True).
export function canonical(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "string")
    return JSON.stringify(v).replace(
      /[\u007f-\uffff]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    );
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v))
      throw Error("Protocol numbers must be safe integers");
    return String(v);
  }
  if (typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object")
    return (
      "{" +
      Object.keys(v)
        .sort(compare)
        .map(
          (k) =>
            canonical(k) + ":" + canonical((v as Record<string, unknown>)[k]),
        )
        .join(",") +
      "}"
    );
  throw Error("Unsupported canonical value");
}
export const sha = async (b: Uint8Array) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", raw(b)));
export const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const hash = async (v: unknown) => hex(await sha(utf8(canonical(v))));
export const fingerprint = async (pem: string) =>
  hex(await sha(utf8(pem)))
    .slice(0, 16)
    .toUpperCase()
    .match(/.{4}/g)!
    .join(" ");
const rsa = { name: "RSA-PSS", hash: "SHA-256" };
export async function sign(key: CryptoKey, b: Uint8Array) {
  const legacy = fallbackPrivate.get(key);
  if (!legacy)
    return new Uint8Array(
      await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 222 },
        key,
        raw(b),
      ),
    );
  const f = await forge();
  const md = f.md.sha256.create();
  md.update(binary(b));
  // WebKit's native RSA-PSS rejects MAX_LENGTH. Preserve the exact protocol,
  // using forge only for this runtime key and CSPRNG-generated 222-byte salt.
  const pss = f.pss.create({
    md: f.md.sha256.create(),
    mgf: f.mgf.mgf1.create(f.md.sha256.create()),
    saltLength: 222,
    salt: f.util.createBuffer(
      binary(crypto.getRandomValues(new Uint8Array(222))),
    ),
  });
  return Uint8Array.from(legacy.sign(md, pss), (x) => x.charCodeAt(0));
}
export async function verify(key: CryptoKey, b: Uint8Array, sig: Uint8Array) {
  try {
    if (
      await crypto.subtle.verify(
        { name: "RSA-PSS", saltLength: 222 },
        key,
        raw(sig),
        raw(b),
      )
    )
      return true;
  } catch (error) {
    if (
      !["OperationError", "NotSupportedError"].includes((error as Error).name)
    )
      return false;
  }
  const pem = publicPem.get(key);
  if (!pem) return false;
  try {
    const f = await forge();
    const md = f.md.sha256.create();
    md.update(binary(b));
    return f.pki
      .publicKeyFromPem(pem)
      .verify(
        md.digest().bytes(),
        binary(sig),
        f.pss.create({
          md: f.md.sha256.create(),
          mgf: f.mgf.mgf1.create(f.md.sha256.create()),
          saltLength: 222,
        }),
      );
  } catch {
    return false;
  }
}
export const pem = (b: Uint8Array, label: string) =>
  `-----BEGIN ${label}-----\n${b64(b)
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END ${label}-----\n`;
const der = (s: string) => un64(s.replace(/-----[^-]+-----|\s/g, ""));
export async function publicKey(s: string) {
  const key = await crypto.subtle.importKey("spki", raw(der(s)), rsa, true, [
    "verify",
  ]);
  publicPem.set(key, s);
  return key;
}
export async function privateKey(b: Uint8Array) {
  const key = await crypto.subtle.importKey("pkcs8", raw(b), rsa, false, [
    "sign",
  ]);
  try {
    await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 222 },
      key,
      new Uint8Array(0),
    );
  } catch (error) {
    if (
      !["OperationError", "NotSupportedError"].includes((error as Error).name)
    )
      throw error;
    const f = await forge();
    fallbackPrivate.set(
      key,
      f.pki.privateKeyFromAsn1(f.asn1.fromDer(binary(b), true)),
    );
  }
  return key;
}
export async function identity() {
  const keys = (await crypto.subtle.generateKey(
    { ...rsa, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return {
    privateBytes: new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", keys.privateKey),
    ),
    publicPem: pem(
      new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey)),
      "PUBLIC KEY",
    ),
  };
}
export interface Ephemeral {
  pub: Uint8Array;
  secret?: CryptoKey | Uint8Array;
}
export async function ephemeral(fallback = false): Promise<Ephemeral> {
  if (!fallback)
    try {
      const pair = (await crypto.subtle.generateKey("X25519", true, [
        "deriveBits",
      ])) as CryptoKeyPair;
      return {
        pub: new Uint8Array(
          await crypto.subtle.exportKey("raw", pair.publicKey),
        ),
        secret: pair.privateKey,
      };
    } catch {
      /* Older browsers: audited noble implementation. */
    }
  const secret = x25519.utils.randomSecretKey();
  return { pub: x25519.getPublicKey(secret), secret };
}
export async function shared(
  own: Ephemeral,
  peer: Uint8Array,
): Promise<CryptoKey> {
  if (peer.length !== 32 || !own.secret)
    throw Error("Invalid or consumed ephemeral key");
  let bytes: Uint8Array;
  const secret = own.secret;
  own.secret = undefined;
  if (secret instanceof Uint8Array) {
    try {
      bytes = x25519.getSharedSecret(secret, peer);
    } finally {
      secret.fill(0);
    }
  } else {
    const pub = await crypto.subtle.importKey(
      "raw",
      raw(peer),
      "X25519",
      false,
      [],
    );
    bytes = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "X25519", public: pub },
        secret,
        256,
      ),
    );
  }
  if (bytes.every((b) => b === 0)) throw Error("Invalid X25519 shared secret");
  const base = await crypto.subtle.importKey("raw", raw(bytes), "HKDF", false, [
    "deriveKey",
  ]);
  bytes.fill(0);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: utf8("CNSProject secure-chat ECDH session key v1"),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export async function encrypt(key: CryptoKey, value: unknown) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const box = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      key,
      raw(utf8(canonical(value))),
    ),
  );
  return {
    nonce: b64(nonce),
    ciphertext: b64(box.slice(0, -16)),
    tag: b64(box.slice(-16)),
  };
}
export async function decrypt(
  key: CryptoKey,
  box: { nonce: string; ciphertext: string; tag: string },
) {
  const nonce = un64(box.nonce),
    tag = un64(box.tag);
  if (nonce.length !== 12 || tag.length !== 16)
    throw Error("Malformed GCM parameters");
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: raw(nonce), tagLength: 128 },
        key,
        raw(concat(un64(box.ciphertext), tag)),
      ),
    ),
  );
}
export const genesis = async (
  init: Uint8Array,
  resp: Uint8Array,
  sender: string,
) =>
  hex(
    await sha(
      concat(utf8("securechat/genesis/v1\0"), init, resp, utf8(sender)),
    ),
  );
export const record = (
  sender: string,
  recipient: string,
  seq: number,
  timestamp: number,
  message: string,
  prev_hash: string,
) => ({ sender, recipient, seq, timestamp, message, prev_hash });
