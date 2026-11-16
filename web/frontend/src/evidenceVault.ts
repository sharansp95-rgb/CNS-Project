import * as c from "./crypto";
export const VAULT_FORMAT = "securechat-vault/v1",
  ITERATIONS = 600000;
export interface VaultPackage {
  format: string;
  iterations: number;
  salt: string;
  nonce: string;
  file_sha256: string;
  ciphertext: string;
}
async function key(password: string, salt: Uint8Array) {
  const base = await crypto.subtle.importKey(
    "raw",
    c.raw(c.utf8(password)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: c.raw(c.concat(c.utf8("CNSProject evidence vault v1\0"), salt)),
      iterations: ITERATIONS,
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
const aad = (hash: string) => c.raw(c.utf8(VAULT_FORMAT + "\0" + hash));
export async function encryptEvidence(
  bytes: Uint8Array,
  password: string,
): Promise<VaultPackage> {
  const salt = crypto.getRandomValues(new Uint8Array(16)),
    nonce = crypto.getRandomValues(new Uint8Array(12)),
    digest = c.hex(await c.sha(bytes));
  return {
    format: VAULT_FORMAT,
    iterations: ITERATIONS,
    salt: c.b64(salt),
    nonce: c.b64(nonce),
    file_sha256: digest,
    ciphertext: c.b64(
      new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad(digest) },
          await key(password, salt),
          c.raw(bytes),
        ),
      ),
    ),
  };
}
export async function decryptEvidence(p: VaultPackage, password: string) {
  if (
    p.format !== VAULT_FORMAT ||
    p.iterations !== ITERATIONS ||
    c.un64(p.salt).length !== 16 ||
    c.un64(p.nonce).length !== 12 ||
    !/^[0-9a-f]{64}$/.test(p.file_sha256)
  )
    throw Error("Invalid encrypted vault package");
  const data = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: c.raw(c.un64(p.nonce)),
        additionalData: aad(p.file_sha256),
      },
      await key(password, c.un64(p.salt)),
      c.raw(c.un64(p.ciphertext)),
    ),
  );
  if (c.hex(await c.sha(data)) !== p.file_sha256)
    throw Error("File hash mismatch");
  return data;
}
export async function vaultRequest(
  token: string,
  path = "",
  options: RequestInit = {},
) {
  const response = await fetch("/api/evidence" + path, {
    ...options,
    headers: {
      Authorization: "Bearer " + token,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const body = await response.json();
  if (!response.ok) throw Error(body.detail || "Vault request failed");
  return body;
}
export const evidenceBytes = (data: unknown) =>
  c.utf8(JSON.stringify(data, null, 2) + "\n");
