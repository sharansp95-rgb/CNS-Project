import {
  utf8,
  raw,
  b64,
  un64,
  privateKey,
  publicKey,
  sign,
  verify,
} from "./crypto";
export interface Backup {
  format: "securechat-key/v1";
  username: string;
  public_key_pem: string;
  iterations: number;
  salt: string;
  nonce: string;
  ciphertext: string;
}
async function wrapping(
  password: string,
  salt: Uint8Array,
  iterations: number,
) {
  const key = await crypto.subtle.importKey(
    "raw",
    raw(utf8(password)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: raw(salt), iterations },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
const aad = (b: Backup) => raw(utf8(b.username + "\0" + b.public_key_pem));
export async function wrap(
  username: string,
  password: string,
  publicPem: string,
  bytes: Uint8Array,
): Promise<Backup> {
  const salt = crypto.getRandomValues(new Uint8Array(16)),
    nonce = crypto.getRandomValues(new Uint8Array(12));
  const backup: Backup = {
    format: "securechat-key/v1",
    username,
    public_key_pem: publicPem,
    iterations: 600000,
    salt: b64(salt),
    nonce: b64(nonce),
    ciphertext: "",
  };
  const key = await wrapping(password, salt, backup.iterations);
  backup.ciphertext = b64(
    new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad(backup) },
        key,
        raw(bytes),
      ),
    ),
  );
  return backup;
}
export async function unwrap(b: Backup, username: string, password: string) {
  if (
    b.format !== "securechat-key/v1" ||
    b.username !== username ||
    !Number.isInteger(b.iterations) ||
    b.iterations < 200000 ||
    b.iterations > 2000000 ||
    un64(b.salt).length !== 16 ||
    un64(b.nonce).length !== 12
  )
    throw Error("Invalid key backup");
  const key = await wrapping(password, un64(b.salt), b.iterations);
  const bytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw(un64(b.nonce)), additionalData: aad(b) },
      key,
      raw(un64(b.ciphertext)),
    ),
  );
  try {
    const private_key = await privateKey(bytes);
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    if (
      !(await verify(
        await publicKey(b.public_key_pem),
        challenge,
        await sign(private_key, challenge),
      ))
    )
      throw Error("Key backup public/private mismatch");
    return private_key;
  } finally {
    bytes.fill(0);
  }
}
async function database() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("securechat-keys", 1);
    request.onupgradeneeded = () =>
      request.result.createObjectStore("identities", { keyPath: "username" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
export async function saveBackup(backup: Backup) {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("identities", "readwrite");
      tx.objectStore("identities").put(backup);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
export async function loadBackup(username: string): Promise<Backup> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const req = db
        .transaction("identities")
        .objectStore("identities")
        .get(username);
      req.onsuccess = () =>
        req.result
          ? resolve(req.result)
          : reject(
              Error(
                "No local identity in this browser. Log in from the browser where you created it.",
              ),
            );
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}
