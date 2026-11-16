import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as c from "../src/crypto";
import { wrap, unwrap } from "../src/keystore";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const python = root + ".venv/bin/python";
const bridge = fileURLToPath(new URL("./vector_bridge.py", import.meta.url));
const vector = JSON.parse(
  execFileSync(python, [bridge, "generate"], { encoding: "utf8" }),
);

describe("Python → browser", () => {
  it("canonicalizes Unicode and control bytes identically", () => {
    expect(c.canonical(vector.record)).toBe(vector.canonical);
    expect(c.canonical({ "\u{10000}": 1, "\ue000": 2 })).toBe(
      '{"\\ue000":2,"\\ud800\\udc00":1}',
    );
  });
  it("verifies the Python RSA signed handshake with MAX_LENGTH salt", async () => {
    expect(
      await c.verify(
        await c.publicKey(vector.public_pem),
        c.un64(vector.handshake_pub),
        c.un64(vector.handshake_sig),
      ),
    ).toBe(true);
  });
  it("matches the PEM fingerprint and record hash", async () => {
    expect(await c.fingerprint(vector.public_pem)).toBe(vector.fingerprint);
    expect(await c.hash(vector.record)).toBe(vector.record_hash);
  });
  it("derives HKDF from X25519 and decrypts the signed Python message", async () => {
    const own = {
      pub: c.un64(vector.peer_pub),
      secret: c.un64(vector.peer_private),
    };
    const key = await c.shared(own, c.un64(vector.handshake_pub));
    const payload = await c.decrypt(key, vector.box);
    expect(payload.message).toBe(vector.record.message);
    expect(
      await c.verify(
        await c.publicKey(vector.public_pem),
        c.utf8(vector.canonical),
        c.un64(payload.signature),
      ),
    ).toBe(true);
    expect(own.secret).toBeUndefined();
  });
  it("rejects ciphertext tampering", async () => {
    const key = await c.shared(
      { pub: c.un64(vector.peer_pub), secret: c.un64(vector.peer_private) },
      c.un64(vector.handshake_pub),
    );
    const ct = c.un64(vector.box.ciphertext);
    ct[0] ^= 1;
    await expect(
      c.decrypt(key, { ...vector.box, ciphertext: c.b64(ct) }),
    ).rejects.toThrow();
  });
});
it("browser → Python verifies handshake, chain and encrypted message", async () => {
  const id = await c.identity(),
    priv = await c.privateKey(id.privateBytes);
  const a = await c.ephemeral(),
    b = await c.ephemeral(true),
    peerPrivate = c.b64((b.secret as Uint8Array).slice());
  const handshake = c.b64(a.pub);
  const key = await c.shared(a, b.pub);
  const rec = c.record(
    "js_alice",
    "py_bob",
    1,
    1800000000,
    "From JS → Python 🙂",
    await c.genesis(a.pub, b.pub, "js_alice"),
  );
  const signature = c.b64(await c.sign(priv, c.utf8(c.canonical(rec))));
  const output = {
    public_pem: id.publicPem,
    handshake_pub: handshake,
    handshake_sig: c.b64(await c.sign(priv, a.pub)),
    peer_private: peerPrivate,
    record: rec,
    record_hash: await c.hash(rec),
    signature,
    box: await c.encrypt(key, { ...rec, signature }),
  };
  expect(
    execFileSync(python, [bridge, "verify"], {
      input: JSON.stringify(output),
      encoding: "utf8",
    }).trim(),
  ).toBe("VERIFIED");
});
it("WebCrypto and noble X25519 derive matching session keys", async () => {
  const native = await c.ephemeral(),
    fallback = await c.ephemeral(true);
  const first = await c.shared(native, fallback.pub),
    second = await c.shared(fallback, native.pub);
  expect(
    await c.decrypt(second, await c.encrypt(first, { message: "same secret" })),
  ).toEqual({ message: "same secret" });
});
it("rejects all-zero fallback X25519 secret", async () => {
  const own = await c.ephemeral(true);
  await expect(c.shared(own, new Uint8Array(32))).rejects.toThrow();
});
it("keeps wrapped backup password-protected and binds its identity", async () => {
  const id = await c.identity();
  const backup = await wrap(
    "alice",
    "secret-password",
    id.publicPem,
    id.privateBytes,
  );
  const priv = await unwrap(backup, "alice", "secret-password");
  expect(
    await c.verify(
      await c.publicKey(id.publicPem),
      c.utf8("backup"),
      await c.sign(priv, c.utf8("backup")),
    ),
  ).toBe(true);
  expect(JSON.stringify(backup)).not.toContain("secret-password");
  await expect(unwrap(backup, "alice", "wrong")).rejects.toThrow();
  await expect(unwrap(backup, "bob", "secret-password")).rejects.toThrow();
});
