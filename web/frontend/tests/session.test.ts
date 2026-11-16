import { it, expect, vi, afterEach } from "vitest";
import { Session } from "../src/session";
import * as c from "../src/crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
class Socket {
  static OPEN = 1;
  readyState = 1;
  sent: any[] = [];
  send(s: string) {
    this.sent.push(JSON.parse(s));
  }
  close() {}
  addEventListener() {}
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
async function pair() {
  vi.stubGlobal("WebSocket", Socket);
  const aId = await c.identity(),
    bId = await c.identity();
  const a = new Session(
      "alice",
      "bob",
      aId.publicPem,
      await c.privateKey(aId.privateBytes),
      "test",
      () => {},
    ),
    b = new Session(
      "bob",
      "alice",
      bId.publicPem,
      await c.privateKey(bId.privateBytes),
      "test",
      () => {},
    );
  a.peerKey = await c.publicKey(bId.publicPem);
  a.peerPem = bId.publicPem;
  b.peerKey = await c.publicKey(aId.publicPem);
  b.peerPem = aId.publicPem;
  a.fingerprint = await c.fingerprint(bId.publicPem);
  b.fingerprint = await c.fingerprint(aId.publicPem);
  a.peerOnline = true;
  await a.maybeInitiate();
  const init = (a.socket as any).sent.at(-1);
  await b.receive(init);
  await a.receive((b.socket as any).sent.at(-1));
  return { a, b };
}
const lastChat = (s: Session) =>
  (s.socket as any).sent.filter((e: any) => e.type === "chat").at(-1);
it("serializes concurrent sends and rejects exact replay", async () => {
  const { a, b } = await pair();
  await Promise.all([a.sendMessage("one"), a.sendMessage("two")]);
  const frames = (a.socket as any).sent.filter((e: any) => e.type === "chat");
  for (const frame of frames) await b.receive(frame);
  expect(b.messages.map((m) => m.message)).toEqual(["one", "two"]);
  await b.receive(frames[1]);
  expect(b.messages).toHaveLength(2);
  expect(b.rejected.at(-1)?.reason).toBe("replay_duplicate");
});
it("accepts authenticated gaps with a warning and resyncs", async () => {
  const { a, b } = await pair();
  await a.sendMessage("dropped");
  await a.sendMessage("visible");
  await b.receive(lastChat(a));
  expect(b.messages[0].message).toBe("visible");
  expect(b.messages[0].receipt.chain_link).toBe("gap");
  expect(b.rejected.at(-1)?.reason).toBe("chain_gap");
  await a.sendMessage("next");
  await b.receive(lastChat(a));
  expect(b.messages.at(-1)?.receipt.chain_link).toBe("ok");
});
it("rejects a signed record with a broken predecessor", async () => {
  const { a, b } = await pair();
  a.outHead = "0".repeat(64);
  await a.sendMessage("broken");
  await b.receive(lastChat(a));
  expect(b.messages).toHaveLength(0);
  expect(b.rejected.at(-1)?.reason).toBe("chain_broken");
});
it("rejects stale signed messages", async () => {
  const { a, b } = await pair();
  await a.sendMessage("old");
  const now = Date.now();
  vi.spyOn(Date, "now").mockReturnValue(now + 31000);
  await b.receive(lastChat(a));
  expect(b.messages).toHaveLength(0);
  expect(b.rejected.at(-1)?.reason).toBe("stale_timestamp");
  vi.restoreAllMocks();
});
it("records a tamper rejection and explains the next gap", async () => {
  const { a, b } = await pair();
  await a.sendMessage("tampered");
  const frame = lastChat(a),
    ct = c.un64(frame.ciphertext);
  ct[0] ^= 1;
  await b.receive({ ...frame, ciphertext: c.b64(ct) });
  await a.sendMessage("authentic");
  await b.receive(lastChat(a));
  expect(b.messages[0].receipt.explained).toBe(1);
  expect(b.messages[0].receipt.chain_link).toBe("gap");
});
it("browser evidence is accepted by the unmodified Python verifier", async () => {
  const { a, b } = await pair();
  await a.sendMessage("hello नमस्ते 🙂");
  await b.receive(lastChat(a));
  await b.sendMessage("reply");
  await a.receive(lastChat(b));
  const file = join(
    mkdtempSync(join(tmpdir(), "cns-evidence-")),
    "evidence.json",
  );
  try {
    writeFileSync(file, JSON.stringify(await a.evidence()));
    const root = fileURLToPath(new URL("../../../", import.meta.url));
    const result = execFileSync(
      root + ".venv/bin/python",
      [root + "tools/verify_transcript.py", file],
      { encoding: "utf8" },
    );
    expect(result).toContain("RESULT: VALID");
  } finally {
    rmSync(file.substring(0, file.lastIndexOf("/")), {
      recursive: true,
      force: true,
    });
  }
});

it("v2 export captures exact envelope hashes and keeps v1 selectable", async () => {
  const { a, b } = await pair();
  await a.sendMessage("envelope evidence");
  const envelope = lastChat(a);
  await b.receive(envelope);
  const v2 = await b.evidence(2);
  expect(v2.format_version).toBe(2);
  expect(v2.records[0].envelope_sha256).toBe(await c.hash(envelope));
  expect((await a.evidence(2)).records[0].envelope_sha256).toBe(
    v2.records[0].envelope_sha256,
  );
  const v1 = await b.evidence(1);
  expect(v1.format).toBe("securechat-evidence/v1");
  expect(v1.records[0].envelope_sha256).toBeUndefined();
});

it("discards session keys on disconnect, reconnects transport and requires login again", async () => {
  vi.useFakeTimers();
  const { a } = await pair();
  a.isAuthenticated = true;
  a.apiToken = "old-bearer";
  const before = a.socket;
  (before as any).onclose();
  expect(a.key).toBeUndefined();
  expect(a.pending).toBeUndefined();
  expect(a.isAuthenticated).toBe(false);
  expect(a.apiToken).toBe("");
  expect(a.status).toContain("Reconnecting…");
  await vi.advanceTimersByTimeAsync(1000);
  expect(a.socket).not.toBe(before);
  (a.socket as any).onopen();
  expect(a.status).toContain("log in again");
  expect(a.key).toBeUndefined();
  expect(a.isAuthenticated).toBe(false);
  expect((a.socket as any).sent).toHaveLength(0);
  a.disconnect();
});
it("explicit disconnect cancels reconnect attempts", async () => {
  vi.useFakeTimers();
  const { a } = await pair();
  a.isAuthenticated = true;
  (a.socket as any).onclose();
  const before = a.socket;
  a.disconnect();
  await vi.advanceTimersByTimeAsync(60000);
  expect(a.socket).toBe(before);
  expect(a.key).toBeUndefined();
});
it("a peer leaving invalidates keys so their next login needs a fresh handshake", async () => {
  const { a } = await pair();
  a.isAuthenticated = true;
  await a.receive({ type: "user_left", username: "bob" });
  expect(a.key).toBeUndefined();
  expect(a.handshake).toBeUndefined();
  expect(a.initiated).toBe(false);
  expect(a.isAuthenticated).toBe(true);
});
it("a delayed old handshake cannot restore a discarded key", async () => {
  const { a } = await pair();
  let release!: (s: string) => void;
  const slow = new Promise<string>((resolve) => {
    release = resolve;
  });
  const spy = vi.spyOn(c, "genesis").mockReturnValue(slow);
  const oldKey = a.key!;
  const pending = a.finish(
    oldKey,
    "alice",
    "bob",
    new Uint8Array(32),
    new Uint8Array(32),
    "old",
    "old",
  );
  a.disconnect();
  release("old-head");
  await pending;
  expect(a.key).toBeUndefined();
  expect(a.handshake).toBeUndefined();
  spy.mockRestore();
});
