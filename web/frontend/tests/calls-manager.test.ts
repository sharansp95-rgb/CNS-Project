import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CallManager, type CallHost } from "../src/calls/manager";
import { parseSignal, type Signal } from "../src/calls/signal";

const fingerprint = Array.from({ length: 32 }, () => "AB").join(":");
const sdp = `v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=fingerprint:sha-256 ${fingerprint}\r\na=setup:actpass\r\na=rtpmap:111 opus/48000/2\r\n`;
const managers: CallManager[] = [];
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function microphone() {
  const stop = vi.fn();
  return {
    stream: {
      getTracks: () => [{ stop }],
      getAudioTracks: () => [],
    } as unknown as MediaStream,
    stop,
  };
}
function manager(username: string, peer: string) {
  const signals: Signal[] = [];
  const host: CallHost = {
    username,
    peer,
    apiToken: "test-only",
    key: {} as CryptoKey,
    peerOnline: true,
    changed: vi.fn(),
    note: vi.fn(),
    securityAlert: vi.fn(),
    send: vi.fn(async (message: string) => {
      const signal = parseSignal(message);
      expect(signal).not.toBeNull(); // Glare uses the existing, verifiable signal format.
      signals.push(signal!);
    }),
  };
  const calls = new CallManager(host);
  managers.push(calls);
  return { calls, host, signals };
}
const invite = (call: string): Signal => ({ v: 1, type: "invite", call, sdp });
beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  managers.splice(0).forEach((calls) => calls.teardown("test ended"));
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("simultaneous calls", () => {
  it("converges on the smaller username's call and discards the losing microphone request", async () => {
    const aMic = deferred<MediaStream>(),
      bMic = deferred<MediaStream>();
    vi.stubGlobal("navigator", {
      mediaDevices: {
        getUserMedia: vi
          .fn()
          .mockReturnValueOnce(aMic.promise)
          .mockReturnValueOnce(bMic.promise),
      },
    });
    const a = manager("alice", "bob"),
      b = manager("bob", "alice");
    const aStart = a.calls.start(),
      bStart = b.calls.start();
    const aId = a.calls.info!.id,
      bId = b.calls.info!.id;
    await a.calls.onSignal(invite(bId));
    await b.calls.onSignal(invite(aId));
    expect(a.calls.info).toMatchObject({
      id: aId,
      role: "caller",
      state: "calling",
    });
    expect(b.calls.info).toMatchObject({
      id: aId,
      role: "callee",
      state: "ringing",
      remoteFp: fingerprint,
    });
    expect(a.signals).toContainEqual({ v: 1, call: bId, type: "busy" });
    expect(b.signals).toContainEqual({
      v: 1,
      call: bId,
      type: "cancel",
      reason: "simultaneous_call",
    });
    expect(
      b.signals.some(
        (s) =>
          s.type === "record" && s.call === bId && s.outcome === "canceled",
      ),
    ).toBe(true);
    const late = microphone();
    bMic.resolve(late.stream);
    await bStart;
    expect(late.stop).toHaveBeenCalledOnce();
    expect(b.calls.info!.id).toBe(aId);
    expect(b.signals.some((s) => s.type === "invite")).toBe(false);
    // A busy response for the abandoned call cannot end the winning incoming call.
    await b.calls.onSignal({ v: 1, call: bId, type: "busy" });
    expect(b.calls.info!.id).toBe(aId);
    a.calls.teardown("done");
    aMic.resolve(microphone().stream);
    await aStart;
  });

  it("keeps an active call busy even when the other username sorts first", async () => {
    const pending = deferred<MediaStream>();
    vi.stubGlobal("navigator", {
      mediaDevices: { getUserMedia: () => pending.promise },
    });
    const { calls, signals } = manager("zara", "alice");
    const starting = calls.start();
    const id = calls.info!.id;
    calls.info!.state = "active";
    await calls.onSignal(invite("b".repeat(32)));
    expect(calls.info!.id).toBe(id);
    expect(signals.at(-1)).toMatchObject({
      type: "busy",
      call: "b".repeat(32),
    });
    calls.teardown("done");
    pending.resolve(microphone().stream);
    await starting;
  });

  it("does not let a denied old permission request clear the winning call", async () => {
    const pending = deferred<MediaStream>();
    vi.stubGlobal("navigator", {
      mediaDevices: { getUserMedia: () => pending.promise },
    });
    const { calls } = manager("zara", "alice");
    const starting = calls.start();
    const id = "a".repeat(32);
    await calls.onSignal(invite(id));
    pending.reject(new DOMException("denied", "NotAllowedError"));
    await expect(starting).resolves.toBeUndefined();
    expect(calls.info).toMatchObject({ id, role: "callee", state: "ringing" });
  });

  it("stops a late microphone stream after cancellation without reviving an invite", async () => {
    const pending = deferred<MediaStream>();
    vi.stubGlobal("navigator", {
      mediaDevices: { getUserMedia: () => pending.promise },
    });
    const { calls, signals } = manager("alice", "bob");
    const starting = calls.start();
    calls.hangup();
    const late = microphone();
    pending.resolve(late.stream);
    await starting;
    expect(late.stop).toHaveBeenCalledOnce();
    expect(calls.info).toBeUndefined();
    expect(signals.some((s) => s.type === "invite")).toBe(false);
  });
});
