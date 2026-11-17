import { test, expect, type Page, type Browser } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const runId = process.env.E2E_RUN_ID || Date.now().toString(36);
const password = "Browser-test-password-42!";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const panel = (p: Page) => p.getByRole("dialog", { name: "Voice call" });
test.describe.configure({ mode: "serial" });
let pa: Page, pb: Page, closeAll: () => Promise<unknown>;
test.beforeAll(async ({ browser, browserName }) => {
  const prefix = `${browserName}_${runId}_call_`;
  const make = async (me: string, peer: string, viewport?: { width: number; height: number }) => {
    const ctx = await browser.newContext({
      viewport,
      permissions: browserName === "chromium" ? ["microphone"] : [],
    });
    const page = await ctx.newPage();
    await page.goto("/");
    await page.getByLabel("Username", { exact: true }).fill(prefix + me);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByLabel("Peer username", { exact: true }).fill(prefix + peer);
    await page.getByRole("button", { name: "Create an identity" }).click();
    return { page, ctx };
  };
  const [a, b] = await Promise.all([make("alice", "bob"), make("bob", "alice", { width: 390, height: 844 })]);
  [pa, pb] = [a.page, b.page];
  closeAll = () => Promise.all([a.ctx.close(), b.ctx.close()]);
  await expect(pa.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(pb.getByLabel("Message", { exact: true })).toBeEnabled();
});
test.afterAll(async () => closeAll?.());
test.beforeEach(async ({ browserName }) => {
  if (test.info().title.includes("microphone error")) return; // runs in every engine
  test.skip(browserName === "webkit" && !(await fakeMediaWorks(pa)), "WebKit has no fake microphone in this environment");
});
async function fakeMediaWorks(page: Page) {
  return page.evaluate(async () => {
    try {
      (await navigator.mediaDevices.getUserMedia({ audio: true })).getTracks().forEach((t) => t.stop());
      return true;
    } catch {
      return false;
    }
  });
}
const bytes = async (p: Page) => Number(await panel(p).getAttribute("data-inbound-bytes"));

test("call connects, shows matching words, audio flows, mute works, hang-up is recorded in evidence", async ({}, testInfo) => {
  const errors: string[] = [];
  for (const p of [pa, pb]) p.on("pageerror", (e) => errors.push(e.message));
  await expect(pa.getByRole("button", { name: "Start voice call" })).toBeEnabled();
  await pa.getByRole("button", { name: "Start voice call" }).click();
  await expect(panel(pa)).toContainText("Calling");
  await expect(panel(pb)).toContainText("Incoming call from");
  // One call at a time: the call button is disabled while a call exists.
  await expect(pb.getByRole("button", { name: "Start voice call" })).toBeDisabled();
  await panel(pb).getByRole("button", { name: "Accept" }).click();
  await expect(panel(pa)).toHaveAttribute("data-state", "active", { timeout: 30000 });
  await expect(panel(pb)).toHaveAttribute("data-state", "active", { timeout: 30000 });
  // Connection type and the real DTLS certificate check against the signed SDP.
  await expect(panel(pa).getByTestId("call-conn")).toContainText("direct");
  await expect(panel(pa).getByTestId("call-fp")).toContainText("matches the fingerprint your contact signed", { timeout: 15000 });
  await expect(panel(pb).getByTestId("call-fp")).toContainText("matches the fingerprint your contact signed", { timeout: 15000 });
  // The same four words on both screens.
  const words = await panel(pa).getByTestId("call-words").innerText();
  expect(words.split(" · ")).toHaveLength(4);
  expect(await panel(pb).getByTestId("call-words").innerText()).toBe(words);
  // Real audio packets flow in both directions.
  await expect.poll(() => bytes(pa), { timeout: 20000 }).toBeGreaterThan(1000);
  await expect.poll(() => bytes(pb), { timeout: 20000 }).toBeGreaterThan(1000);
  // Mute really disables the microphone track, and media keeps flowing.
  await panel(pa).getByRole("button", { name: "Mute" }).click();
  await expect(panel(pa)).toHaveAttribute("data-track-enabled", "false");
  await panel(pa).getByRole("button", { name: "Unmute" }).click();
  await expect(panel(pa)).toHaveAttribute("data-track-enabled", "true");
  // Wire log shows ciphertext for signaling, plus the fingerprints, never the SDP.
  await pa.getByRole("button", { name: "Wire Log" }).click();
  const wire = await pa.locator(".wire").innerText();
  expect(wire).toContain("call_fingerprints");
  expect(wire).toMatch(/[0-9A-F]{2}(:[0-9A-F]{2}){31}/);
  expect(wire).not.toContain("m=audio");
  expect(wire).not.toContain("securechat-call");
  await pa.getByRole("button", { name: "Wire Log" }).click();
  // Both confirm the words: "Call verified".
  for (const p of [pa, pb]) await panel(p).getByRole("button", { name: "The words match" }).click();
  await expect(panel(pa).getByTestId("call-verified")).toBeVisible();
  await expect(panel(pb).getByTestId("call-verified")).toBeVisible();
  await expect(panel(pb).getByRole("button", { name: "Hang up" })).toBeInViewport();
  expect(await pb.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await pa.waitForTimeout(1500);
  await panel(pa).getByRole("button", { name: "Hang up" }).click();
  await expect(panel(pa)).toHaveCount(0);
  await expect(panel(pb)).toHaveCount(0);
  for (const p of [pa, pb]) await expect(p.getByTestId("call-log").last()).toContainText(/Call · 0:0\d · direct · verified/);
  // Evidence includes both signed call records (metadata only) and verifies offline.
  // Bob's record may still be in flight over a real network, so export until it arrives.
  let out = "";
  for (let attempt = 0; attempt < 8 && !/\(callee\) call [0-9a-f]{8}: completed/.test(out); attempt++) {
    if (attempt) await pa.waitForTimeout(1000);
    const download = pa.waitForEvent("download");
    await pa.getByRole("button", { name: "Export Evidence" }).click();
    const file = testInfo.outputPath(`calls-evidence-${attempt}.json`);
    await (await download).saveAs(file);
    out = execFileSync(root + ".venv/bin/python", [root + "tools/verify_transcript.py", file], { encoding: "utf8" });
  }
  expect(out).toContain("RESULT: VALID");
  expect(out).toContain("Voice calls");
  expect(out).toMatch(/\(caller\) call [0-9a-f]{8}: completed, \d+s, connection direct, fingerprint check yes, words confirmed yes/);
  expect(out).toMatch(/\(callee\) call [0-9a-f]{8}: completed/);
  expect(errors).toEqual([]);
});

test("declined call is recorded for the caller", async () => {
  await pa.getByRole("button", { name: "Start voice call" }).click();
  await expect(panel(pb)).toContainText("Incoming call from");
  await panel(pb).getByRole("button", { name: "Decline" }).click();
  await expect(panel(pa)).toHaveCount(0);
  await expect(pa.getByTestId("call-log").last()).toContainText("Call declined");
  await expect(pb.getByTestId("call-log").last()).toContainText("Call declined");
});

test("caller can cancel while ringing", async () => {
  await pa.getByRole("button", { name: "Start voice call" }).click();
  await expect(panel(pb)).toContainText("Incoming call from");
  await panel(pa).getByRole("button", { name: "Cancel" }).click();
  await expect(panel(pb)).toHaveCount(0);
  await expect(pb.getByTestId("call-log").last()).toContainText("Missed call");
  await expect(pa.getByTestId("call-log").last()).toContainText("Call canceled");
});

test("microphone error is explained and no call starts (every engine)", async () => {
  for (const [name, message] of [
    ["NotAllowedError", "Microphone permission was denied"],
    ["NotFoundError", "No microphone was found"],
    ["NotReadableError", "in use by another app"],
  ] as const) {
    await pa.evaluate((n) => {
      (window as any).__gum = (window as any).__gum || navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = () => Promise.reject(new DOMException("blocked", n));
    }, name);
    await pa.getByRole("button", { name: "Start voice call" }).click();
    await expect(pa.getByRole("alert").filter({ hasText: message })).toBeVisible();
    await expect(panel(pa)).toHaveCount(0);
    await expect(panel(pb)).toHaveCount(0);
  }
  await pa.evaluate(() => {
    navigator.mediaDevices.getUserMedia = (window as any).__gum;
  });
});

test("an unanswered incoming call times out after 30 seconds", async () => {
  await pb.clock.install();
  await pa.getByRole("button", { name: "Start voice call" }).click();
  await expect(panel(pb)).toContainText("Incoming call from");
  await pb.clock.fastForward(31000);
  await expect(panel(pb)).toHaveCount(0);
  await expect(pb.getByTestId("call-log").last()).toContainText("Missed call");
});


// Live only: with TURN configured, a relay-only call must connect and report "via relay".
test("relay-only call goes through TURN (live, when TURN is available)", async ({ browser, browserName }) => {
  test.setTimeout(300000);
  test.skip(!process.env.BASE_URL || !process.env.LIVE_TURN || browserName !== "chromium", "needs live TURN (set LIVE_TURN=1) and a fake microphone");
  const prefix = `${browserName}_${runId}_relay_`;
  const make = async (me: string, peer: string) => {
    const ctx = await browser.newContext({ permissions: ["microphone"] });
    const page = await ctx.newPage();
    await page.goto("/?relay=1");
    await page.getByLabel("Username", { exact: true }).fill(prefix + me);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByLabel("Peer username", { exact: true }).fill(prefix + peer);
    await page.getByRole("button", { name: "Create an identity" }).click();
    return { page, ctx };
  };
  const [a, b] = await Promise.all([make("alice", "bob"), make("bob", "alice")]);
  await expect(a.page.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(b.page.getByLabel("Message", { exact: true })).toBeEnabled();
  // Metered credentials need up to 2 minutes to propagate; the client fetched them at login.
  // The gateway closes sockets idle for 120 s, so keep both sessions busy with chat while waiting.
  for (let i = 0; i < 2; i++) {
    await a.page.waitForTimeout(40000);
    for (const p of [a.page, b.page]) {
      await p.getByLabel("Message", { exact: true }).fill("keepalive " + i);
      await p.getByRole("button", { name: "Send message" }).click();
    }
  }
  await a.page.getByRole("button", { name: "Start voice call" }).click();
  await b.page.getByRole("dialog", { name: "Voice call" }).getByRole("button", { name: "Accept" }).click();
  for (const p of [a.page, b.page]) {
    await expect(panel(p)).toHaveAttribute("data-state", "active", { timeout: 40000 });
    await expect(panel(p).getByTestId("call-conn")).toContainText("via relay (TURN)", { timeout: 20000 });
    await expect(panel(p).getByTestId("call-fp")).toContainText("matches", { timeout: 20000 });
    await expect.poll(() => bytes(p), { timeout: 20000 }).toBeGreaterThan(1000);
  }
  await a.ctx.close();
  await b.ctx.close();
});
