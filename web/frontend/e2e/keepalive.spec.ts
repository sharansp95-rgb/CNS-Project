import { test, expect } from "@playwright/test";
const runId = process.env.E2E_RUN_ID || Date.now().toString(36);
const password = "Browser-test-password-42!";
// The local test server drops sockets idle for 9 s; production uses 120 s.
const IDLE_WAIT = process.env.BASE_URL ? 135000 : 22000;

test("an idle logged-in session survives past the server idle limit", async ({ browser, browserName }) => {
  test.setTimeout(IDLE_WAIT + 90000);
  const prefix = `${browserName}_${runId}_ka_`;
  const make = async (me: string, peer: string) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto("/");
    await page.getByLabel("Username", { exact: true }).fill(prefix + me);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByLabel("Peer username", { exact: true }).fill(prefix + peer);
    await page.getByRole("button", { name: "Create an identity" }).click();
    return { page, ctx };
  };
  const [a, b] = await Promise.all([make("alice", "bob"), make("bob", "alice")]);
  await expect(a.page.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(b.page.getByLabel("Message", { exact: true })).toBeEnabled();
  // Completely idle: no typing, no messages. Only the automatic keepalive runs.
  await a.page.waitForTimeout(IDLE_WAIT);
  await expect(a.page.getByLabel("Message", { exact: true })).toBeEnabled();
  await a.page.getByLabel("Message", { exact: true }).fill("still here after idling");
  await a.page.getByRole("button", { name: "Send message" }).click();
  await expect(
    b.page.getByRole("button", { name: "Security receipt: still here after idling", exact: true }),
  ).toBeVisible();
  // Keepalive traffic stays out of the Wire Log.
  await a.page.getByRole("button", { name: "Wire Log" }).click();
  const wire = await a.page.locator(".wire").innerText();
  expect(wire).not.toContain('"ping"');
  expect(wire).not.toContain('"pong"');
  await a.ctx.close();
  await b.ctx.close();
});
