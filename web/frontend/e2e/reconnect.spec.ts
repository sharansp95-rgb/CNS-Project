import { test, expect } from "@playwright/test";
const runId = process.env.E2E_RUN_ID || Date.now().toString(36);
const password = "Browser-test-password-42!";

test("a dropped connection logs back in by itself and the chat keeps working", async ({
  browser,
  browserName,
}) => {
  test.skip(!!process.env.BASE_URL, "Needs control of the browser network");
  test.setTimeout(120000);
  const prefix = `${browserName}_${runId}_rc_`;
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
  const [a, b] = await Promise.all([
    make("alice", "bob"),
    make("bob", "alice"),
  ]);
  const box = (p: typeof a) => p.page.getByLabel("Message", { exact: true });
  await expect(box(a)).toBeEnabled();
  await expect(box(b)).toBeEnabled();
  // Cut Alice's network long enough for the server to see a dead socket.
  await a.ctx.setOffline(true);
  await expect(a.page.locator(".reconnect-banner")).toBeVisible({
    timeout: 30000,
  });
  // The chat stays on screen; no login form appears.
  await expect(a.page.getByLabel("Password", { exact: true })).toHaveCount(0);
  await a.page.waitForTimeout(12000);
  await a.ctx.setOffline(false);
  // Logs back in and re-runs the signed handshake without any typing.
  await expect(box(a)).toBeEnabled({ timeout: 60000 });
  await expect(a.page.locator(".reconnect-banner")).toHaveCount(0);
  await box(a).fill("back after the drop");
  await a.page.getByRole("button", { name: "Send message" }).click();
  await expect(
    b.page.getByRole("button", {
      name: "Security receipt: back after the drop",
      exact: true,
    }),
  ).toBeVisible();
  await a.ctx.close();
  await b.ctx.close();
});
