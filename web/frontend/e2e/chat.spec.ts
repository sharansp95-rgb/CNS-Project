import { test, expect, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const password = "Browser-test-password-42!";
async function fill(page: Page, user: string, peer: string) {
  await page.goto("/");
  await page.getByLabel("Username", { exact: true }).fill(user);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByLabel("Peer username", { exact: true }).fill(peer);
}
test("two isolated browsers exchange, inspect, export and restore a wrapped identity", async ({
  browser,
}, testInfo) => {
  const aContext = await browser.newContext(),
    bContext = await browser.newContext();
  const a = await aContext.newPage(),
    b = await bContext.newPage();
  const errors: string[] = [];
  for (const page of [a, b]) {
    page.on("pageerror", (error) => errors.push(error.message));
  }
  await fill(a, "browser_alice", "browser_bob");
  await a.getByRole("button", { name: "Create an identity" }).click();
  await expect(
    a.getByRole("button", { name: "Export Evidence" }),
  ).toBeVisible();
  await fill(b, "browser_bob", "browser_alice");
  await b.getByRole("button", { name: "Create an identity" }).click();
  await expect(a.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(b.getByLabel("Message", { exact: true })).toBeEnabled();
  const first = "Browser hello नमस्ते 🙂",
    reply = "Browser reply, verified.";
  await a.getByLabel("Message", { exact: true }).fill(first);
  await a.getByRole("button", { name: "Send message" }).click();
  await expect(
    b.getByRole("button", { name: "Security receipt: " + first, exact: true }),
  ).toBeVisible();
  await b.getByLabel("Message", { exact: true }).fill(reply);
  await b.getByRole("button", { name: "Send message" }).click();
  await expect(
    a.getByRole("button", { name: "Security receipt: " + reply, exact: true }),
  ).toBeVisible();
  await b
    .getByRole("button", { name: "Security receipt: " + first, exact: true })
    .click();
  await expect(
    b.getByRole("dialog", { name: "Security receipt", exact: true }),
  ).toBeVisible();
  await expect(
    b.getByText("Signed, encrypted and linked", { exact: false }),
  ).toBeVisible();
  await b.getByRole("button", { name: "Close receipt" }).click();
  await a.getByRole("button", { name: "Wire Log" }).click();
  await expect(a.locator(".wire")).toContainText("ciphertext");
  expect(await a.locator(".wire").innerText()).not.toContain(first);
  expect(await a.locator(".wire").innerText()).not.toContain(password);
  const evidenceDownload = a.waitForEvent("download");
  await a.getByRole("button", { name: "Export Evidence" }).click();
  const evidence = await evidenceDownload;
  const file = testInfo.outputPath("evidence.json");
  await evidence.saveAs(file);
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  expect(
    execFileSync(
      root + ".venv/bin/python",
      [root + "tools/verify_transcript.py", file],
      { encoding: "utf8" },
    ),
  ).toContain("RESULT: VALID");
  const backupDownload = a.waitForEvent("download");
  await a.getByRole("button", { name: "Download key backup" }).click();
  const backup = await backupDownload;
  const backupFile = testInfo.outputPath("backup.json");
  await backup.saveAs(backupFile);
  await a.getByRole("button", { name: "Disconnect", exact: false }).click();
  await aContext.close();
  await bContext.close();
  const restored = await browser.newContext(),
    page = await restored.newPage();
  await fill(page, "browser_alice", "browser_bob");
  await page
    .getByLabel("Import key backup", { exact: true })
    .setInputFiles(backupFile);
  await expect(page.getByRole("status")).toContainText("Identity imported");
  await page.getByRole("button", { name: "Log in", exact: false }).click();
  await expect(
    page.getByRole("button", { name: "Export Evidence" }),
  ).toBeVisible();
  expect(errors).toEqual([]);
  await restored.close();
});
test("mobile login and chat remain within the viewport", async ({
  browser,
}) => {
  const context = await browser.newContext({
      viewport: { width: 390, height: 844 },
    }),
    page = await context.newPage();
  await fill(page, "mobile_user", "offline_peer");
  await expect(
    page.getByRole("button", { name: "Create an identity" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Create an identity" }).click();
  await expect(page.getByLabel("Message", { exact: true })).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/mobile-chat.png",
    fullPage: true,
  });
  await context.close();
});

test("browser interoperates with a real Python SecureChatClient over TCP/TLS", async ({
  browser,
}, testInfo) => {
  const context = await browser.newContext(),
    page = await context.newPage();
  await fill(page, "z_browser", "a_python");
  await page.getByRole("button", { name: "Create an identity" }).click();
  await expect(page.getByLabel("Message", { exact: true })).toBeEnabled();
  await page
    .getByLabel("Message", { exact: true })
    .fill("BROWSER_TCP_INTEROP_🙂");
  await page.getByRole("button", { name: "Send message" }).click();
  await expect(
    page.getByRole("button", {
      name: "Security receipt: Python reply: BROWSER_TCP_INTEROP_🙂",
      exact: true,
    }),
  ).toBeVisible();
  const waiting = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Evidence" }).click();
  const download = await waiting;
  const file = testInfo.outputPath("interop-evidence.json");
  await download.saveAs(file);
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  expect(
    execFileSync(
      root + ".venv/bin/python",
      [root + "tools/verify_transcript.py", file],
      { encoding: "utf8" },
    ),
  ).toContain("RESULT: VALID");
  await page.getByRole("button", { name: "Wire Log", exact: false }).click();
  await page.screenshot({
    path: "test-results/desktop-chat.png",
    fullPage: true,
  });
  await context.close();
});
