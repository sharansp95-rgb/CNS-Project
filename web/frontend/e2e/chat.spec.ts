import { test, expect, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const runId = process.env.E2E_RUN_ID || Date.now().toString(36);
const password = "Browser-test-password-42!";
async function fill(page: Page, user: string, peer: string) {
  if (user !== "z_browser") {
    const prefix = `${page.context().browser()!.browserType().name()}_${runId}_`;
    user = prefix + user;
    peer = prefix + peer;
  }
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
  // A browser close is local; wait for the relay to release the identity before
  // logging it in again over a different connection through the live proxy.
  await expect(b.locator(".session-divider")).toContainText(
    "Peer disconnected",
  );
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
  test.skip(
    !!process.env.BASE_URL,
    "Render has no raw TCP port; local-only interoperability test",
  );
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

test("chat evidence is encrypted, saved, listed, downloaded and verified locally", async ({
  browser,
}, testInfo) => {
  const aContext = await browser.newContext(),
    bContext = await browser.newContext(),
    a = await aContext.newPage(),
    b = await bContext.newPage();
  await fill(a, "vault_alice", "vault_bob");
  await a.getByRole("button", { name: "Create an identity" }).click();
  await fill(b, "vault_bob", "vault_alice");
  await b.getByRole("button", { name: "Create an identity" }).click();
  await expect(a.getByLabel("Message", { exact: true })).toBeEnabled();
  const message = "VAULT_BROWSER_SECRET नमस्ते 🙂";
  await a.getByLabel("Message", { exact: true }).fill(message);
  await a.getByRole("button", { name: "Send message" }).click();
  await expect(
    b.getByRole("button", {
      name: "Security receipt: " + message,
      exact: true,
    }),
  ).toBeVisible();
  let upload = "";
  a.on("request", (req) => {
    if (req.url().endsWith("/api/evidence") && req.method() === "POST")
      upload = req.postData() || "";
  });
  await a.getByRole("button", { name: "Save evidence", exact: true }).click();
  await a.getByLabel("Vault password", { exact: true }).fill(password);
  await a.getByLabel("Evidence title", { exact: true }).fill("Proof session");
  await a
    .getByRole("button", { name: "Encrypt and save", exact: true })
    .click();
  await expect(
    a.getByRole("heading", { name: "Proof session", exact: true }),
  ).toBeVisible();
  await expect(
    a.getByRole("heading", { name: "VALID", exact: true }),
  ).toBeVisible();
  expect(upload).not.toContain(message);
  expect(upload).not.toContain(password);
  await a.getByRole("button", { name: "Evidence", exact: true }).click();
  await a.getByLabel("Vault password", { exact: true }).fill(password);
  const downloading = a.waitForEvent("download");
  await a.getByRole("button", { name: "Download JSON", exact: true }).click();
  const file = testInfo.outputPath("vault-evidence.json");
  await (await downloading).saveAs(file);
  const receiptDownload = a.waitForEvent("download");
  await a.getByRole("button", { name: "Download timestamp receipt" }).click();
  const receiptFile = testInfo.outputPath("receipt.json");
  await (await receiptDownload).saveAs(receiptFile);
  const key = await a.request.get("/api/timestamp-key").then((r) => r.json());
  const pdfDownload = a.waitForEvent("download");
  await a.getByRole("button", { name: "Download companion PDF" }).click();
  await (await pdfDownload).saveAs(testInfo.outputPath("companion.pdf"));
  const local = await browser.newContext(),
    page = await local.newPage();
  let posted = false;
  page.on("request", (r) => {
    if (["POST", "PUT"].includes(r.method())) posted = true;
  });
  await page.goto("/verify");
  await page
    .getByLabel("Evidence JSON file", { exact: true })
    .setInputFiles(file);
  await page
    .getByLabel("Receipt JSON file", { exact: true })
    .setInputFiles(receiptFile);
  await page
    .getByLabel("Trusted TSA public key (PEM)", { exact: true })
    .fill(key.public_key_pem);
  await page.getByRole("button", { name: "Verify locally" }).click();
  await expect(
    page.getByRole("heading", { name: "VALID", exact: true }),
  ).toBeVisible();
  expect(posted).toBe(false);
  await a.getByRole("button", { name: "Delete evidence", exact: true }).click();
  await expect(a.getByText("No saved evidence yet.")).toBeVisible();
  await aContext.close();
  await bContext.close();
  await local.close();
});

test("public verification names the edited message without uploading the file", async ({
  page,
}) => {
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  let uploads = 0;
  page.on("request", (r) => {
    if (r.method() === "POST") uploads++;
  });
  await page.goto("/verify");
  await page
    .getByLabel("Evidence JSON file", { exact: true })
    .setInputFiles(root + "tests/fixtures/evidence_corpus/edited_message.json");
  await page.getByRole("button", { name: "Verify locally" }).click();
  await expect(
    page.getByRole("heading", { name: "INVALID", exact: true }),
  ).toBeVisible();
  await expect(page.locator(".proof-verdict")).toContainText("Message #1");
  expect(uploads).toBe(0);
});

test("a dropped connection reconnects, requires login and derives a different signed session", async ({
  browser,
}) => {
  const a = await browser.newPage(),
    b = await browser.newPage();
  await a.addInitScript(() => {
    const Original = window.WebSocket;
    (window as any).testSockets = [];
    (window as any).handshakeKeys = [];
    window.WebSocket = new Proxy(Original, {
      construct(target, args) {
        const socket = Reflect.construct(target, args) as WebSocket;
        const send = socket.send.bind(socket);
        socket.send = (data) => {
          try {
            const frame = JSON.parse(String(data));
            if (frame.type === "handshake_init")
              (window as any).handshakeKeys.push(frame.pubkey);
          } catch {
            /* Non-JSON frames are irrelevant to handshake-key capture. */
          }
          send(data);
        };
        (window as any).testSockets.push(socket);
        return socket;
      },
    });
  });
  try {
    await fill(a, "reconnect_alice", "reconnect_bob");
    await a
      .getByRole("button", { name: "Create an identity", exact: true })
      .click();
    await fill(b, "reconnect_bob", "reconnect_alice");
    await b
      .getByRole("button", { name: "Create an identity", exact: true })
      .click();
    await expect(a.getByLabel("Message", { exact: true })).toBeEnabled();
    const before = await a.evaluate(() => (window as any).handshakeKeys.at(-1));
    expect(before).toBeTruthy();
    await a.evaluate(() => (window as any).testSockets.at(-1).close());
    await expect(a.getByRole("status")).toContainText("Reconnecting…");
    await expect(a.getByRole("status")).toContainText("log in again");
    await expect(b.getByLabel("Message", { exact: true })).toBeDisabled();
    await a.getByLabel("Password", { exact: true }).fill(password);
    await a.getByRole("button", { name: "Log in", exact: false }).click();
    await expect(a.getByLabel("Message", { exact: true })).toBeEnabled();
    await expect(b.getByLabel("Message", { exact: true })).toBeEnabled();
    const after = await a.evaluate(() => (window as any).handshakeKeys.at(-1));
    expect(after).toBeTruthy();
    expect(after).not.toBe(before);
    await a
      .getByLabel("Message", { exact: true })
      .fill("Fresh session after reconnect");
    await a.getByRole("button", { name: "Send message", exact: true }).click();
    await expect(
      b.getByRole("button", {
        name: "Security receipt: Fresh session after reconnect",
        exact: true,
      }),
    ).toBeVisible();
  } finally {
    await a.close();
    await b.close();
  }
});
