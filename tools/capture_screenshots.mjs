/** Capture synthetic documentation screenshots against disposable local services. */
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const require = createRequire(path.join(root, "web/frontend/package.json"));
const { chromium, expect } = require("@playwright/test");
const output = path.join(root, "docs/screenshots/current");
const scratch = "/tmp/cns-phase8/screenshots";
await mkdir(output, { recursive: true });
await mkdir(scratch, { recursive: true });
const env = { ...process.env };
for (const key of Object.keys(env))
  if (/DATABASE_URL|TSA_|LAB_ACCESS_CODE|^S3_|METERED_|TURN_SECRET/.test(key))
    delete env[key];
const servers = [
  spawn(
    path.join(root, ".venv/bin/python"),
    ["web/frontend/tests/run_server.py"],
    {
      cwd: root,
      env: { ...env, CNS_TEST_PORT: "8790" },
      stdio: "ignore",
    },
  ),
  spawn(
    path.join(root, ".venv/bin/python"),
    ["attack_lab/tests/run_server.py"],
    {
      cwd: root,
      env: { ...env, CNS_TEST_LAB_PORT: "8791" },
      stdio: "ignore",
    },
  ),
];
async function ready(url) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      /* service starting */
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw Error("Local screenshot service did not start");
}
let browser;
try {
  await Promise.all([
    ready("http://127.0.0.1:8790/healthz"),
    ready("http://127.0.0.1:8791/healthz"),
  ]);
  browser = await chromium.launch({
    args: [
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
      "--disable-features=WebRtcHideLocalIpsWithMdns",
    ],
  });
  const contexts = await Promise.all(
    [0, 1].map(() =>
      browser.newContext({
        viewport: { width: 1440, height: 1050 },
        permissions: ["microphone"],
      }),
    ),
  );
  const [a, b] = await Promise.all(contexts.map((ctx) => ctx.newPage()));
  const password = "Synthetic-screenshot-password-42!";
  for (const [page, me, peer] of [
    [a, "demo_alice", "demo_bob"],
    [b, "demo_bob", "demo_alice"],
  ]) {
    await page.goto("http://127.0.0.1:8790/");
    await page.getByLabel("Username", { exact: true }).fill(me);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByLabel("Peer username", { exact: true }).fill(peer);
    await page
      .getByRole("button", { name: "Create an identity", exact: true })
      .click();
  }
  await expect(a.getByLabel("Message", { exact: true })).toBeEnabled();
  async function send(page, text) {
    await page.getByLabel("Message", { exact: true }).fill(text);
    await page
      .getByRole("button", { name: "Send message", exact: true })
      .click();
  }
  const screenshot = async (page, name, fullPage = true) => {
    await page.screenshot({
      path: path.join(output, name + ".png"),
      fullPage,
      animations: "disabled",
    });
    console.log("Captured", name);
  };
  await send(a, "The Team 15 demonstration is ready.");
  await expect(
    b.getByRole("button", {
      name: "Security receipt: The Team 15 demonstration is ready.",
      exact: true,
    }),
  ).toBeVisible();
  await send(
    b,
    "Received. The signature, hash chain and encryption checks passed.",
  );
  await a.getByRole("button", { name: "Wire Log", exact: false }).click();
  await a.locator(".wire").evaluate((el) => {
    el.scrollTop = el.scrollHeight;
  });
  await screenshot(a, "01-chat-wire-dark");
  await a.getByRole("button", { name: "Toggle theme", exact: true }).click();
  await screenshot(a, "02-chat-wire-light");
  await a.getByRole("button", { name: "Wire Log", exact: false }).click();
  await b
    .getByRole("button", {
      name: "Security receipt: The Team 15 demonstration is ready.",
      exact: true,
    })
    .click();
  await screenshot(b, "03-security-receipt");
  await b.getByRole("button", { name: "Close receipt", exact: true }).click();
  await a.getByRole("button", { name: "Save evidence", exact: true }).click();
  await a.getByLabel("Vault password", { exact: true }).fill(password);
  await a
    .getByLabel("Evidence title", { exact: true })
    .fill("Team 15 synthetic demonstration");
  await a
    .getByRole("button", { name: "Encrypt and save", exact: true })
    .click();
  await expect(
    a.getByRole("heading", { name: "VALID", exact: true }),
  ).toBeVisible();
  await screenshot(a, "04-encrypted-evidence-vault");
  for (const [label, filename] of [
    ["Download exact signed JSON", "evidence.json"],
    ["Download timestamp receipt", "receipt.json"],
    ["Download companion PDF", "companion.pdf"],
  ]) {
    const pending = a.waitForEvent("download");
    await a.getByRole("button", { name: label, exact: true }).click();
    await (await pending).saveAs(path.join(scratch, filename));
  }
  const verify = await browser.newPage({
    viewport: { width: 1280, height: 1100 },
  });
  await verify.goto("http://127.0.0.1:8790/verify");
  await verify
    .getByLabel("Evidence JSON file", { exact: true })
    .setInputFiles(path.join(scratch, "evidence.json"));
  await verify
    .getByLabel("Receipt JSON file", { exact: true })
    .setInputFiles(path.join(scratch, "receipt.json"));
  const key = await (
    await fetch("http://127.0.0.1:8790/api/timestamp-key")
  ).json();
  await verify
    .getByLabel("Trusted TSA public key (PEM)", { exact: true })
    .fill(key.public_key_pem);
  await verify
    .getByRole("button", { name: "Verify locally", exact: true })
    .click();
  await expect(
    verify.getByRole("heading", { name: "VALID", exact: true }),
  ).toBeVisible();
  await screenshot(verify, "05-verify-valid");
  const edited = JSON.parse(
    await readFile(path.join(scratch, "evidence.json"), "utf8"),
  );
  edited.records[0].message = "Edited after signing";
  await writeFile(path.join(scratch, "edited.json"), JSON.stringify(edited));
  await verify
    .getByLabel("Evidence JSON file", { exact: true })
    .setInputFiles(path.join(scratch, "edited.json"));
  await verify
    .getByRole("button", { name: "Verify locally", exact: true })
    .click();
  await expect(
    verify.getByRole("heading", { name: "INVALID", exact: true }),
  ).toBeVisible();
  await screenshot(verify, "06-verify-tampered");
  await a.getByRole("button", { name: "Back to chat", exact: false }).click();
  await a
    .getByLabel("Attach file")
    .setInputFiles(path.join(root, "web/frontend/e2e/fixtures/photo.png"));
  await expect(b.getByTestId("attachment")).toHaveCount(1);
  await b
    .getByTestId("attachment")
    .getByRole("button", { name: /Open image/ })
    .click();
  await expect(b.getByRole("dialog", { name: "Image viewer" })).toBeVisible();
  await screenshot(b, "07-verified-attachment");
  await b.keyboard.press("Escape");
  await a
    .getByRole("button", { name: "Start voice call", exact: true })
    .click();
  const call = (page) =>
    page.getByRole("dialog", { name: "Voice call", exact: true });
  await call(b).getByRole("button", { name: "Accept", exact: true }).click();
  await expect(call(a)).toHaveAttribute("data-state", "active", {
    timeout: 30000,
  });
  await expect(call(a).getByTestId("call-fp")).toContainText("matches", {
    timeout: 15000,
  });
  await screenshot(a, "08-call-verification-words");
  await b.setViewportSize({ width: 390, height: 844 });
  await screenshot(b, "09-mobile-call");
  await call(a).getByRole("button", { name: "Hang up", exact: true }).click();
  const lab = await browser.newPage({
    viewport: { width: 1720, height: 1100 },
  });
  await lab.goto("http://127.0.0.1:8791/");
  await lab
    .getByLabel("Lab access code", { exact: true })
    .fill("Local-test-access-code-ONLY-1234");
  await lab.getByRole("button", { name: "Enter sandbox", exact: true }).click();
  await lab
    .getByRole("button", { name: "Start lab session", exact: true })
    .click();
  await lab
    .getByRole("button", { name: "Connect victims", exact: true })
    .click();
  await expect(
    lab.frameLocator("#alice").getByLabel("Message", { exact: true }),
  ).toBeEnabled();
  await lab
    .getByRole("button", { name: "Tamper ciphertext", exact: true })
    .click();
  await lab
    .getByRole("button", { name: "Send next message", exact: true })
    .click();
  await expect(lab.locator("#detections")).toContainText("decryption_failed");
  await screenshot(lab, "10-lab-genuine-detection");
} finally {
  await browser?.close();
  for (const child of servers) child.kill("SIGTERM");
}
