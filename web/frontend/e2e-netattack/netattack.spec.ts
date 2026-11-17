import {
  test,
  expect,
  devices,
  type Page,
  type BrowserContext,
} from "@playwright/test";
import { fileURLToPath } from "node:url";
// The victims' URL is Mallory's proxy; the real HTTPS/WSS gateway sits behind it.
const VICTIM = "https://localhost:8861";
const MALLORY = "http://127.0.0.1:8863";
const password = "Browser-test-password-42!";
const runId = Date.now().toString(36);
const fx = (n: string) =>
  fileURLToPath(new URL("../e2e/fixtures/" + n, import.meta.url));
test.describe.configure({ mode: "serial" });
// Mallory's state is shared by all tests: start each one with Intercept off and auto-resume on.
test.beforeEach(async ({ request }) => {
  const headers = { origin: MALLORY };
  await request.post(MALLORY + "/api/intercept", {
    data: { on: false },
    headers,
  });
  await request.post(MALLORY + "/api/auto-resume", {
    data: { on: true },
    headers,
  });
  await request.post(MALLORY + "/api/clear", { headers });
});

let counter = 0;
async function pair(browser: import("@playwright/test").Browser) {
  const tag = `na${runId}${counter++}`;
  const ctxs: BrowserContext[] = await Promise.all([
    browser.newContext({ permissions: ["microphone"] }),
    browser.newContext({ permissions: ["microphone"] }),
  ]);
  const [alice, bob] = [await ctxs[0].newPage(), await ctxs[1].newPage()];
  for (const [page, me, peer] of [
    [alice, "alice", "bob"],
    [bob, "bob", "alice"],
  ] as const) {
    await page.goto(VICTIM + "/");
    await page.getByLabel("Username", { exact: true }).fill(`${tag}_${me}`);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page
      .getByLabel("Peer username", { exact: true })
      .fill(`${tag}_${peer}`);
    await page.getByRole("button", { name: "Create an identity" }).click();
  }
  await expect(alice.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(bob.getByLabel("Message", { exact: true })).toBeEnabled();
  const mallory = await (await browser.newContext()).newPage();
  await mallory.goto(MALLORY + "/");
  return {
    tag,
    alice,
    bob,
    mallory,
    close: () => Promise.all(ctxs.map((c) => c.close())),
  };
}
const send = async (p: Page, text: string) => {
  await p.getByLabel("Message", { exact: true }).fill(text);
  await p.getByRole("button", { name: "Send message" }).click();
};
const feed = (m: Page) => m.locator("#feed");
const intercept = async (m: Page) => {
  await m.getByRole("button", { name: "Intercept: OFF" }).click();
  await expect(m.getByRole("button", { name: "Intercept: ON" })).toBeVisible();
};
/** Press a decision button on the held record travelling client -> server. */
const decide = async (m: Page, action: string) => {
  const row = m.locator("tr.pending", { hasText: "→ server" }).first();
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: action, exact: true }).click();
};

test("chat, photo and voice call work through the proxy, and Mallory only sees ciphertext", async ({
  browser,
  request,
}) => {
  const { tag, alice, bob, mallory, close } = await pair(browser);
  try {
    const secret = `SECRET-${runId}-hello`;
    await send(alice, secret);
    await expect(bob.getByText(secret)).toBeVisible();
    await send(bob, `reply-${runId}`);
    await expect(alice.getByText(`reply-${runId}`)).toBeVisible();
    await alice.getByLabel("Attach file").setInputFiles(fx("photo.png"));
    await expect(bob.getByTestId("attachment")).toHaveCount(1);
    await alice.getByRole("button", { name: "Start voice call" }).click();
    const panel = (p: Page) => p.getByRole("dialog", { name: "Voice call" });
    await panel(bob).getByRole("button", { name: "Accept" }).click();
    await expect(panel(alice)).toHaveAttribute("data-state", "active", {
      timeout: 30000,
    });
    await expect(panel(bob)).toHaveAttribute("data-state", "active", {
      timeout: 30000,
    });
    await panel(alice)
      .getByRole("button", { name: /hang up|end/i })
      .click();
    // Mallory's window lists only unreadable TLS records.
    await expect(mallory.locator("#rows tr").first()).toBeVisible();
    const kinds = await mallory
      .locator("#rows tr td:nth-child(4)")
      .allTextContents();
    expect(kinds.length).toBeGreaterThan(10);
    expect(new Set(kinds.map((k) => k.replace(/ \(.*/, "")))).toEqual(
      new Set(["Application Data", "ChangeCipherSpec", "Handshake"]),
    );
    const pcap = Buffer.from(
      await (await request.get(MALLORY + "/api/capture.pcap")).body(),
    );
    for (const needle of [
      secret,
      `reply-${runId}`,
      tag,
      password,
      "register",
      '"type"',
    ])
      expect(pcap.includes(Buffer.from(needle))).toBe(false);
  } finally {
    await close();
  }
});

test("Alter: the real TLS stack rejects the changed record and the browser loses its session", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await pair(browser);
  try {
    await intercept(mallory);
    await send(alice, "pay 500");
    await decide(mallory, "Alter");
    await expect(alice.getByRole("status")).toContainText(
      /Reconnecting|Connection failed/,
    );
    await expect(feed(mallory)).toContainText(/ALTER.*|closed by the server/);
    await expect(feed(mallory)).toContainText("closed by the server");
    await expect(bob.getByText("pay 500")).toHaveCount(0);
  } finally {
    await close();
  }
});

test("Replay: the duplicate record breaks the connection", async ({
  browser,
}) => {
  const { alice, mallory, close } = await pair(browser);
  try {
    await intercept(mallory);
    await send(alice, "replay me");
    await decide(mallory, "Replay");
    await expect(alice.getByRole("status")).toContainText(
      /Reconnecting|Connection failed/,
    );
    await expect(feed(mallory)).toContainText("REPLAY");
  } finally {
    await close();
  }
});

test("Drop: the message silently never arrives; the next one desynchronises TLS", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await pair(browser);
  try {
    await intercept(mallory);
    await send(alice, "lost message");
    await decide(mallory, "Drop");
    await expect(feed(mallory)).toContainText("STALLED", { timeout: 20000 });
    await expect(bob.getByText("lost message")).toHaveCount(0);
    await send(alice, "after the gap");
    await expect(alice.getByRole("status")).toContainText(
      /Reconnecting|Connection failed/,
      {
        timeout: 30000,
      },
    );
    await expect(bob.getByText("after the gap")).toHaveCount(0);
  } finally {
    await close();
  }
});

test("the browser's own network stack reports the TLS failure for an altered HTTPS POST", async ({
  browser,
}) => {
  const { alice, mallory, close } = await pair(browser);
  try {
    const errors: string[] = [];
    alice.on("requestfailed", (r) => errors.push(r.failure()?.errorText ?? ""));
    // Chrome silently retries a failed request on a fresh connection: keep Mallory in the way.
    await mallory.getByLabel("resume forwarding after an attack").uncheck();
    await intercept(mallory);
    const result = alice.evaluate(() =>
      fetch("/api/timestamp-key", { method: "POST", cache: "no-store" }).then(
        () => "ok",
        (e) => String(e),
      ),
    );
    // Alter every record Mallory is holding for the server (the POST is one of them).
    await expect(mallory.locator("tr.pending").first()).toBeVisible();
    for (let i = 0; i < 6; i++) {
      for (const b of await mallory
        .locator("tr.pending")
        .getByRole("button", { name: "Alter", exact: true })
        .all())
        await b.click({ timeout: 2000 }).catch(() => undefined);
      await mallory.waitForTimeout(250);
    }
    expect(await result).not.toBe("ok");
    console.log("browser errors:", JSON.stringify(errors));
    expect(errors.join(" ")).toMatch(/net::ERR_/);
  } finally {
    await close();
  }
});

test("a phone-sized browser reaches the proxy on the LAN address and chats with a desktop browser", async ({
  browser,
  request,
}) => {
  const state = await (await request.get(MALLORY + "/api/state")).json();
  test.skip(!state.lan, "this machine has no private LAN address");
  const phoneUrl: string = state.lan.url; // https://<lan ip>:8861, what the QR code encodes
  const tag = `ph${runId}`;
  const phone = await browser.newContext({
    ...devices["iPhone 13"],
    defaultBrowserType: undefined,
    permissions: ["microphone"],
  });
  const desktop = await browser.newContext();
  try {
    const [pp, dp] = [await phone.newPage(), await desktop.newPage()];
    for (const [page, url, me, peer] of [
      [pp, phoneUrl, "phone", "desk"],
      [dp, VICTIM, "desk", "phone"],
    ] as const) {
      await page.goto(url + "/");
      await page.getByLabel("Username", { exact: true }).fill(`${tag}_${me}`);
      await page.getByLabel("Password", { exact: true }).fill(password);
      await page
        .getByLabel("Peer username", { exact: true })
        .fill(`${tag}_${peer}`);
      await page.getByRole("button", { name: "Create an identity" }).click();
    }
    await expect(pp.getByLabel("Message", { exact: true })).toBeEnabled();
    await expect(dp.getByLabel("Message", { exact: true })).toBeEnabled();
    await send(pp, "hello from the phone");
    await expect(dp.getByText("hello from the phone")).toBeVisible();
    await send(dp, "hello from the desktop");
    await expect(pp.getByText("hello from the desktop")).toBeVisible();
    // The phone's traffic passed through Mallory on the LAN address, and is unreadable there.
    const pcap = Buffer.from(
      await (await request.get(MALLORY + "/api/capture.pcap")).body(),
    );
    expect(pcap.includes(Buffer.from("hello from the phone"))).toBe(false);
  } finally {
    await phone.close();
    await desktop.close();
  }
});
