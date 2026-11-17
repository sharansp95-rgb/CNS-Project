import { test, expect, type Page, type Browser } from "@playwright/test";
const CHAT = "http://127.0.0.1:8871";
const MALLORY = "http://127.0.0.1:8872";
const password = "Browser-test-password-42!";
const runId = Date.now().toString(36);
test.describe.configure({ mode: "serial" });

let counter = 0;
async function scene(browser: Browser) {
  const tag = `m${runId}${counter++}`;
  const [ca, cb, cm] = await Promise.all([
    browser.newContext(),
    browser.newContext(),
    browser.newContext(),
  ]);
  const [alice, bob, mallory] = [
    await ca.newPage(),
    await cb.newPage(),
    await cm.newPage(),
  ];
  for (const [page, me, peer] of [
    [alice, "alice", "bob"],
    [bob, "bob", "alice"],
  ] as const) {
    await page.goto(CHAT + "/");
    await page.getByLabel("Username", { exact: true }).fill(`${tag}${me}`);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page
      .getByLabel("Peer username", { exact: true })
      .fill(`${tag}${peer}`);
    await page.getByRole("button", { name: "Create an identity" }).click();
  }
  await expect(alice.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(bob.getByLabel("Message", { exact: true })).toBeEnabled();
  await mallory.goto(MALLORY + "/");
  await mallory.getByRole("button", { name: "Reset" }).click();
  return {
    alice,
    bob,
    mallory,
    from: `${tag}alice`,
    close: () => Promise.all([ca.close(), cb.close(), cm.close()]),
  };
}
const send = async (p: Page, text: string) => {
  await p.getByLabel("Message", { exact: true }).fill(text);
  await p.getByRole("button", { name: "Send message" }).click();
};
const rowFor = (m: Page, from: string) =>
  m.locator(".row", { hasText: `${from} →` }).first();
const arm = async (
  m: Page,
  from: string,
  action: "DROP" | "TAMPER" | "REPLAY",
) => rowFor(m, from).getByRole("button", { name: action, exact: true }).click();
const warnings = (p: Page) => p.getByTestId("security-warnings");

test("Mallory sees one unreadable row per message with exactly three buttons", async ({
  browser,
}) => {
  const { alice, bob, mallory, from, close } = await scene(browser);
  try {
    const secret = `top-secret-${runId}`;
    await send(alice, secret);
    await expect(bob.getByText(secret)).toBeVisible();
    await expect(mallory.locator(".row")).toHaveCount(1);
    const row = rowFor(mallory, from);
    await expect(row).toContainText("→");
    await expect(row.getByRole("button")).toHaveText([
      "DROP",
      "TAMPER",
      "REPLAY",
    ]);
    // Nothing but rows, one Reset button and the feed: no intercept, no TLS, no hex dump.
    await expect(mallory.getByRole("button")).toHaveCount(4);
    const text = await mallory.locator("body").innerText();
    expect(text).not.toContain(secret);
    for (const word of ["Intercept", "pcap", "Wireshark", "Delay", "hex"])
      expect(text).not.toContain(word);
    await expect(row.locator(".ct")).toHaveText(/^[A-Za-z0-9+/]{20,}…?$/);
    await expect(row).toContainText("delivered");
    await expect(warnings(bob)).toHaveCount(0);
  } finally {
    await close();
  }
});

test("DROP: the message never arrives and the next one shows 'message missing'", async ({
  browser,
}) => {
  const { alice, bob, mallory, from, close } = await scene(browser);
  try {
    await send(alice, "warm-up");
    await expect(bob.getByText("warm-up")).toBeVisible();
    await arm(mallory, from, "DROP");
    await expect(mallory.locator("#feed")).toContainText("DROP armed");
    await send(alice, "this one is lost");
    await expect(mallory.locator("#feed")).toContainText("dropped");
    await expect(rowFor(mallory, from)).toContainText("dropped");
    await expect(bob.getByText("this one is lost")).toHaveCount(0);
    await expect(warnings(bob)).toHaveCount(0); // nothing arrived, so nothing can be noticed yet
    await send(alice, "the next one");
    await expect(bob.getByText("the next one")).toBeVisible();
    await expect(warnings(bob)).toContainText("Message missing");
    await expect(warnings(bob)).toContainText("1 message never arrived");
    // Mallory's feed repeats only what Bob's own client reported.
    await expect(mallory.locator("#feed")).toContainText(
      "own client: message missing",
    );
  } finally {
    await close();
  }
});

test("TAMPER: the receiver blocks the altered message", async ({ browser }) => {
  const { alice, bob, mallory, from, close } = await scene(browser);
  try {
    await send(alice, "warm-up");
    await expect(bob.getByText("warm-up")).toBeVisible();
    await arm(mallory, from, "TAMPER");
    await send(alice, "pay 500 to mallory");
    await expect(warnings(bob)).toContainText("altered");
    await expect(warnings(bob)).toContainText("rejected");
    await expect(bob.getByText("pay 500 to mallory")).toHaveCount(0);
    await expect(rowFor(mallory, from)).toContainText("tampered");
    await expect(mallory.locator("#feed")).toContainText(
      "own client: message was altered, rejected",
    );
    // The session survives: the next untouched message arrives normally.
    await send(alice, "normal again");
    await expect(bob.getByText("normal again")).toBeVisible();
  } finally {
    await close();
  }
});

test("REPLAY: the receiver blocks the duplicate", async ({ browser }) => {
  const { alice, bob, mallory, from, close } = await scene(browser);
  try {
    await send(alice, "warm-up");
    await expect(bob.getByText("warm-up")).toBeVisible();
    await arm(mallory, from, "REPLAY");
    await send(alice, "transfer once");
    await expect(bob.getByText("transfer once")).toHaveCount(1);
    await expect(warnings(bob)).toContainText(
      "Duplicate or old message — rejected",
    );
    await expect(rowFor(mallory, from)).toContainText("replayed");
    await expect(mallory.locator("#feed")).toContainText(
      "own client: duplicate or old message, rejected",
    );
    await expect(bob.getByText("transfer once")).toHaveCount(1); // still only once
  } finally {
    await close();
  }
});

test("Reset clears Mallory's rows, feed and armed attack; untouched messages stay normal", async ({
  browser,
}) => {
  const { alice, bob, mallory, from, close } = await scene(browser);
  try {
    await send(alice, "one");
    await expect(bob.getByText("one")).toBeVisible();
    await arm(mallory, from, "DROP");
    await mallory.getByRole("button", { name: "Reset" }).click();
    await expect(mallory.locator(".row")).toHaveCount(0);
    await send(alice, "two");
    await expect(bob.getByText("two")).toBeVisible(); // the armed DROP was cleared
    await expect(warnings(bob)).toHaveCount(0);
  } finally {
    await close();
  }
});
