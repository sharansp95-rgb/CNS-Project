import { test, expect, type Page, type Browser } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const CHAT = "http://127.0.0.1:8871";
const MALLORY = "http://127.0.0.1:8872";
const password = "Browser-test-password-42!";
const runId = Date.now().toString(36);
test.describe.configure({ mode: "serial" });

// The relay allows 20 register/login attempts per address per minute; each scene registers 2 users.
// Both browser projects share one budget, so the start times live in a file.
const stamps = join(tmpdir(), "mallory-e2e-starts.json");
async function pace() {
  const read = (): number[] => {
    try {
      return JSON.parse(readFileSync(stamps, "utf8"));
    } catch {
      return [];
    }
  };
  for (;;) {
    const recent = read().filter((t) => Date.now() - t < 61000);
    if (recent.length < 8) {
      writeFileSync(stamps, JSON.stringify([...recent, Date.now()]));
      return;
    }
    const wait = 61000 - (Date.now() - recent[0]) + 500;
    test.setTimeout(test.info().timeout + wait);
    await new Promise((r) => setTimeout(r, wait));
  }
}
let counter = 0;
async function scene(browser: Browser) {
  await pace();
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
    to: `${tag}bob`,
    close: () => Promise.all([ca.close(), cb.close(), cm.close()]),
  };
}
const send = async (p: Page, text: string) => {
  await p.getByLabel("Message", { exact: true }).fill(text);
  await p.getByRole("button", { name: "Send message" }).click();
};
const rows = (m: Page) => m.locator(".row");
const button = (m: Page, name: "TAMPER" | "DROP" | "REPLAY") =>
  m.getByRole("button", { name, exact: true });
const armed = (m: Page) => m.locator("#armed");
const warnings = (p: Page) => p.getByTestId("security-warnings");
const feed = (m: Page) => m.locator("#feed");

test("one set of three attack buttons at the top; rows are a read-only live list", async ({
  browser,
}) => {
  const { alice, bob, mallory, from, close } = await scene(browser);
  try {
    // Exactly TAMPER, DROP, REPLAY (in that order) plus Reset (top right): nothing else clickable.
    await expect(mallory.locator(".attacks").getByRole("button")).toHaveText([
      "TAMPER",
      "DROP",
      "REPLAY",
    ]);
    await expect(mallory.getByRole("button")).toHaveCount(4);
    await expect(armed(mallory)).toHaveText(
      "Nothing armed. Messages pass untouched.",
    );
    const secret = `top-secret-${runId}`;
    await send(alice, secret);
    await expect(bob.getByText(secret)).toBeVisible();
    await expect(rows(mallory)).toHaveCount(1);
    const row = rows(mallory).first();
    await expect(row).toContainText(`${from} →`);
    await expect(row.getByRole("button")).toHaveCount(0);
    await expect(row.locator(".ct")).toHaveText(/^[A-Za-z0-9+/]{20,}…?$/);
    await expect(row.locator(".badge")).toHaveCount(0); // untouched message: no label
    await expect(mallory.getByRole("button")).toHaveCount(4); // still just 3 + Reset
    const text = await mallory.locator("body").innerText();
    expect(text).not.toContain(secret);
    for (const word of ["Intercept", "pcap", "Wireshark", "Delay", "hex"])
      expect(text).not.toContain(word);
    await expect(warnings(bob)).toHaveCount(0);
  } finally {
    await close();
  }
});

test("clicking arms the attack clearly; clicking it again disarms; arming another switches", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await scene(browser);
  try {
    await button(mallory, "TAMPER").click();
    await expect(button(mallory, "TAMPER")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(button(mallory, "DROP")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    await expect(armed(mallory)).toHaveText(
      "Armed: TAMPER — waiting for next message",
    );
    await button(mallory, "TAMPER").click(); // second click disarms
    await expect(button(mallory, "TAMPER")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    await expect(armed(mallory)).toHaveText(
      "Nothing armed. Messages pass untouched.",
    );
    await button(mallory, "DROP").click();
    await button(mallory, "REPLAY").click(); // only one attack can be armed
    await expect(armed(mallory)).toHaveText(
      "Armed: REPLAY — waiting for next message",
    );
    await expect(button(mallory, "DROP")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    await button(mallory, "REPLAY").click();
    // Disarmed: the next message passes untouched.
    await send(alice, "untouched");
    await expect(bob.getByText("untouched")).toBeVisible();
    await expect(warnings(bob)).toHaveCount(0);
    await expect(rows(mallory).first().locator(".badge")).toHaveCount(0);
  } finally {
    await close();
  }
});

test("TAMPER: the receiver blocks the altered message, then Mallory disarms itself", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await scene(browser);
  try {
    await send(alice, "warm-up");
    await expect(bob.getByText("warm-up")).toBeVisible();
    await button(mallory, "TAMPER").click();
    await expect(armed(mallory)).toContainText("Armed: TAMPER");
    await send(alice, "pay 500 to mallory");
    await expect(warnings(bob)).toContainText(
      "Message was altered in transit — rejected",
    );
    await expect(bob.getByText("pay 500 to mallory")).toHaveCount(0);
    await expect(rows(mallory).first().locator(".badge")).toHaveText(
      "TAMPERED",
    );
    await expect(armed(mallory)).toHaveText(
      "Nothing armed. Messages pass untouched.",
    ); // auto-disarmed
    await expect(feed(mallory)).toContainText(
      "own client: message was altered, rejected",
    );
    await send(alice, "normal again"); // one shot: the next message is untouched
    await expect(bob.getByText("normal again")).toBeVisible();
    await expect(rows(mallory).first().locator(".badge")).toHaveCount(0);
  } finally {
    await close();
  }
});

test("DROP: the message never arrives; the next one shows '1 message missing'", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await scene(browser);
  try {
    await send(alice, "warm-up");
    await expect(bob.getByText("warm-up")).toBeVisible();
    await button(mallory, "DROP").click();
    await send(alice, "this one is lost");
    await expect(rows(mallory).first().locator(".badge")).toHaveText("DROPPED");
    await expect(armed(mallory)).toHaveText(
      "Nothing armed. Messages pass untouched.",
    );
    await expect(bob.getByText("this one is lost")).toHaveCount(0);
    await expect(warnings(bob)).toHaveCount(0); // nothing arrived, so nothing can be noticed yet
    await send(alice, "the next one");
    await expect(bob.getByText("the next one")).toBeVisible();
    await expect(warnings(bob)).toContainText("1 message missing");
    await expect(feed(mallory)).toContainText("own client: message missing");
  } finally {
    await close();
  }
});

test("REPLAY: delivered once, then the duplicate is blocked", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await scene(browser);
  try {
    await send(alice, "warm-up");
    await expect(bob.getByText("warm-up")).toBeVisible();
    await button(mallory, "REPLAY").click();
    await send(alice, "transfer once");
    await expect(bob.getByText("transfer once")).toHaveCount(1);
    await expect(warnings(bob)).toContainText(
      "Duplicate or old message — rejected",
    );
    await expect(rows(mallory).first().locator(".badge")).toHaveText(
      "REPLAYED",
    );
    await expect(feed(mallory)).toContainText(
      "own client: duplicate or old message, rejected",
    );
    await expect(armed(mallory)).toHaveText(
      "Nothing armed. Messages pass untouched.",
    );
    await expect(bob.getByText("transfer once")).toHaveCount(1); // still only once
  } finally {
    await close();
  }
});

test("an armed attack hits the next message from EITHER user (Bob -> Alice)", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await scene(browser);
  try {
    await send(alice, "hi bob");
    await expect(bob.getByText("hi bob")).toBeVisible();
    await send(bob, "hi alice");
    await expect(alice.getByText("hi alice")).toBeVisible();
    await button(mallory, "TAMPER").click();
    await send(bob, "bob's secret");
    await expect(warnings(alice)).toContainText(
      "Message was altered in transit — rejected",
    );
    await expect(alice.getByText("bob's secret")).toHaveCount(0);
    await expect(rows(mallory).first()).toContainText("bob →");
    await expect(rows(mallory).first().locator(".badge")).toHaveText(
      "TAMPERED",
    );
  } finally {
    await close();
  }
});

test("Reset clears Mallory's rows, feed and armed attack", async ({
  browser,
}) => {
  const { alice, bob, mallory, close } = await scene(browser);
  try {
    await send(alice, "one");
    await expect(bob.getByText("one")).toBeVisible();
    await button(mallory, "DROP").click();
    await mallory.getByRole("button", { name: "Reset" }).click();
    await expect(rows(mallory)).toHaveCount(0);
    await expect(armed(mallory)).toHaveText(
      "Nothing armed. Messages pass untouched.",
    );
    await send(alice, "two");
    await expect(bob.getByText("two")).toBeVisible(); // the armed DROP was cleared
    await expect(warnings(bob)).toHaveCount(0);
  } finally {
    await close();
  }
});
