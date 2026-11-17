import { test, expect, type Page, type Browser } from "@playwright/test";
import { fileURLToPath } from "node:url";
const runId = process.env.E2E_RUN_ID || Date.now().toString(36);
const password = "Browser-test-password-42!";
const fx = (n: string) =>
  fileURLToPath(new URL("./fixtures/" + n, import.meta.url));
async function pair(browser: Browser, tag: string) {
  const prefix = `${browser.browserType().name()}_${runId}_${tag}_`;
  const [a, b] = await Promise.all([
    browser.newContext(),
    browser.newContext(),
  ]);
  const [pa, pb] = [await a.newPage(), await b.newPage()];
  for (const [page, me, peer] of [
    [pa, "alice", "bob"],
    [pb, "bob", "alice"],
  ] as const) {
    await page.goto("/");
    await page.getByLabel("Username", { exact: true }).fill(prefix + me);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByLabel("Peer username", { exact: true }).fill(prefix + peer);
    await page.getByRole("button", { name: "Create an identity" }).click();
  }
  await expect(pa.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(pb.getByLabel("Message", { exact: true })).toBeEnabled();
  return { pa, pb, close: () => Promise.all([a.close(), b.close()]) };
}
// Local signed URL, or a presigned URL straight to the bucket in production.
const OBJECT_URL = /\/api\/attachments\/object\/|X-Amz-Signature=/;
const card = (p: Page) => p.getByTestId("attachment");
// One shared pair for the whole file: the relay allows 20 register/login attempts per
// address per minute, and the other suites share this server.
test.describe.configure({ mode: "serial" });
let pa: Page, pb: Page, closeAll: () => Promise<unknown>;
const counts = new Map<Page, number>();
/** Attach a file on `from` and wait until `to` shows one more attachment card. */
async function send(from: Page, to: Page, file: string) {
  const expected = (counts.get(to) ?? 0) + 1;
  counts.set(to, expected);
  counts.set(from, (counts.get(from) ?? 0) + 1);
  await from.getByLabel("Attach file").setInputFiles(fx(file));
  await expect(card(to)).toHaveCount(expected);
  return expected - 1; // index of the new card on `to`
}
test.beforeAll(async ({ browser }) => {
  const p = await pair(browser, "att");
  ({ pa, pb } = p);
  closeAll = p.close;
});
test.afterAll(async () => closeAll?.());

test("images both ways: encrypted upload, GPS stripped, verified render, wire log", async () => {
  const errors: string[] = [];
  for (const p of [pa, pb]) p.on("pageerror", (e) => errors.push(e.message));
  const uploads: Buffer[] = [],
    uploadHosts: string[] = [];
  pa.on("request", (r) => {
    // Local backend: same-origin signed URL. Production: a presigned URL straight to the bucket.
    if (
      r.method() === "PUT" &&
      (r.url().includes("/api/attachments/object/") ||
        r.url().includes("X-Amz-Signature="))
    ) {
      uploads.push(r.postDataBuffer()!);
      uploadHosts.push(new URL(r.url()).host);
    }
  });
  const i = await send(pa, pb, "photo_gps.jpg");
  await expect(card(pb).nth(i)).toContainText("photo_gps.jpg");
  await expect(card(pb).nth(i).locator("img")).toBeVisible(); // encrypted thumbnail from the message
  await card(pb)
    .nth(i)
    .getByRole("button", { name: /Open image/ })
    .click();
  const viewer = pb.getByRole("dialog", { name: "Image viewer" });
  await expect(viewer.locator("img")).toBeVisible();
  expect(
    await viewer
      .locator("img")
      .evaluate((im: HTMLImageElement) => im.naturalWidth),
  ).toBe(240);
  await pb.keyboard.press("Escape");
  // The decrypted file the recipient saves has a safe name and no Exif/GPS.
  const download = pb.waitForEvent("download");
  await card(pb).nth(i).getByRole("button", { name: "Save" }).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toBe("photo_gps.jpg");
  const bytes = Array.from(
    (await import("node:fs")).readFileSync((await saved.path())!),
  );
  expect(src(bytes)).not.toContain("Exif");
  expect(bytes.slice(0, 3)).toEqual([0xff, 0xd8, 0xff]);
  // What reached storage was ciphertext only.
  expect(uploads).toHaveLength(1);
  // With object storage configured, bytes never pass through the app server.
  if (process.env.BASE_URL)
    expect(uploadHosts[0]).not.toBe(new URL(process.env.BASE_URL).host);
  expect(src(Array.from(uploads[0]))).not.toContain("JFIF");
  expect(uploads[0].subarray(0, 3)).not.toEqual(
    Buffer.from([0xff, 0xd8, 0xff]),
  );
  // Wire log: ciphertext hash and the "only ciphertext" note, never the file name or key.
  await pa.getByRole("button", { name: "Wire Log" }).click();
  const wire = await pa.locator(".wire").innerText();
  expect(wire).toContain("attachment_upload");
  expect(wire).toContain("Only ciphertext was uploaded");
  expect(wire).toMatch(/[0-9a-f]{64}/);
  expect(wire).not.toContain("photo_gps");
  await pa.getByRole("button", { name: "Wire Log" }).click();
  // Other direction.
  const j = await send(pb, pa, "photo.png");
  await card(pa)
    .nth(j)
    .getByRole("button", { name: /Open image/ })
    .click();
  await expect(
    pa.getByRole("dialog", { name: "Image viewer" }).locator("img"),
  ).toBeVisible();
  await pa.keyboard.press("Escape");
  expect(errors).toEqual([]);
});

test("video both ways with inline player", async () => {
  const i = await send(pa, pb, "clip.webm");
  await expect(card(pb).nth(i)).toContainText("clip.webm");
  await card(pb)
    .nth(i)
    .getByRole("button", { name: /Open video/ })
    .click();
  const video = card(pb).nth(i).locator("video");
  await expect(video).toBeVisible();
  await expect
    .poll(() => video.evaluate((v: HTMLVideoElement) => v.videoWidth))
    .toBe(64);
  expect(
    await video.evaluate((v: HTMLVideoElement) => v.src.startsWith("blob:")),
  ).toBe(true);
  const j = await send(pb, pa, "clip.webm");
  await card(pa)
    .nth(j)
    .getByRole("button", { name: /Open video/ })
    .click();
  await expect
    .poll(() =>
      card(pa)
        .nth(j)
        .locator("video")
        .evaluate((v: HTMLVideoElement) => v.videoWidth),
    )
    .toBe(64);
});

test("a modified stored object is rejected as tampered", async () => {
  await pb.route(OBJECT_URL, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const r = await route.fetch();
    const body = Buffer.from(await r.body());
    body[body.length >> 1] ^= 0xff;
    await route.fulfill({ response: r, body });
  });
  const i = await send(pa, pb, "photo.png");
  await card(pb)
    .nth(i)
    .getByRole("button", { name: /Open image/ })
    .click();
  await expect(card(pb).nth(i).getByRole("alert")).toContainText(
    "tampered or corrupted",
  );
  await expect(pb.getByRole("dialog", { name: "Image viewer" })).toHaveCount(0);
  await pb.unroute(OBJECT_URL);
});

test("a swapped object (another valid ciphertext) is rejected", async () => {
  const first = await send(pa, pb, "photo.png");
  const second = await send(pa, pb, "photo_gps.jpg");
  // Serve the first attachment's ciphertext when the second one is requested.
  let firstBody: Buffer | undefined;
  await pb.route(OBJECT_URL, async (route) => {
    const r = await route.fetch();
    const body = Buffer.from(await r.body());
    if (!firstBody) firstBody = body;
    await route.fulfill({ response: r, body: firstBody });
  });
  await card(pb)
    .nth(first)
    .getByRole("button", { name: /Open image/ })
    .click();
  await expect(pb.getByRole("dialog", { name: "Image viewer" })).toBeVisible();
  await pb.keyboard.press("Escape");
  await card(pb)
    .nth(second)
    .getByRole("button", { name: /Open image/ })
    .click();
  await expect(card(pb).nth(second).getByRole("alert")).toContainText(
    "tampered or corrupted",
  );
  await pb.unroute(OBJECT_URL);
});

test("unsupported and disguised files are refused; paste and drop work", async () => {
  const before = counts.get(pb) ?? 0;
  await pa.getByLabel("Attach file").setInputFiles({
    name: "evil.jpg",
    mimeType: "image/jpeg",
    buffer: Buffer.from(
      "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
    ),
  });
  await expect(
    pa.getByRole("alert").filter({ hasText: "Unsupported file type" }),
  ).toBeVisible();
  await expect(card(pb)).toHaveCount(before);
  const png = (await import("node:fs"))
    .readFileSync(fx("photo.png"))
    .toString("base64");
  const fire = (target: string, kind: "paste" | "drop") =>
    pa.evaluate(
      ([b64, sel, k]) => {
        const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        const dt = new DataTransfer();
        dt.items.add(new File([bin], "pasted.png", { type: "image/png" }));
        const el = document.querySelector(sel)!;
        const ev =
          k === "paste"
            ? new ClipboardEvent("paste", {
                clipboardData: dt,
                bubbles: true,
                cancelable: true,
              })
            : new DragEvent("drop", {
                dataTransfer: dt,
                bubbles: true,
                cancelable: true,
              });
        el.dispatchEvent(ev);
      },
      [png, target, kind] as const,
    );
  await fire('input[aria-label="Message"]', "paste");
  await expect(card(pb)).toHaveCount(before + 1);
  await fire(".chat", "drop");
  await expect(card(pb)).toHaveCount(before + 2);
});

test("mobile layout keeps the attach control inside the viewport", async ({
  browser,
}) => {
  const ctx = await browser.newContext({
    viewport: { width: 390, height: 844 },
  });
  const p = await ctx.newPage();
  await p.goto("/");
  await p
    .getByLabel("Username", { exact: true })
    .fill(`m_${runId}_${Math.random().toString(36).slice(2, 6)}`);
  await p.getByLabel("Password", { exact: true }).fill(password);
  await p.getByLabel("Peer username", { exact: true }).fill("nobody_here");
  await p.getByRole("button", { name: "Create an identity" }).click();
  await expect(p.getByLabel("Attach file")).toBeAttached();
  expect(
    await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBe(true);
  await ctx.close();
});
function src(bytes: number[]) {
  return String.fromCharCode(...bytes.slice(0, 4096));
}

test("/verify checks a file against the attachment hashes in evidence, locally", async ({
  page,
}) => {
  const corpus = (n: string) =>
    fileURLToPath(
      new URL("../../../tests/fixtures/evidence_corpus/" + n, import.meta.url),
    );
  const uploads: string[] = [];
  page.on("request", (r) => r.method() !== "GET" && uploads.push(r.url()));
  await page.goto("/verify");
  await page
    .getByLabel("Evidence JSON file")
    .setInputFiles(corpus("valid_v2_attachment.json"));
  await page.getByRole("button", { name: "Verify locally" }).click();
  await expect(page.getByRole("heading", { name: "VALID" })).toBeVisible();
  const section = page.getByRole("region", {
    name: "Attachments in this evidence",
  });
  await expect(section).toContainText("sample.png");
  await section
    .getByLabel("Attachment file to check")
    .setInputFiles(corpus("attachment_sample.png"));
  await expect(section.getByRole("status")).toContainText("MATCH");
  await expect(section.getByRole("status")).toContainText(
    "original (decrypted) file",
  );
  await section
    .getByLabel("Attachment file to check")
    .setInputFiles(corpus("attachment_sample.enc"));
  await expect(section.getByRole("status")).toContainText(
    "stored encrypted object",
  );
  await section
    .getByLabel("Attachment file to check")
    .setInputFiles(corpus("valid_v1.json"));
  await expect(section.getByRole("status")).toContainText("NO MATCH");
  expect(uploads).toEqual([]);
});
