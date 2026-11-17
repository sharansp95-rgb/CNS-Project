import {
  test,
  expect,
} from "../../web/frontend/node_modules/@playwright/test/index.js";
// The lab allows 10 access-session starts per minute per address. Every test starts one,
// so pace them: wait just long enough that no more than 9 fall inside any 61 seconds.
const starts: number[] = [];
test.beforeEach(async () => {
  const now = () => Date.now();
  while (starts.length && now() - starts[0] > 61000) starts.shift();
  if (starts.length >= 9) {
    const wait = 61000 - (now() - starts[0]) + 500;
    test.setTimeout(test.info().timeout + wait);
    await new Promise((r) => setTimeout(r, wait));
    while (starts.length && now() - starts[0] > 61000) starts.shift();
  }
  starts.push(now());
});
const attacks = [
  ["Tamper ciphertext", "decryption_failed"],
  ["Replay old envelope", "replay_duplicate"],
  ["Drop next message", "chain_gap"],
  ["Reorder next messages", "chain_broken"],
  ["Inject forged message", "decryption_failed"],
  ["MITM key substitution", "signature_failed"],
  ["Login brute-force / lockout", "lockout_rejected"],
];
for (const [action, reason] of attacks)
  test("real victim detection: " + action, async ({ page }) => {
    await page.goto("/");
    const gate = page.getByLabel("Lab access code", { exact: true });
    if (await gate.isVisible()) {
      await gate.fill(
        process.env.LAB_ACCESS_CODE || "Local-test-access-code-ONLY-1234",
      );
      await page
        .getByRole("button", { name: "Enter sandbox", exact: true })
        .click();
    }
    await expect(page.locator("header")).toContainText(
      "ATTACK LAB — sandbox, not the real service",
    );
    await page
      .getByRole("button", { name: "Start lab session", exact: true })
      .click();
    await page.getByRole("button", { name: "Reset lab", exact: true }).click();
    await expect(page.locator("#status")).toContainText("reseeded");
    const alice = page.frameLocator("#alice"),
      bob = page.frameLocator("#bob");
    if (action === "MITM key substitution") {
      await page.getByRole("button", { name: action, exact: true }).click();
      await page
        .getByRole("button", { name: "Connect victims", exact: true })
        .click();
      await expect(bob.locator(".session-divider")).toContainText(
        "signature_failed",
      );
      await expect(page.locator("#detections")).toContainText(
        "handshake_aborted",
      );
      return;
    }
    if (action === "Login brute-force / lockout") {
      await page.getByRole("button", { name: action, exact: true }).click();
      await expect(alice.locator(".feedback")).toContainText("locked");
      await expect(page.locator("#detections")).toContainText(
        "lockout_rejected",
      );
      return;
    }
    await page
      .getByRole("button", { name: "Connect victims", exact: true })
      .click();
    await expect(alice.getByLabel("Message", { exact: true })).toBeEnabled();
    await expect(bob.getByLabel("Message", { exact: true })).toBeEnabled();
    if (action === "Replay old envelope") {
      await page
        .getByRole("button", { name: "Send next message", exact: true })
        .click();
      await expect(
        bob.getByRole("button", {
          name: "Security receipt: Sandbox message 1",
          exact: true,
        }),
      ).toBeVisible();
    }
    await page.getByRole("button", { name: action, exact: true }).click();
    if (action !== "Replay old envelope") {
      await page
        .getByRole("button", { name: "Send next message", exact: true })
        .click();
      if (action === "Drop next message" || action === "Reorder next messages")
        await page
          .getByRole("button", { name: "Send follow-up message", exact: true })
          .click();
    }
    await expect(bob.locator(".session-divider")).toContainText(reason);
    await expect(page.locator("#detections")).toContainText(reason);
    expect(await page.locator("#wire").innerText()).not.toContain(
      "Sandbox message",
    );
    expect(await page.locator("#wire").innerText()).not.toContain(
      "Lab-Password-1234!",
    );
  });

for (const [action, sends] of [
  ["Tamper stored attachment", 1],
  ["Swap attachment object", 2],
] as const)
  test("real victim detection: " + action, async ({ page }) => {
    await page.goto("/");
    const gate = page.getByLabel("Lab access code", { exact: true });
    if (await gate.isVisible()) {
      await gate.fill(
        process.env.LAB_ACCESS_CODE || "Local-test-access-code-ONLY-1234",
      );
      await page
        .getByRole("button", { name: "Enter sandbox", exact: true })
        .click();
    }
    await page
      .getByRole("button", { name: "Start lab session", exact: true })
      .click();
    await page.getByRole("button", { name: "Reset lab", exact: true }).click();
    await expect(page.locator("#status")).toContainText("reseeded");
    const alice = page.frameLocator("#alice"),
      bob = page.frameLocator("#bob");
    await page
      .getByRole("button", { name: "Connect victims", exact: true })
      .click();
    await expect(alice.getByLabel("Message", { exact: true })).toBeEnabled();
    await expect(bob.getByLabel("Message", { exact: true })).toBeEnabled();
    for (let i = 1; i <= sends; i++) {
      await page
        .getByRole("button", { name: "Alice sends test image", exact: true })
        .click();
      await expect(bob.getByTestId("attachment")).toHaveCount(i);
    }
    await page.getByRole("button", { name: action, exact: true }).click();
    await page
      .getByRole("button", { name: "Bob opens newest attachment", exact: true })
      .click();
    await expect(
      bob.getByRole("alert").filter({ hasText: "tampered or corrupted" }),
    ).toBeVisible();
    await expect(page.locator("#detections")).toContainText(
      "attachment_rejected",
    );
    await expect(page.locator("#attempts")).toContainText(
      action.startsWith("Tamper") ? "tamper_attachment" : "swap_attachment",
    );
    expect(await page.locator("#wire").innerText()).not.toContain("lab-");
  });

test("untouched lab attachment opens (control for the attachment attacks)", async ({
  page,
}) => {
  await page.goto("/");
  const gate = page.getByLabel("Lab access code", { exact: true });
  if (await gate.isVisible()) {
    await gate.fill(
      process.env.LAB_ACCESS_CODE || "Local-test-access-code-ONLY-1234",
    );
    await page
      .getByRole("button", { name: "Enter sandbox", exact: true })
      .click();
  }
  await page
    .getByRole("button", { name: "Start lab session", exact: true })
    .click();
  await page.getByRole("button", { name: "Reset lab", exact: true }).click();
  await expect(page.locator("#status")).toContainText("reseeded");
  const alice = page.frameLocator("#alice"),
    bob = page.frameLocator("#bob");
  await page
    .getByRole("button", { name: "Connect victims", exact: true })
    .click();
  await expect(alice.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(bob.getByLabel("Message", { exact: true })).toBeEnabled();
  await page
    .getByRole("button", { name: "Alice sends test image", exact: true })
    .click();
  await expect(bob.getByTestId("attachment")).toHaveCount(1);
  await page
    .getByRole("button", { name: "Bob opens newest attachment", exact: true })
    .click();
  await expect(bob.getByRole("dialog", { name: "Image viewer" })).toBeVisible();
  await expect(page.locator("#detections")).not.toContainText(
    "attachment_rejected",
  );
});

// ---- voice-call attacks (fake microphone: Chromium; WebKit has none) ----------
async function enter(page: any) {
  await page.goto("/");
  const gate = page.getByLabel("Lab access code", { exact: true });
  if (await gate.isVisible()) {
    await gate.fill(
      process.env.LAB_ACCESS_CODE || "Local-test-access-code-ONLY-1234",
    );
    await page
      .getByRole("button", { name: "Enter sandbox", exact: true })
      .click();
  }
  await page
    .getByRole("button", { name: "Start lab session", exact: true })
    .click();
  await page.getByRole("button", { name: "Reset lab", exact: true }).click();
  await expect(page.locator("#status")).toContainText("reseeded");
  await page
    .getByRole("button", { name: "Connect victims", exact: true })
    .click();
  const alice = page.frameLocator("#alice"),
    bob = page.frameLocator("#bob");
  await expect(alice.getByLabel("Message", { exact: true })).toBeEnabled();
  await expect(bob.getByLabel("Message", { exact: true })).toBeEnabled();
  return { alice, bob };
}
const callPanel = (f: any) => f.getByRole("dialog", { name: "Voice call" });
const needsMic = (browserName: string) =>
  test.skip(browserName !== "chromium", "WebKit has no fake microphone");

test("control: a normal call connects in the lab with a matching DTLS fingerprint", async ({
  page,
  browserName,
}) => {
  needsMic(browserName);
  const { alice, bob } = await enter(page);
  await page
    .getByRole("button", { name: "Alice calls Bob", exact: true })
    .click();
  await expect(callPanel(bob)).toContainText("Incoming call");
  await page
    .getByRole("button", { name: "Bob accepts call", exact: true })
    .click();
  await expect(callPanel(bob).getByTestId("call-fp")).toContainText("matches", {
    timeout: 20000,
  });
  await expect(callPanel(alice).getByTestId("call-fp")).toContainText(
    "matches",
    { timeout: 20000 },
  );
  await expect(page.locator("#detections")).not.toContainText(
    "fingerprint_mismatch",
  );
  expect(await page.locator("#wire").innerText()).not.toContain("m=audio");
});

test("real victim detection: Substitute DTLS fingerprint in SDP", async ({
  page,
  browserName,
}) => {
  needsMic(browserName);
  const { bob } = await enter(page);
  await page
    .getByRole("button", {
      name: "Substitute DTLS fingerprint in SDP",
      exact: true,
    })
    .click();
  await page
    .getByRole("button", { name: "Alice calls Bob", exact: true })
    .click();
  await expect(page.locator("#detections")).toContainText("decryption_failed");
  await expect(callPanel(bob)).toHaveCount(0); // the edited offer never rings
});

test("real victim detection: Inject forged call offer", async ({ page }) => {
  const { bob } = await enter(page);
  await page
    .getByRole("button", { name: "Inject forged call offer", exact: true })
    .click();
  await expect(page.locator("#detections")).toContainText("decryption_failed");
  await expect(callPanel(bob)).toHaveCount(0);
});

test("real victim detection: Replay old call offer", async ({
  page,
  browserName,
}) => {
  needsMic(browserName);
  const { alice, bob } = await enter(page);
  await page
    .getByRole("button", { name: "Alice calls Bob", exact: true })
    .click();
  await expect(callPanel(bob)).toContainText("Incoming call");
  await page
    .getByRole("button", { name: "Bob accepts call", exact: true })
    .click();
  await expect(callPanel(bob).getByTestId("call-fp")).toContainText("matches", {
    timeout: 20000,
  });
  await page.getByRole("button", { name: "Hang up", exact: true }).click();
  await expect(callPanel(bob)).toHaveCount(0);
  await page
    .getByRole("button", { name: "Replay old call offer", exact: true })
    .click();
  await expect(page.locator("#detections")).toContainText("replay_duplicate");
  await expect(callPanel(bob)).toHaveCount(0); // the replayed offer never rings again
  void alice;
});

test("real victim detection: MITM media path (other DTLS certificate)", async ({
  page,
  browserName,
}) => {
  needsMic(browserName);
  const { bob } = await enter(page);
  await page
    .getByRole("button", {
      name: "MITM media path (other DTLS certificate)",
      exact: true,
    })
    .click();
  await page
    .getByRole("button", { name: "Alice calls Bob", exact: true })
    .click();
  await expect(callPanel(bob)).toContainText("Incoming call");
  await page
    .getByRole("button", { name: "Bob accepts call", exact: true })
    .click();
  await expect(
    bob.getByRole("alert").filter({
      hasText: "does not match the fingerprint your contact signed",
    }),
  ).toBeVisible({ timeout: 20000 });
  await expect(page.locator("#detections")).toContainText(
    "call_fingerprint_mismatch",
  );
  await expect(callPanel(bob)).toHaveCount(0);
});
