import {
  test,
  expect,
} from "../../web/frontend/node_modules/@playwright/test/index.mjs";
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
