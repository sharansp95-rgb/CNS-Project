import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const runId = Date.now().toString(36);
const password = "Accessibility-demo-password-42!";
test("onboarding and public verification meet automated WCAG AA checks in both themes", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("list", { name: "Getting started" }),
  ).toContainText("Your secure session");
  for (const theme of ["dark", "light"]) {
    if (theme === "light")
      await page
        .getByRole("button", { name: "Toggle theme", exact: true })
        .click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  }
  await page.goto("/verify");
  await expect(
    page.getByRole("heading", { name: "Verify evidence", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Toggle theme", exact: true }),
  ).toBeVisible();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
});

test("keyboard skip link focuses the main content", async ({
  page,
  browserName,
}) => {
  await page.goto("/");
  // Safari's default macOS setting uses Option-Tab to include links/buttons.
  await page.keyboard.press(browserName === "webkit" ? "Alt+Tab" : "Tab");
  await expect(
    page.getByRole("link", { name: "Skip to main content" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
});

test("chat receipts trap and restore keyboard focus", async ({ browser }) => {
  const contexts = await Promise.all([
    browser.newContext(),
    browser.newContext(),
  ]);
  const pages = await Promise.all(contexts.map((context) => context.newPage()));
  const prefix = `${browser.browserType().name()}_${runId}_a11y_`;
  try {
    for (const [index, page] of pages.entries()) {
      await page.goto("/");
      await page.getByLabel("Username", { exact: true }).fill(prefix + index);
      await page.getByLabel("Password", { exact: true }).fill(password);
      await page
        .getByLabel("Peer username", { exact: true })
        .fill(prefix + (1 - index));
      await page
        .getByRole("button", { name: "Create an identity", exact: true })
        .click();
    }
    const [a, b] = pages;
    await expect(a.getByLabel("Message", { exact: true })).toBeEnabled();
    await a
      .getByLabel("Message", { exact: true })
      .fill("A readable, verifiable conversation.");
    await a.getByRole("button", { name: "Send message", exact: true }).click();
    const message = b.getByRole("button", {
      name: "Security receipt: A readable, verifiable conversation.",
      exact: true,
    });
    await message.click();
    const close = b.getByRole("button", { name: "Close receipt", exact: true });
    await expect(close).toBeFocused();
    await b.keyboard.press("Tab");
    await expect(close).toBeFocused();
    await b.keyboard.press("Shift+Tab");
    await expect(close).toBeFocused();
    expect(
      (
        await new AxeBuilder({ page: b })
          .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
          .analyze()
      ).violations,
    ).toEqual([]);
    await b.keyboard.press("Escape");
    await expect(message).toBeFocused();
    for (const theme of ["dark", "light"]) {
      if (theme === "light")
        await b
          .getByRole("button", { name: "Toggle theme", exact: true })
          .click();
      expect(
        (
          await new AxeBuilder({ page: b })
            .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
            .analyze()
        ).violations,
      ).toEqual([]);
    }
    await expect(b.getByLabel("Message", { exact: true })).toBeEnabled();
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
  }
});
