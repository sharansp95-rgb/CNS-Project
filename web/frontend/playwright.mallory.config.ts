import { defineConfig } from "@playwright/test";
// Simple Mallory demo: the real web chat served by the lab relay + Mallory's window.
const chat = 8871;
export default defineConfig({
  testDir: "e2e-mallory",
  timeout: 90000,
  workers: 1,
  expect: { timeout: 15000 },
  use: { headless: true, trace: "retain-on-failure" },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "webkit", use: { browserName: "webkit" } },
  ],
  webServer: {
    command: `.venv/bin/python -m attack_lab.simple --port ${chat} --mallory-port ${chat + 1}`,
    cwd: "../..",
    url: `http://127.0.0.1:${chat + 1}/`,
    reuseExistingServer: false,
    timeout: 40000,
  },
});
