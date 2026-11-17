import { defineConfig } from "@playwright/test";
const external = process.env.LAB_URL;
const browsers = ["chromium", "firefox", "webkit"] as const;
export default defineConfig({
  testDir: "../../attack_lab/e2e",
  timeout: external ? 120000 : 45000,
  workers: 1,
  expect: { timeout: external ? 30000 : 10000 },
  use: { headless: true, trace: external ? "off" : "retain-on-failure" },
  projects: browsers.map((browserName, index) => ({
    name: browserName,
    use: {
      browserName,
      baseURL: external || `http://127.0.0.1:${8766 + index * 2}`,
    },
  })),
  outputDir: "../../attack_lab/test-results",
  webServer: external
    ? undefined
    : browsers.map((_, index) => ({
        command: "../../.venv/bin/python ../../attack_lab/tests/run_server.py",
        env: { CNS_TEST_LAB_PORT: String(8766 + index * 2) },
        url: `http://127.0.0.1:${8766 + index * 2}`,
        reuseExistingServer: false,
        timeout: 30000,
      })),
});
