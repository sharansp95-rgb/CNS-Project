import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "../../attack_lab/e2e",
  timeout: 45000,
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:8766",
    headless: true,
    trace: "retain-on-failure",
  },
  outputDir: "../../attack_lab/test-results",
  webServer: {
    command: "../../.venv/bin/python ../../attack_lab/tests/run_server.py",
    url: "http://127.0.0.1:8766",
    reuseExistingServer: false,
    timeout: 30000,
  },
});
