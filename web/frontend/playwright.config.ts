import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "e2e",
  timeout: 45000,
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:8765",
    headless: true,
    trace: "retain-on-failure",
  },
  webServer: {
    command: "../../.venv/bin/python tests/run_server.py",
    url: "http://127.0.0.1:8765",
    reuseExistingServer: false,
    timeout: 30000,
  },
});
