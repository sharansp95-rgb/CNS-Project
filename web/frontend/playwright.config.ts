import { defineConfig } from "@playwright/test";
const browsers = ["chromium", "firefox", "webkit"] as const;
const external = process.env.BASE_URL;
export default defineConfig({
  testDir: "e2e",
  timeout: external ? 120000 : 45000,
  workers: 1,
  expect: { timeout: external ? 30000 : 10000 },
  use: { headless: true, trace: external ? "off" : "retain-on-failure" },
  projects: browsers.map((browserName, index) => ({
    name: browserName,
    use: {
      browserName,
      // Fake microphone for call tests (Chromium only; WebKit has no fake-device switch).
      ...(browserName === "chromium"
        ? {
            launchOptions: {
              args: [
                "--use-fake-device-for-media-stream",
                "--use-fake-ui-for-media-stream",
                "--disable-features=WebRtcHideLocalIpsWithMdns",
              ],
            },
            permissions: ["microphone"],
          }
        : {}),
      baseURL: external || `http://127.0.0.1:${8765 + index * 2}`,
    },
  })),
  webServer: external
    ? undefined
    : browsers.map((_, index) => ({
        command: "../../.venv/bin/python tests/run_server.py",
        env: { CNS_TEST_PORT: String(8765 + index * 2) },
        url: `http://127.0.0.1:${8765 + index * 2}`,
        reuseExistingServer: false,
        timeout: 30000,
      })),
});
