import { defineConfig } from "@playwright/test";
// Browser network-attacker rig: HTTPS/WSS gateway behind Mallory's TLS-blind proxy.
const base = 8861;
export default defineConfig({
  testDir: "e2e-netattack",
  timeout: 90000,
  workers: 1,
  expect: { timeout: 15000 },
  use: {
    headless: true,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    launchOptions: {
      args: [
        "--use-fake-device-for-media-stream",
        "--use-fake-ui-for-media-stream",
        "--disable-features=WebRtcHideLocalIpsWithMdns",
      ],
    },
    permissions: ["microphone"],
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: {
    command: "../../.venv/bin/python tests/run_netattack.py",
    env: { CNS_NETATTACK_BASE: String(base) },
    url: `http://127.0.0.1:${base + 2}/`,
    reuseExistingServer: false,
    timeout: 40000,
  },
});
