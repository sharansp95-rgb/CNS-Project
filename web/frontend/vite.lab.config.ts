import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";
export default defineConfig({
  root: fileURLToPath(new URL("../../attack_lab/frontend", import.meta.url)),
  build: {
    outDir: "../static",
    emptyOutDir: true,
    assetsDir: "console-assets",
  },
});
