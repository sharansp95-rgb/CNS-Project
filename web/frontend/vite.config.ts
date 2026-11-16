import { defineConfig } from "vite";
export default defineConfig({
  build: { outDir: "../static", emptyOutDir: true },
  server: { proxy: { "/ws": { target: "ws://127.0.0.1:8080", ws: true } } },
});
