import { ESLint } from "eslint";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const eslint = new ESLint({ cwd: root });
const results = await eslint.lintFiles([
  "web/frontend/src",
  "web/frontend/tests",
  "web/frontend/e2e",
  "web/frontend/*.ts",
  "attack_lab/frontend",
  "attack_lab/e2e",
]);
const formatter = await eslint.loadFormatter("stylish");
const output = formatter.format(results);
if (output) process.stdout.write(output);
if (results.some((r) => r.errorCount || r.warningCount)) process.exitCode = 1;
