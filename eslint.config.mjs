import { js, tseslint, hooks, globals } from "./web/frontend/lint/index.mjs";
export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/test-results/**",
      "**/playwright-report/**",
      "web/static/**",
      "attack_lab/static/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["web/frontend/**/*.{ts,tsx}", "attack_lab/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { "react-hooks": hooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
  // These pre-existing dynamic objects are validated at runtime. Replacing their
  // wire/evidence/RTC types is a separate security review, not a cleanup shortcut.
  {
    files: [
      "web/frontend/src/{crypto,session,evidenceVerify,pdfReport,main}.ts*",
      "web/frontend/src/calls/{manager,sdp}.ts",
      "web/frontend/tests/**",
      "web/frontend/e2e/**",
      "attack_lab/{frontend,e2e}/**",
    ],
    rules: { "@typescript-eslint/no-explicit-any": "off" },
  },
);
