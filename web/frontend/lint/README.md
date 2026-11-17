# Lint tooling

The application compiler remains pinned to TypeScript 7.0.2. Current typescript-eslint
8.73.0 supports TypeScript >=4.8.4 and <6.1.0, so this development-only package uses
TypeScript 6.0.3 to parse the project's existing syntax. The strict application type
check still uses TypeScript 7; this package is neither bundled nor deployed.

From web/frontend, run `npm ci`, then `npm run setup:lint` and `npm run lint`.
The separate lockfile keeps parser dependencies out of the application compiler's
module-resolution scope. No forced peer dependency installation is needed.

ESLint checks both main and lab source/tests. Narrow exceptions preserve existing
runtime-validated wire/evidence/RTC objects; changing those types is a separate
security review. All source and tests are also covered by strict `tsc --noEmit`.

Sources: https://typescript-eslint.io/users/dependency-versions/ and
https://typescript-eslint.io/getting-started/ (checked 17 November 2026).
