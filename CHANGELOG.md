## [2.0.0](https://github.com/D1g1talEntr0py/krypton/compare/v1.0.0...v2.0.0) (2026-03-16)

### ⚠ BREAKING CHANGES

* Library rewritten in TypeScript with new modular API.
Individual cipher classes replace the single Krypton class.

### Features

* rewrite in TypeScript with modular cipher architecture
  - Rewrite entire library from JavaScript to TypeScript
  - Split monolithic krypton.js into modular cipher classes: AES, ECDH, ECDSA, HMAC, and RSA
  - Add strong typing with dedicated types module
  - Add barrel export via index.ts

### Documentation

* update README and add release process guide
  - Rewrite README with updated API docs, usage examples, and badges
  - Add release process documentation (docs/release-process.md)

### Miscellaneous Chores

* replace LICENSE.txt with LICENSE

### Tests

* rewrite test suite in Vitest and TypeScript
  - Migrate tests from Jest (JavaScript) to Vitest (TypeScript)
  - Add dedicated test files for each cipher module: ECDH, ECDSA, HMAC, RSA, and Krypton
  - Remove legacy krypton.test.js

### Build System

* migrate to pnpm and TypeScript toolchain
  - Replace npm with pnpm as package manager
  - Add TypeScript config (tsconfig.json) and build tooling (@d1g1tal/tsbuild)
  - Migrate ESLint from .eslintrc.json to flat config (eslint.config.js)
  - Replace Jest with Vitest for testing (vitest.config.ts)
  - Update package.json with ESM exports, type declarations, and new scripts
  - Remove legacy jsconfig.json and package-lock.json
* add .npmrc to fix frozen lockfile config mismatch
* move autoInstallPeers config to pnpm-workspace.yaml

### Continuous Integration

* add GitHub Actions workflows and release automation
  - Add CI workflow (ci.yml) for lint, type-check, tests across Node 20/22/24
  - Add publish workflow (publish.yml) with semantic-release
  - Add semantic-release config (.releaserc.json) with conventional commits
  - Add commit-msg git hook to enforce conventional commit format

## 1.0.0 (2026-03-16)

Initial release.
