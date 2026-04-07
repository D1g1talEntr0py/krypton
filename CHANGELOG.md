## [3.0.0](https://github.com/D1g1talEntr0py/krypton/compare/v2.0.0...v3.0.0) (2026-04-07)

### ⚠ BREAKING CHANGES

* upgrade to TypeScript 6

### Bug Fixes

* **deps:** bump vite to resolve CVE-2026-39363 (0dd7478a20d26d96cffb1a8d2a238d4ed61aca68)
Updates the Vite package, which is a transitive dependency of Vitest, to address a discovered security vulnerability.
Aligns dev dependencies like TypeScript, ESLint, and Vitest to their latest compatible versions.
Synchronizes the pnpm lockfile across the workspace to reflect the updated integrity hashes and package versions.

* **release:** more fun with lockfiles and peer dependencies (ad28174ee005088435766b403e845d25a67d9fd9)

### Code Refactoring

* upgrade to TypeScript 6 (7bf48a43887c4cf58c10049d39be71cb9def2cff)
Modifies the TypeScript compiler options to use module preserve and enables consistent structure and sourcemaps.
Adds an alias for the src directory in the Vitest configuration and disables redundant typechecking during unit tests.


### Documentation

* clean up changelog (d52ee59f6e7b621a9edb198aeaf86b79d743d63f)

### Styles

* update editorconfig indent size (2ce710f4d41b1fb1c60d1f4551874e77b041f0d7)
Changes the default indentation size from 1 to 2 within the project.
Fixes irregular indentation spacing to conform to standard conventions and improve overall code readability.


### Continuous Integration

* add breaking change release rule (1763e754ed7def617f973cbf34a74abb72f74ea4)
Updates `.releaserc.json` to explicitly map breaking changes to a major version release.
Ensures correct semantic versioning and publishing processes.

* update pnpm and github workflows (c608110a95654d55a09083259b19ff4db6b2b2f2)
Upgrades setup-node and pnpm steps to their latest major versions in CI workflows.
Adjusts pnpm settings to enable autoInstallPeers globally while explicitly disabling it in the publish workflow.
Configures allowed build scripts in the workspace.

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
