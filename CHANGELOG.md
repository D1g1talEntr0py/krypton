## [2.0.0](https://github.com/D1g1talEntr0py/krypton/compare/v1.0.0...v2.0.0) (2026-03-16)

### ⚠ BREAKING CHANGES

* Library rewritten in TypeScript with new modular API.
Individual cipher classes replace the single Krypton class.

### Features

* rewrite in TypeScript with modular cipher architecture (502f6d41590c2dcb940a4252829741c4f68df792)
- Rewrite entire library from JavaScript to TypeScript
- Split monolithic krypton.js into modular cipher classes:
  AES, ECDH, ECDSA, HMAC, and RSA
- Add strong typing with dedicated types module
- Add barrel export via index.ts


### Documentation

* update README and add release process guide (ca9c9cc8de309207340e7db9c9737808f840822a)
- Rewrite README with updated API docs, usage examples, and badges
- Add release process documentation (docs/release-process.md)
- Add CHANGELOG.md placeholder for semantic-release


### Miscellaneous Chores

* **release:** 1.0.0 [skip ci] (35c9e737331efd853c7dcd17d46682f7b4c47563)
## 1.0.0 (2026-03-16)

### ⚠ BREAKING CHANGES

* Library rewritten in TypeScript with new modular API.
Individual cipher classes replace the single Krypton class.

### Features

* rewrite in TypeScript with modular cipher architecture (502f6d41590c2dcb940a4252829741c4f68df792)
- Rewrite entire library from JavaScript to TypeScript
- Split monolithic krypton.js into modular cipher classes:
  AES, ECDH, ECDSA, HMAC, and RSA
- Add strong typing with dedicated types module
- Add barrel export via index.ts

### Documentation

* update README and add release process guide (ca9c9cc8de309207340e7db9c9737808f840822a)
- Rewrite README with updated API docs, usage examples, and badges
- Add release process documentation (docs/release-process.md)
- Add CHANGELOG.md placeholder for semantic-release

### Miscellaneous Chores

* replace LICENSE.txt with LICENSE (19211f9a2aa39f28672812db3dff2a3e3c9b0fd4)

### Tests

* rewrite test suite in Vitest and TypeScript (19b81180cf4af6e09e2fc3c7f6d1ffb453208523)
- Migrate tests from Jest (JavaScript) to Vitest (TypeScript)
- Add dedicated test files for each cipher module:
  ECDH, ECDSA, HMAC, RSA, and Krypton
- Remove legacy krypton.test.js

### Build System

* add .npmrc to fix frozen lockfile config mismatch (8941ddcec55a4c00e76a2490eb545d630fa12e04)
* migrate to pnpm and TypeScript toolchain (6b49021cbbaf632b868c270db8f0f26199c32178)
- Replace npm with pnpm as package manager
- Add TypeScript config (tsconfig.json) and build tooling (@d1g1tal/tsbuild)
- Migrate ESLint from .eslintrc.json to flat config (eslint.config.js)
- Replace Jest with Vitest for testing (vitest.config.ts)
- Update package.json with ESM exports, type declarations, and new scripts
- Remove legacy jsconfig.json and package-lock.json

* move autoInstallPeers config to pnpm-workspace.yaml (57ed8dbc27854242ce52d5aea299f64f396a0f1c)

### Continuous Integration

* add GitHub Actions workflows and release automation (a4bf9b80de122d3af911c8cdc6ed58adf7e00fe2)
- Add CI workflow (ci.yml) for lint, type-check, tests across Node 20/22/24
- Add publish workflow (publish.yml) with semantic-release
- Add semantic-release config (.releaserc.json) with conventional commits
- Add commit-msg git hook to enforce conventional commit format

* configure npm trusted publishing (45cc98f2e7f58a0d00c9f9de712978b8a958b2ce)
* fix publish workflow install step (9829ebc258ec55f0a6334b62b5e064a867a58cba)
* remove always-auth warning and fix package scope (76e675be8e34443060464e12b26ceaef9f687c1b)
* remove invalid .npmrc (67543e1d97bad8a384c242fbd861063d298d91b8)
* restore publish workflow config (f47aeec4c2a64e94a7edadcfd6ddca90b8f4547f)

* replace LICENSE.txt with LICENSE (19211f9a2aa39f28672812db3dff2a3e3c9b0fd4)
* trigger release (bcb1d5d3bcd2b17580982e10bf2c318ecb377c53)

### Tests

* rewrite test suite in Vitest and TypeScript (19b81180cf4af6e09e2fc3c7f6d1ffb453208523)
- Migrate tests from Jest (JavaScript) to Vitest (TypeScript)
- Add dedicated test files for each cipher module:
  ECDH, ECDSA, HMAC, RSA, and Krypton
- Remove legacy krypton.test.js


### Build System

* add .npmrc to fix frozen lockfile config mismatch (8941ddcec55a4c00e76a2490eb545d630fa12e04)
* move autoInstallPeers config to pnpm-workspace.yaml (57ed8dbc27854242ce52d5aea299f64f396a0f1c)

### Continuous Integration

* add GitHub Actions workflows and release automation (a4bf9b80de122d3af911c8cdc6ed58adf7e00fe2)
- Add CI workflow (ci.yml) for lint, type-check, tests across Node 20/22/24
- Add publish workflow (publish.yml) with semantic-release
- Add semantic-release config (.releaserc.json) with conventional commits
- Add commit-msg git hook to enforce conventional commit format

* configure npm trusted publishing (45cc98f2e7f58a0d00c9f9de712978b8a958b2ce)
* fix publish workflow install step (9829ebc258ec55f0a6334b62b5e064a867a58cba)
* remove always-auth warning and fix package scope (76e675be8e34443060464e12b26ceaef9f687c1b)
* remove invalid .npmrc (67543e1d97bad8a384c242fbd861063d298d91b8)
* restore publish workflow config (f47aeec4c2a64e94a7edadcfd6ddca90b8f4547f)

## 1.0.0 (2026-03-16)

### ⚠ BREAKING CHANGES

* Library rewritten in TypeScript with new modular API.
Individual cipher classes replace the single Krypton class.

### Features

* rewrite in TypeScript with modular cipher architecture (502f6d41590c2dcb940a4252829741c4f68df792)
- Rewrite entire library from JavaScript to TypeScript
- Split monolithic krypton.js into modular cipher classes:
  AES, ECDH, ECDSA, HMAC, and RSA
- Add strong typing with dedicated types module
- Add barrel export via index.ts


### Documentation

* update README and add release process guide (ca9c9cc8de309207340e7db9c9737808f840822a)
- Rewrite README with updated API docs, usage examples, and badges
- Add release process documentation (docs/release-process.md)
- Add CHANGELOG.md placeholder for semantic-release


### Miscellaneous Chores

* replace LICENSE.txt with LICENSE (19211f9a2aa39f28672812db3dff2a3e3c9b0fd4)

### Tests

* rewrite test suite in Vitest and TypeScript (19b81180cf4af6e09e2fc3c7f6d1ffb453208523)
- Migrate tests from Jest (JavaScript) to Vitest (TypeScript)
- Add dedicated test files for each cipher module:
  ECDH, ECDSA, HMAC, RSA, and Krypton
- Remove legacy krypton.test.js


### Build System

* add .npmrc to fix frozen lockfile config mismatch (8941ddcec55a4c00e76a2490eb545d630fa12e04)
* migrate to pnpm and TypeScript toolchain (6b49021cbbaf632b868c270db8f0f26199c32178)
- Replace npm with pnpm as package manager
- Add TypeScript config (tsconfig.json) and build tooling (@d1g1tal/tsbuild)
- Migrate ESLint from .eslintrc.json to flat config (eslint.config.js)
- Replace Jest with Vitest for testing (vitest.config.ts)
- Update package.json with ESM exports, type declarations, and new scripts
- Remove legacy jsconfig.json and package-lock.json

* move autoInstallPeers config to pnpm-workspace.yaml (57ed8dbc27854242ce52d5aea299f64f396a0f1c)

### Continuous Integration

* add GitHub Actions workflows and release automation (a4bf9b80de122d3af911c8cdc6ed58adf7e00fe2)
- Add CI workflow (ci.yml) for lint, type-check, tests across Node 20/22/24
- Add publish workflow (publish.yml) with semantic-release
- Add semantic-release config (.releaserc.json) with conventional commits
- Add commit-msg git hook to enforce conventional commit format

* configure npm trusted publishing (45cc98f2e7f58a0d00c9f9de712978b8a958b2ce)
* fix publish workflow install step (9829ebc258ec55f0a6334b62b5e064a867a58cba)
* remove always-auth warning and fix package scope (76e675be8e34443060464e12b26ceaef9f687c1b)
* remove invalid .npmrc (67543e1d97bad8a384c242fbd861063d298d91b8)
* restore publish workflow config (f47aeec4c2a64e94a7edadcfd6ddca90b8f4547f)

## 1.0.0 (2026-03-16)

### ⚠ BREAKING CHANGES

* Library rewritten in TypeScript with new modular API.
Individual cipher classes replace the single Krypton class.

### Features

* rewrite in TypeScript with modular cipher architecture (502f6d41590c2dcb940a4252829741c4f68df792)
- Rewrite entire library from JavaScript to TypeScript
- Split monolithic krypton.js into modular cipher classes:
  AES, ECDH, ECDSA, HMAC, and RSA
- Add strong typing with dedicated types module
- Add barrel export via index.ts


### Documentation

* update README and add release process guide (ca9c9cc8de309207340e7db9c9737808f840822a)
- Rewrite README with updated API docs, usage examples, and badges
- Add release process documentation (docs/release-process.md)
- Add CHANGELOG.md placeholder for semantic-release


### Miscellaneous Chores

* replace LICENSE.txt with LICENSE (19211f9a2aa39f28672812db3dff2a3e3c9b0fd4)

### Tests

* rewrite test suite in Vitest and TypeScript (19b81180cf4af6e09e2fc3c7f6d1ffb453208523)
- Migrate tests from Jest (JavaScript) to Vitest (TypeScript)
- Add dedicated test files for each cipher module:
  ECDH, ECDSA, HMAC, RSA, and Krypton
- Remove legacy krypton.test.js


### Build System

* add .npmrc to fix frozen lockfile config mismatch (8941ddcec55a4c00e76a2490eb545d630fa12e04)
* migrate to pnpm and TypeScript toolchain (6b49021cbbaf632b868c270db8f0f26199c32178)
- Replace npm with pnpm as package manager
- Add TypeScript config (tsconfig.json) and build tooling (@d1g1tal/tsbuild)
- Migrate ESLint from .eslintrc.json to flat config (eslint.config.js)
- Replace Jest with Vitest for testing (vitest.config.ts)
- Update package.json with ESM exports, type declarations, and new scripts
- Remove legacy jsconfig.json and package-lock.json


### Continuous Integration

* add GitHub Actions workflows and release automation (a4bf9b80de122d3af911c8cdc6ed58adf7e00fe2)
- Add CI workflow (ci.yml) for lint, type-check, tests across Node 20/22/24
- Add publish workflow (publish.yml) with semantic-release
- Add semantic-release config (.releaserc.json) with conventional commits
- Add commit-msg git hook to enforce conventional commit format
