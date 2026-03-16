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
