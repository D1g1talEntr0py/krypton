## [4.0.0](https://github.com/D1g1talEntr0py/krypton/compare/v3.0.0...v4.0.0) (2026-11-09)

### ⚠ BREAKING CHANGES

* **crypto:** make digest data-first

### Features

* **api:** load cipher modules on demand (13f3f116b39ad2d66c855fddf1a060b33396bc61)
- Load cipher modules on first use
- Expose cipher classes through dedicated subpath exports
- Document subpath imports and remove the old barrel entrypoint

* **crypto:** add byte decryption and validate key inputs (acc28eb3a57b23205b3c26c9c9bb50b81d13ab78)
- add byte-preserving decryption methods to the static, AES, and RSA APIs
- select key usages by algorithm and require explicit asymmetric import usages
- validate random request sizes before allocation and support cross-realm AES buffers
- document the APIs and add regression tests

* **crypto:** make digest data-first (a5b6ffb1b07af0f0bb6849b7c0d72d3afa291f15)
- make digest accept data first and default to SHA-256
- remove the invalid KeyUsage.digest constant and update callers and tests
- refresh README and release instructions for current versions and package details

* **crypto:** type factory options by algorithm (8b56bd21e32de28056888bb6c7f799a0aec1fe99)
- add an exported options map derived from cipher factory signatures
- constrain Krypton.create options to the selected algorithm
- add compile-only assertions for valid and invalid options


### Bug Fixes

* **ciphers:** honor key generation options (b87cc87e8b59371bfde52e68a2f695772894db6b)
- Pass the requested curve to ECDSA key generation
- Pass the requested hash and modulus length to RSA key generation
- Test custom ECDSA and RSA key parameters

* **ciphers:** validate algorithm-specific options (4e4f69ecf75c5d1b80fadf8e0d3fa820ce719a5c)
- Reject additional data for AES-CBC and AES-CTR
- Default derived HMAC keys to sign and verify usages
- Reject incomplete RSA key pairs
- Test supported options and defaults

* **publish:** specify version for conventional-changelog-conventionalcommits in semantic-release (e444dfc31ea3a37c7ca43b6aafc30bc006a51622)
* **tsconfig:** ensure target is set to ES2022 (f440fbd1a290325b40f2b1635489b0f4d3d9a670)

### Code Refactoring

* **crypto:** avoid AES decryption copies and reuse RSA fixtures (7d83018dfe0dfe96dcb47d781ba26272e85ab442)
- pass IV and ciphertext subarray views to Web Crypto
- share a default RSA key pair across tests while preserving default and custom key generation coverage

* **crypto:** encapsulate internals with [#private](https://github.com/D1g1talEntr0py/krypton/issues/private) fields (4cccb203eaa6070a049ea329aba1603422ae0694)
- Replace TypeScript-only private state and helpers with native runtime-private members
- Add reflection tests for cipher state and internal helpers


### Documentation

* **README:** clarify RSA-OAEP limits and ECDH key agreement context (80540c6a67d236acca5b989c18bf8a55e27cf451)

### Miscellaneous Chores

* **toolchain:** upgrade Node, pnpm and build tooling (52ab16949752eef870ce702f25b3faab39d4047b)
- Upgrade Node and pnpm requirements and CI actions
- Update TypeScript, ESLint, Vitest, and build tooling
- Rename and update the TypeScript ESLint configuration
- Refresh workspace, compiler, test, and lockfile settings


### Tests

* **crypto:** cover asymmetric key imports and malformed inputs (9c6a8ac4ea5974e4baf6f2abebb060a1c4cf6740)
- add a no-emit TypeScript configuration for source and test files
- cover public and private RSA-OAEP, ECDSA, and ECDH imports across JWK, SPKI, and PKCS8
- reject malformed asymmetric keys and RSA ciphertext
- guard tampered signature mutations against unchecked index access

* **crypto:** verify vectors and add browser integration coverage (176facd74464691e322d15ca4af563d0fe07eb12)
- verify AES-GCM, HMAC-SHA-256, and SHA-256 against published vectors
- assert exact AES-CBC/CTR/GCM wire lengths and native Web Crypto interoperability
- add isolated Chromium tests using Vitest and Playwright
- run browser tests in CI and release validation on Node 24

* **package:** validate published TypeScript declarations (05e6a6f7d9e716f3d7e3f255940c699956806bc3)
- Add a consumer fixture for root and cipher subpath exports
- Check public signatures and algorithm-specific options against built declarations
- Run the consumer check from the existing package smoke-test command


### Continuous Integration

* **package:** validate package exports before release (28ec2923f6b87db4784fdbf4207d841b643cd4af)
- Add a smoke test for package exports and lazy cipher loading
- Run the package smoke test in CI and before release
- Gate publishing on validation across supported Node versions

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
