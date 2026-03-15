# Release Process

## Overview

This project uses [semantic-release](https://github.com/semantic-release/semantic-release) with [Conventional Commits](https://www.conventionalcommits.org). The version number, changelog, npm publish, and GitHub release are all determined automatically from commit messages. There are no manual version bumps.

## Step-by-Step: Making a Release

### 1. Write Code on a Feature Branch

```sh
git checkout -b feat/my-feature
```

### 2. Commit Using Conventional Commit Messages

Every commit message must follow the format:

```
type(optional-scope): description
```

**Types that trigger a release:**

| Type | Bump | Example |
|---|---|---|
| `feat` | Minor (`1.x.0`) | `feat: add watch mode` |
| `fix` | Patch (`1.0.x`) | `fix: resolve path edge case` |
| `perf` | Patch (`1.0.x`) | `perf: cache module resolution` |
| `refactor` | Patch (`1.0.x`) | `refactor: simplify bundler` |
| `revert` | Patch (`1.0.x`) | `revert: undo feature X` |

**Types that do NOT trigger a release:**

| Type | Example |
|---|---|
| `docs` | `docs: update README` |
| `style` | `style: fix formatting` |
| `chore` | `chore: update deps` |
| `test` | `test: add bundler tests` |
| `build` | `build: update esbuild config` |
| `ci` | `ci: fix workflow` |

**Breaking changes** (major bump `x.0.0`):

Add `!` after the type, or include a `BREAKING CHANGE:` footer:

```
feat!: drop Node 18 support

BREAKING CHANGE: Minimum Node.js version is now 20.16.0.
```

### 3. Push and Open a Pull Request

```sh
git push -u origin feat/my-feature
```

Open a PR targeting `main`. The CI workflow runs lint, type-check, tests, and build across Node.js 20, 22, and 24. All checks must pass.

### 4. Merge to `main`

Merge the PR (squash or merge commit — both work). The commit message(s) on `main` are what semantic-release reads, so:

- **Squash merge**: Edit the squash commit message to use the correct conventional commit format.
- **Merge commit**: Each individual commit on the branch is analyzed, so they should all follow the format.

### 5. Automated Release (Hands-Off)

After the merge, the `publish.yml` workflow triggers automatically and does everything:

1. Analyzes all commits since the last git tag
2. Determines the version bump (or skips if no release-worthy commits)
3. Updates `CHANGELOG.md` with grouped release notes
4. Bumps `version` in `package.json`
5. Publishes to npm with provenance attestation via Trusted Publishers
6. Commits `CHANGELOG.md` and `package.json` back to `main` with `[skip ci]`
7. Creates a git tag (e.g., `v1.2.0`)
8. Creates a GitHub Release with the release notes

### 6. Verify

- Check the [Actions tab](../../actions) for the workflow run
- Check [npm](https://www.npmjs.com/package/@d1g1tal/tsbuild) for the published version
- Check [Releases](../../releases) for the GitHub release

## Dry Run (Local Testing)

To preview what semantic-release would do without actually publishing:

```sh
npx semantic-release --dry-run
```

This requires `GITHUB_TOKEN` to be set in your environment (for reading tags/commits).

## Troubleshooting

**No release was created after merging:**
- The commits on `main` don't include any release-worthy types. Only `feat`, `fix`, `perf`, `refactor`, and `revert` trigger releases.

**Wrong version bump:**
- Check the commit messages. A `feat` always bumps minor, a `fix`/`refactor`/`perf` always bumps patch, and `BREAKING CHANGE` always bumps major.

**npm publish failed:**
- Verify the `npm` environment exists in the repo's GitHub Settings → Environments.
- Verify Trusted Publishing is configured on npmjs.com for this repo and the `publish.yml` workflow.
