# Releasing agent-comms-mcp

## Prerequisites

- Write access to `redesignhealth/agent-comms-mcp`
- PyPI trusted publisher configured (already done — `publish.yml`, env `pypi`)
- GitHub `production` environment configured on the repo with required reviewers
  (gates the `deploy-prod` job — without it, prod deploys are unreviewed)
- IAM roles `rh-platform-dev-github-actions-ecr-push-role` and
  `rh-platform-github-actions-ecr-push-role` configured with ECS deploy permissions
  and correct OIDC trust policies (see deploy.yml header comments)

## Steps

1. **Bump the version** in `pyproject.toml` and `uv.lock` (run `uv lock` after editing):
   ```
   version = "X.Y.Z"
   ```

2. **Commit and push to main:**
   ```bash
   git add pyproject.toml uv.lock
   git commit -m "chore: bump version to X.Y.Z"
   git push
   ```

3. **Create a GitHub release** (full release, not pre-release):
   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes
   ```
   Or via the GitHub UI: Releases → Draft a new release → tag `vX.Y.Z`.
   **Do not check "Set as a pre-release"** — pre-releases skip `deploy.yml`.

4. **Verify both triggered workflows** pass at:
   `https://github.com/redesignhealth/agent-comms-mcp/actions`
   - `publish.yml` — publishes the Python wheel to PyPI
   - `deploy.yml` — builds the Docker image, deploys to dev ECS, then promotes to prod ECS
     (the `deploy-prod` job requires approval from a `production` environment reviewer)

5. **Confirm the package is live** on PyPI:
   ```bash
   pip index versions agent-comms-mcp
   ```

## Pre-releases

Pre-releases (GitHub "Set as a pre-release" flag) trigger `publish.yml` but **not** `deploy.yml`.
Use pre-releases to publish a wheel to PyPI for testing without touching ECS.

## Versioning

Follow [SemVer](https://semver.org/):
- **Patch** (`0.1.x`) — bug fixes, doc updates, dependency bumps
- **Minor** (`0.x.0`) — new MCP tools or message types (backwards-compatible)
- **Major** (`x.0.0`) — breaking changes to auth model, wire format, or DB schema

## Hotfix

`deploy.yml` requires a successful **push-triggered** CI run for the exact release SHA.
Hotfixes must be merged to main before cutting a release.

```bash
# 1. Branch from the last release tag
git checkout -b hotfix/vX.Y.Z vX.Y.(Z-1)

# 2. Apply the fix, commit, push
git push origin hotfix/vX.Y.Z

# 3. Open a PR targeting main and merge it
#    Wait for CI to pass on the merge commit on main.

# 4. Capture the exact merge commit SHA (avoids tagging a later commit
#    if main moved after your merge):
git fetch origin main
HOTFIX_SHA=$(gh pr view <PR_NUMBER> --json mergeCommit --jq '.mergeCommit.oid')

# 5. Create the release targeting that exact SHA
gh release create vX.Y.Z --target "$HOTFIX_SHA" --title "vX.Y.Z" --notes "..."
```

> **Important:** Use `--target "$HOTFIX_SHA"` with the merge commit OID from `gh pr view`.
> Do not use `git rev-parse origin/main` — if another PR merged after yours, that SHA
> will point at a different commit that CI hasn't validated for this release.
> If no successful push-triggered CI run is found for the release SHA, the deploy job will fail.
