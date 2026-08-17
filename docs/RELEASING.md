# Releasing agent-comms-mcp

## Prerequisites

- Write access to `redesignhealth/agent-comms-mcp`
- PyPI trusted publisher configured (already done — `publish.yml`, env `pypi`)
- GitHub `production` environment configured on the repo with required reviewers
  (gates the `deploy-prod` job — without it, prod deploys are unreviewed)
- IAM roles configured on RH's private infra side, trusting only this repo's own
  CI (see `deploy.yml`'s header comment for the trust split) -- these are already
  set up; no action needed here.
- **`deploy.yml` only builds and pushes images to ECR — it does not deploy to
  ECS.** After both `deploy-dev` and `deploy-prod` succeed, the actual ECS
  deployment is a **manual step performed by RH staff** against RH's private
  infra (this is deliberate, not a gap — see `deploy.yml`'s header comment for
  why an automated cross-repo dispatch from this public repo was rejected).
  See RH's internal ops runbook for the exact procedure; ping an RH maintainer
  if you don't have access to it.

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

3. **Wait for CI to pass** on the version bump commit before creating the release.
   `deploy.yml` checks for a successful CI run on the exact release SHA — creating a
   release before CI finishes causes the deploy job to fail immediately.
   ```bash
   RELEASE_SHA=$(git rev-parse HEAD)
   gh run watch \
     "$(gh run list --workflow ci.yml --event push --branch main \
          --commit "$RELEASE_SHA" --limit 1 --json databaseId --jq '.[0].databaseId')" \
     --exit-status
   ```

4. **Create a GitHub release** (full release, not pre-release):
   ```bash
   # Use --target to pin the exact commit — avoids tagging the wrong commit
   # if main moves (e.g. another merge) between your push and the release.
   gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes --target "$RELEASE_SHA"
   ```
   Or via the GitHub UI: Releases → Draft a new release → tag `vX.Y.Z`, set
   **Target** to the version-bump commit SHA.
   **Do not check "Set as a pre-release"** — pre-releases skip `deploy.yml`.

5. **Verify both triggered workflows** pass at:
   `https://github.com/redesignhealth/agent-comms-mcp/actions`
   - `publish.yml` — publishes the Python wheel to PyPI
   - `deploy.yml` — builds the Docker image and pushes it to dev ECR, then promotes to prod ECR
     (the `deploy-prod` job requires approval from a `production` environment reviewer). This
     workflow does not deploy to ECS at all — see step 7.

6. **Confirm the package is live** on PyPI:
   ```bash
   pip index versions agent-comms-mcp
   ```

7. **Deploy to ECS (RH staff only, manual, required):** once both ECR pushes above are
   confirmed green, follow RH's internal ops runbook to actually roll the new image out to
   ECS — this is a deliberate manual step, not an oversight (see `deploy.yml`'s header
   comment). The release is **not** live in either environment until this step is done.

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
#    if main moved after your merge). Replace <PR_NUMBER> with your PR number.
HOTFIX_SHA=$(gh pr view <PR_NUMBER> --json mergeCommit --jq '.mergeCommit.oid // empty')
if [ -z "$HOTFIX_SHA" ]; then
  echo "ERROR: PR is not merged yet or mergeCommit.oid is not available" >&2
  exit 1
fi
echo "Hotfix merge commit: $HOTFIX_SHA"

# 5. Create the release targeting that exact SHA
gh release create vX.Y.Z --target "$HOTFIX_SHA" --title "vX.Y.Z" --notes "..."
```

> **Important:** Use `--target "$HOTFIX_SHA"` with the merge commit OID from `gh pr view`.
> The `// empty` filter surfaces a null OID (PR not yet merged) as an error rather than
> silently creating a release targeting the wrong SHA.
> If no successful push-triggered CI run is found for the release SHA, the deploy job will fail.
