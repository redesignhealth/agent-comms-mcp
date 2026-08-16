# Releasing agent-comms-mcp

## Prerequisites

- Write access to `redesignhealth/agent-comms-mcp`
- PyPI trusted publisher configured (already done — `publish.yml`, env `pypi`)
- GitHub `production` environment configured on the repo with required reviewers
  (gates the `deploy-prod` job — without it, prod deploys are unreviewed)
- Three IAM roles configured in `redesignhealth/rh-data-platform`, correct OIDC
  trust policies (see `deploy.yml` header comments for the exact trust split):
  - `rh-platform-dev-github-actions-ecr-push-role` and
    `rh-platform-github-actions-ecr-push-role` -- ECR push/pull only
  - `rh-platform-github-actions-ecs-deploy-reclaw-comms-role` (prod instance
    only -- `deploy-dev` no longer assumes this role) -- read-only access to
    the dev ECR repo, for `deploy-prod` to promote the dev image to prod ECR.
    **This role carries no ECS or `PassRole` permissions as of issue #7795**:
    this workflow no longer deploys to ECS directly at all -- see the next
    bullet.
  - **This workflow does not deploy to ECS.** `deploy-prod`'s last step
    dispatches `redesignhealth/rh-data-platform`'s `deploy-reclaw-comms.yml`,
    whose own `deploy-terraform.yml` calls are the only thing that ever
    deploys this service. Two repo secrets gate that dispatch:
    `RH_DATA_PLATFORM_DISPATCH_APP_ID` and
    `RH_DATA_PLATFORM_DISPATCH_APP_PRIVATE_KEY`, for a GitHub App installed
    on `rh-data-platform` with `actions: write`. Without them provisioned,
    the "Generate rh-data-platform dispatch token" step fails immediately
    (bad/missing App credentials) -- the service is not deployed, not
    "deployed but drifted." If the secrets are present but the App lacks
    `actions: write` on `rh-data-platform`, token generation ALSO fails at
    that same step -- GitHub's installation-token API returns HTTP 422 when
    the requested permission isn't granted to the App installation, with an
    error like "Requested permissions are not available" rather than a bad
    credentials error. The dispatch step is never reached either way.
    The dispatch step has its own separate failure mode: `timeout-minutes: 20`
    on the step overall, and up to 5 minutes of that CAN be spent discovering
    the dispatched run before watching even starts -- so ~15 minutes is the
    worst-case watch *floor*, not the effective ceiling. In the normal path
    the run is discovered within 15-30s and the watch gets nearly the full 20
    minutes; the 5-minute discovery budget is only exhausted (and the step
    fails without ever watching) if the run never appears in
    `deploy-reclaw-comms.yml`'s run list at all. If
    `deploy-reclaw-comms.yml` (dev+prod Terraform apply plus ECS
    stabilization) takes longer than the watch actually got, this step fails
    even though the downstream deploy may still be proceeding -- a
    best-effort `trap` (registered for both `SIGTERM` and `SIGINT` --
    **manually canceling this release job from the Actions UI sends SIGINT
    and has the same blast radius as a timeout**, with no separate warning
    at cancel time) attempts to cancel the downstream run in that case (not
    guaranteed: GitHub Actions can escalate to SIGKILL on the whole process
    tree before the handler runs), but check rh-data-platform's Actions tab
    to confirm actual ECS state before assuming a red run means nothing
    deployed.
    **If the trap's cancellation lands mid-`terraform apply`**, it can leave
    rh-data-platform's Terraform backend with a held state lock. Terraform's
    lock error itself is not opaque -- it reports the lock ID, operation
    type, holder identity, and creation timestamp -- but it does not
    obviously connect back to the canceled GitHub Actions job, so an
    operator can misread an informative error as unrelated noise. Before
    running `terraform force-unlock <LockID>` in rh-data-platform:
    1. Confirm the downstream `deploy-reclaw-comms.yml` run has actually
       stopped (check rh-data-platform's Actions tab) -- the cancel is
       best-effort and may not have landed, and force-unlocking a lock that
       Terraform is still actively holding can corrupt the state file. If no
       `RUN_ID` was ever discovered (the 5-minute discovery budget was
       exhausted before dispatch was even found), no cancel fired and no
       lock risk exists from this step -- but check for any in-flight
       `deploy-reclaw-comms.yml` run dispatched around the release
       timestamp regardless, since the deploy may still be proceeding
       unmonitored.
    2. Only once it's confirmed stopped, use the lock ID from Terraform's
       own error with `terraform force-unlock`, or escalate to whoever owns
       that repo's Terraform state, before re-releasing.
  - **Merge order**: [rh-data-platform#7796](https://github.com/redesignhealth/rh-data-platform/pull/7796)
    (or its successor, if already merged -- confirm the IAM role above has
    had its ECS/PassRole grants removed and `deploy-reclaw-comms.yml` exists)
    must be merged and applied before cutting a release with this workflow.
    If it isn't: `deploy-dev` still pushes a new dev image successfully (it
    no longer touches ECS at all, so nothing to fail there); `deploy-prod`
    pushes to prod ECR and then fails at the "Deploy via ... deploy-reclaw-
    comms.yml" step, and the release never reaches ECS in either
    environment.

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
     (the `deploy-prod` job requires approval from a `production` environment reviewer). Neither
     job deploys to ECS directly: `deploy-prod`'s last step dispatches
     `redesignhealth/rh-data-platform`'s `deploy-reclaw-comms.yml` and waits for it to complete —
     that workflow's Terraform apply is what actually updates the ECS service.

6. **Confirm the package is live** on PyPI:
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
