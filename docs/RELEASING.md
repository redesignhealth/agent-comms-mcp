# Releasing agent-comms-mcp

## Prerequisites

- Write access to `redesignhealth/agent-comms-mcp`
- PyPI trusted publisher configured (already done — `publish.yml`, env `pypi`)

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

3. **Create a GitHub release:**
   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes
   ```
   Or via the GitHub UI: Releases → Draft a new release → tag `vX.Y.Z`.

4. **Verify both triggered workflows** pass at:
   `https://github.com/redesignhealth/agent-comms-mcp/actions`
   - `publish.yml` — publishes the Python wheel to PyPI
   - `deploy.yml` — builds the Docker image, deploys to dev ECS, then promotes to prod ECS

5. **Confirm the package is live** on PyPI:
   ```bash
   pip index versions agent-comms-mcp
   ```

## Versioning

Follow [SemVer](https://semver.org/):
- **Patch** (`0.1.x`) — bug fixes, doc updates, dependency bumps
- **Minor** (`0.x.0`) — new MCP tools or message types (backwards-compatible)
- **Major** (`x.0.0`) — breaking changes to auth model, wire format, or DB schema

## Hotfix

`deploy.yml` requires a successful **push-triggered** CI run for the exact release SHA. Hotfixes
must be merged to main before cutting a release — there is no fallback to PR-triggered runs.

```bash
git checkout -b hotfix/vX.Y.Z vX.Y.(Z-1)
# apply fix
git push origin hotfix/vX.Y.Z
# open a PR targeting main and merge it
# wait for CI to pass on main for this SHA, then:
gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."
```

> **Important:** Create the release only after the hotfix SHA is on main and CI has passed.
> The `gh release create` command above tags the current `main` HEAD by default.
> If no successful push-triggered CI run is found for the release SHA, the deploy job will fail.
