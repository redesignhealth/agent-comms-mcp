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

If main has moved past what you want to release:

```bash
git checkout -b hotfix/vX.Y.Z vX.Y.(Z-1)
# apply fix
git push origin hotfix/vX.Y.Z
gh release create vX.Y.Z --target hotfix/vX.Y.Z --title "vX.Y.Z" --notes "..."
```

> **Important:** `deploy.yml` verifies a successful CI run exists for the release SHA before deploying.
> Push the hotfix branch and open a PR against main (or trigger CI manually via `gh workflow run CI`)
> so CI runs against the hotfix SHA before you create the release. If no successful CI run is found,
> the deploy job will fail immediately.
