# Multi-stage build: pinned slim base, non-root runtime user,
# no secrets in the image.

# Pinned by digest (not the mutable `3.12-slim` tag) so the base image is
# reproducible and can't drift underfoot between builds. Resolved via
# `docker buildx imagetools inspect python:3.12-slim` on 2026-08-11
# (tag was 3.12.13-slim-trixie at resolution time).
FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS builder

WORKDIR /app

# Pin uv to match CI (.github/workflows/ci.yml). Pinning avoids
# build-behavior drift from an unpinned install.
RUN pip install --no-cache-dir uv==0.11.28

# Copy only deps first for layer caching. Flat-layout app: the project
# itself is never installed as a wheel (--no-install-project).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy service code
COPY . .

FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

WORKDIR /app

# UID/GID pinned so they're stable across base-image rebuilds — an unpinned
# uid can drift on a future base-image change and silently break volume
# ownership (e.g. EFS access points with fixed POSIX ownership).
RUN addgroup --system --gid 10001 app && adduser --system --uid 10001 --gid 10001 app

COPY --from=builder --chown=app:app /app /app
COPY --chown=app:app entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# The venv is fully baked at build time; run its interpreter directly so
# the container never re-contacts a package index at startup.
ENV PATH="/app/.venv/bin:$PATH"

# Argus round 3, TECH-5822 SUGGESTION: makes explicit what was previously
# an implicit side effect of entrypoint.sh's `exec python main.py` running
# from WORKDIR /app (which Python prepends to sys.path[0]) -- plugins.py's
# `importlib.resources.files("providers")` (a flat py-modules layout, never
# installed into site-packages via --no-install-project) depends on
# `providers` being importable. Without this, a switch to a console-script
# entrypoint or a different working directory would fail at boot with
# `ModuleNotFoundError: No module named 'providers'` instead of this
# dependency being visible here.
ENV PYTHONPATH="/app"

USER app

# EXPOSE is documentation-only and reflects only the DEFAULT MCP_PORT
# (8080). If MCP_PORT is overridden at runtime (e.g. `docker run -e
# MCP_PORT=9000`), this line does not change with it -- `docker run -P`
# (auto-publish-all-exposed-ports) would then publish the wrong port. Use
# an explicit `-p` mapping (or docker-compose.yml's parameterized ports:
# block, which already handles this) instead of relying on `-P`.
EXPOSE 8080

# Distinguishes a crashed/unhealthy container from a healthy one during
# ECS Fargate rolling deploys, hitting the same /health endpoint the
# service exposes on MCP_PORT (default 8080, see main.py).
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD ["sh", "-c", "python -c \"import os, urllib.request; urllib.request.urlopen('http://localhost:' + os.environ.get('MCP_PORT', '8080') + '/health')\" || exit 1"]

# Runs pending Alembic migrations before starting the server (see
# entrypoint.sh) — no automated migration mechanism otherwise runs inside
# the container.
CMD ["./entrypoint.sh"]
