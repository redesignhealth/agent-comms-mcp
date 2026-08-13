#!/bin/sh
# Container entrypoint: run pending Alembic migrations before the server
# starts, so a deploy never serves traffic against an unmigrated schema.
# `exec` replaces the shell with the server process (PID 1), preserving
# signal handling for ECS Fargate task stop.
set -e

alembic upgrade head
exec python main.py
