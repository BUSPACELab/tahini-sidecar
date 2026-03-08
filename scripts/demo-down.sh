#!/usr/bin/env bash
# Tear down the demo: stop containers and remove the shared volume.
#
# Usage:  bazel run //:demo_down
set -e
cd "${BUILD_WORKSPACE_DIRECTORY:-.}"

exec docker compose \
    -f docker-compose.yml \
    -f docker-compose.sgx.yml \
    down -v
