#!/usr/bin/env bash
# Native builds, including the existing Pi's 32-bit Docker Engine 20.10.
# Modern hosts can use `docker compose --profile debug build` instead.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export DOCKER_BUILDKIT=1
docker build -t infrareveal-gateway:local -f Dockerfile .
docker build -t infrareveal-dashboard:local -f dashboard/Dockerfile .
docker build -t infrareveal-debug-dashboard:local -f debug-dashboard/Dockerfile .
