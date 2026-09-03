#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

pnpm test
pnpm build
pnpm lint
(cd pocketbase && go test -count=1 ./...)
(cd pocketbase && go test -race ./debugtrace ./labgate ./netmeta)
./scripts/test-entrypoint.sh
./scripts/check-proxy-lab-privacy.sh

if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" -eq 0 ]; then
  ./scripts/test-lab-gate-netns.sh
else
  echo "SKIP: privileged NFQUEUE namespace suite requires root on Linux"
fi

if [ "${1:-}" = "--docker" ]; then
  docker compose build proxy dashboard debug-dashboard
fi
