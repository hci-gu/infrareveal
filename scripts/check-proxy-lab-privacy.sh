#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"
command -v rg >/dev/null

gate_sources=(
  pocketbase/labgate
  pocketbase/data
  debug-dashboard/src/experiments/proxy-lab
)

for source in "${gate_sources[@]}"; do
  test -e "$source" || { echo "missing privacy source: $source" >&2; exit 1; }
done

if rg -n --glob '!**/*_test.*' '(raw_payload|payload_content|packet_body|request_body)' "${gate_sources[@]}"; then
  echo "forbidden content-bearing gate field found" >&2
  exit 1
fi

if rg -n --glob '!**/*_test.*' '(controlToken|operatorToken).*(searchParams|[?&]token=)|[?&]token=.*(controlToken|operatorToken)' debug-dashboard/src; then
  echo "control token appears to enter a URL" >&2
  exit 1
fi

if rg -n 'record\.Set\("(payload|body|content|token)"' pocketbase/labgate; then
  echo "gate persistence contains payload/token field" >&2
  exit 1
fi

echo "Proxy Lab static privacy checks passed"
