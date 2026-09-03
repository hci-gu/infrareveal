#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

gate_sources=(
  pocketbase/labgate
  pocketbase/migrations/202609030001_gate_events.go
  pocketbase/migrations/202609030002_gate_event_packet_metadata.go
  debug-dashboard/src/experiments/proxy-lab
)

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
