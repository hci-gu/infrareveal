#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMAND_LOG="$(mktemp)"
trap 'rm -f "$COMMAND_LOG"' EXIT

iptables() {
  {
    printf 'iptables'
    printf ' %q' "$@"
    printf '\n'
  } >> "$COMMAND_LOG"
  return 1
}

ipset() {
  {
    printf 'ipset'
    printf ' %q' "$@"
    printf '\n'
  } >> "$COMMAND_LOG"
  return 1
}

export -f iptables ipset
export COMMAND_LOG
export INFRAREVEAL_ENTRYPOINT_LIBRARY_ONLY=true

# Dynamic repository root is intentional in the harness.
# shellcheck disable=SC1091
source "$REPOSITORY_ROOT/entrypoint.sh"
cleanup_lab_rules
cleanup_lab_rules

test "$(grep -c 'iptables -w -C FORWARD -j INFRAREVEAL_LAB' "$COMMAND_LOG")" -eq 2
test "$(grep -c 'iptables -w -C INPUT -j INFRAREVEAL_LAB_DNS' "$COMMAND_LOG")" -eq 2
test "$(grep -c 'iptables -w -X INFRAREVEAL_LAB_DNS' "$COMMAND_LOG")" -eq 2
test "$(grep -c 'ipset destroy infrareveal_lab_clients' "$COMMAND_LOG")" -eq 2
bash -n "$REPOSITORY_ROOT/entrypoint.sh"

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x "$REPOSITORY_ROOT/entrypoint.sh" "$0"
fi
