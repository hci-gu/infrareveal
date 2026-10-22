#!/usr/bin/env bash
# Controller: copy the harness, browse on the client, verify on the gateway.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
client=${1:-pi@192.168.10.139}
gateway=${2:-pi@192.168.10.120}
run="$(date -u +%Y%m%dT%H%M%SZ)-$$"
output=${3:-output/pocketbase-restructuring/client-e2e/$run}
[[ ! -e $output ]] || { echo 'Output directory already exists.' >&2; exit 1; }
mkdir -p "$output"
control=$(mktemp -d /tmp/ir-e2e.XXXXXX)
cleanup() {
  ssh -S "$control/client" -O exit "$client" 2>/dev/null || true
  ssh -S "$control/gateway" -O exit "$gateway" 2>/dev/null || true
  rmdir "$control" 2>/dev/null || true
}
trap cleanup EXIT
for role in client gateway; do
  target=$client
  [[ $role != gateway ]] || target=$gateway
  ssh -M -S "$control/$role" -o ControlPersist=600 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -fN "$target"
done
client_ssh=(ssh -S "$control/client" -o BatchMode=yes "$client")
gateway_ssh=(ssh -S "$control/gateway" -o BatchMode=yes "$gateway")
client_root=$("${client_ssh[@]}" 'printf "%s/infrareveal-e2e" "$HOME"')
gateway_root=$("${gateway_ssh[@]}" 'printf "%s/infrareveal-e2e" "$HOME"')
[[ $client_root =~ ^/[a-zA-Z0-9/_-]+$ && $gateway_root =~ ^/[a-zA-Z0-9/_-]+$ ]] || { echo 'Unsupported remote home path.' >&2; exit 1; }
"${client_ssh[@]}" "mkdir -p $client_root/scripts $client_root/testdata $client_root/results"
"${gateway_ssh[@]}" "mkdir -p $gateway_root/scripts $gateway_root/results/$run"
scp -q -o ControlPath="$control/client" scripts/client-wifi-e2e.sh scripts/client-browsing.py "$client:$client_root/scripts/"
scp -q -o ControlPath="$control/client" testdata/browsing-session.json "$client:$client_root/testdata/"
scp -q -o ControlPath="$control/gateway" scripts/check-client-browsing.py "$gateway:$gateway_root/scripts/"
"${gateway_ssh[@]}" "python3 $gateway_root/scripts/check-client-browsing.py --snapshot" > "$output/gateway-before.json"
status=0
"${client_ssh[@]}" "sudo -n timeout --signal=TERM 900 bash $client_root/scripts/client-wifi-e2e.sh $client_root/results/$run" > "$output/client.log" 2>&1 || status=$?
if "${client_ssh[@]}" "test -d $client_root/results/$run"; then
  scp -q -r -o ControlPath="$control/client" "$client:$client_root/results/$run" "$output/client"
fi
if [[ $status != 0 ]]; then cat "$output/client.log"; exit "$status"; fi
scp -q -o ControlPath="$control/gateway" "$output/gateway-before.json" "$output/client/browser.json" "$gateway:$gateway_root/results/$run/"
status=0
"${gateway_ssh[@]}" "python3 $gateway_root/scripts/check-client-browsing.py --browser $gateway_root/results/$run/browser.json --baseline $gateway_root/results/$run/gateway-before.json --output $gateway_root/results/$run" > "$output/verification.log" 2>&1 || status=$?
scp -q -r -o ControlPath="$control/gateway" "$gateway:$gateway_root/results/$run" "$output/gateway"
cat "$output/verification.log"
printf 'Evidence: %s\n' "$output"
exit "$status"
