#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ] || [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: NFQUEUE namespace test requires root on Linux"
  exit 0
fi

for command in ip iptables curl python3 go; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done

CLIENT_NS="ir-lab-client-$$"
GATEWAY_NS="ir-lab-gateway-$$"
UPSTREAM_NS="ir-lab-upstream-$$"
QUEUE_PID=""
SERVER_PID=""
CLIENT_PID=""
PRESSURE_PIDS=()
TEMP_DIR="$(mktemp -d)"
REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  for client_pid in "${PRESSURE_PIDS[@]}"; do kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; done
  if [ -n "$QUEUE_PID" ]; then kill "$QUEUE_PID" 2>/dev/null || true; wait "$QUEUE_PID" 2>/dev/null || true; fi
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  if [ -n "$CLIENT_PID" ]; then kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; fi
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  ip netns del "$GATEWAY_NS" 2>/dev/null || true
  ip netns del "$UPSTREAM_NS" 2>/dev/null || true
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT INT TERM

ip netns add "$CLIENT_NS"
ip netns add "$GATEWAY_NS"
ip netns add "$UPSTREAM_NS"
ip link add ir-client type veth peer name ir-gw-client
ip link add ir-upstream type veth peer name ir-gw-upstream
ip link set ir-client netns "$CLIENT_NS"
ip link set ir-gw-client netns "$GATEWAY_NS"
ip link set ir-upstream netns "$UPSTREAM_NS"
ip link set ir-gw-upstream netns "$GATEWAY_NS"

ip -n "$CLIENT_NS" addr add 10.250.1.2/24 dev ir-client
ip -n "$GATEWAY_NS" addr add 10.250.1.1/24 dev ir-gw-client
ip -n "$GATEWAY_NS" addr add 10.250.2.1/24 dev ir-gw-upstream
ip -n "$UPSTREAM_NS" addr add 10.250.2.2/24 dev ir-upstream
for namespace in "$CLIENT_NS" "$GATEWAY_NS" "$UPSTREAM_NS"; do ip -n "$namespace" link set lo up; done
ip -n "$CLIENT_NS" link set ir-client up
ip -n "$GATEWAY_NS" link set ir-gw-client up
ip -n "$GATEWAY_NS" link set ir-gw-upstream up
ip -n "$UPSTREAM_NS" link set ir-upstream up
ip -n "$CLIENT_NS" route add default via 10.250.1.1
ip -n "$UPSTREAM_NS" route add default via 10.250.2.1
ip netns exec "$GATEWAY_NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$GATEWAY_NS" iptables -P FORWARD ACCEPT

ip netns exec "$UPSTREAM_NS" python3 -m http.server 18080 --bind 10.250.2.2 >"$TEMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.2
ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 2 http://10.250.2.2:18080/ >/dev/null

install_queue_rule() {
  ip netns exec "$GATEWAY_NS" iptables -F FORWARD
  ip netns exec "$GATEWAY_NS" iptables -A FORWARD -s 10.250.1.2 -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 42 --queue-bypass
  ip netns exec "$GATEWAY_NS" iptables -A FORWARD -j ACCEPT
}

start_queue() {
  local mode="$1"
  ip netns exec "$GATEWAY_NS" "$TEMP_DIR/nfqueue-smoke" -queue 42 -client-subnet 10.250.1.0/24 -mode "$mode" -hold 1s >"$TEMP_DIR/queue.log" 2>&1 &
  QUEUE_PID=$!
  for _ in $(seq 1 100); do grep -q READY "$TEMP_DIR/queue.log" && return; sleep 0.02; done
  cat "$TEMP_DIR/queue.log" >&2
  exit 1
}

(cd "$REPOSITORY_ROOT/pocketbase" && go build -o "$TEMP_DIR/nfqueue-smoke" ./cmd/nfqueue-smoke)
install_queue_rule

# --queue-bypass preserves forwarding with no listener.
ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 2 "http://10.250.2.2:18080/?bypass=$RANDOM" >/dev/null

start_queue hold
started="$(date +%s%3N)"
ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 3 "http://10.250.2.2:18080/?hold=$RANDOM" >/dev/null
elapsed=$(( $(date +%s%3N) - started ))
test "$elapsed" -ge 900
kill "$QUEUE_PID"; wait "$QUEUE_PID" || true; QUEUE_PID=""

# Closing a listener while one packet is held must release forwarding through
# the kernel queue's fail-open/unbind behaviour.
start_queue hold
ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 3 "http://10.250.2.2:18080/?kill-held=$RANDOM" >/dev/null &
CLIENT_PID=$!
sleep 0.1
kill "$QUEUE_PID"; wait "$QUEUE_PID" || true; QUEUE_PID=""
wait "$CLIENT_PID"; CLIENT_PID=""

start_queue drop
if ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 1 "http://10.250.2.2:18080/?drop=$RANDOM" >/dev/null 2>&1; then
  echo "drop verdict unexpectedly completed" >&2
  exit 1
fi
kill "$QUEUE_PID"; wait "$QUEUE_PID" || true; QUEUE_PID=""

# A small configured queue under parallel connection pressure must fail open;
# every controlled request still completes once accepted/held packets release.
ip netns exec "$GATEWAY_NS" "$TEMP_DIR/nfqueue-smoke" -queue 42 -queue-length 16 -client-subnet 10.250.1.0/24 -mode hold -hold 500ms >"$TEMP_DIR/queue.log" 2>&1 &
QUEUE_PID=$!
for _ in $(seq 1 100); do grep -q READY "$TEMP_DIR/queue.log" && break; sleep 0.02; done
if ! grep -q READY "$TEMP_DIR/queue.log"; then
  cat "$TEMP_DIR/queue.log" >&2
  exit 1
fi
for request in $(seq 1 48); do
  ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 4 "http://10.250.2.2:18080/?pressure=$request-$RANDOM" >/dev/null &
  PRESSURE_PIDS+=("$!")
done
for client_pid in "${PRESSURE_PIDS[@]}"; do wait "$client_pid"; done
PRESSURE_PIDS=()
kill "$QUEUE_PID"; wait "$QUEUE_PID" || true; QUEUE_PID=""

# Killing the listener returns to queue-bypass forwarding.
ip netns exec "$CLIENT_NS" curl --fail --silent --show-error --max-time 2 "http://10.250.2.2:18080/?recovered=$RANDOM" >/dev/null

cleanup
cleanup
trap - EXIT INT TERM
echo "NFQUEUE namespace smoke test passed"
