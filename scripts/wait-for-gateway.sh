#!/bin/sh
# nginx runs this before binding the admin address. The API starts only after
# gateway preflight, firewall isolation and address assignment have completed.
set -eu
if ! wget -q -T 2 -O /dev/null http://127.0.0.1:8090/api/health; then
  echo 'Waiting for gateway networking before starting the dashboard.'
  until wget -q -T 2 -O /dev/null http://127.0.0.1:8090/api/health; do
    sleep 2
  done
fi
