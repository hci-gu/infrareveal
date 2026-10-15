#!/usr/bin/env bash
# One fresh-data bootstrap path. --reset explicitly discards existing dev data.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    --dir|-dir)
      if ((i+1<${#args[@]})) && [[ "${args[i+1]}" != /* ]]; then
        args[i+1]="$PWD/${args[i+1]}"
      fi
      ;;
    --dir=*|-dir=*)
      value="${args[i]#*=}"
      [[ "$value" == /* ]] || args[i]="${args[i]%%=*}=$PWD/$value"
      ;;
  esac
done
cd "$repo_dir/pocketbase"
exec go run ./cmd/dev-data "${args[@]}"
