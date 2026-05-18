#!/bin/sh
set -eu

RUNTIME_ENV="${MATTERMOST_RUNTIME_ENV:-/runtime/mattermost.env}"

echo "Waiting for Mattermost bootstrap file: ${RUNTIME_ENV}"
for _ in $(seq 1 180); do
  if [ -f "${RUNTIME_ENV}" ]; then
    set -a
    . "${RUNTIME_ENV}"
    set +a
    echo "Loaded Mattermost API settings"
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
  fi
  sleep 1
done

echo "Mattermost bootstrap file was not created in time" >&2
exit 1

