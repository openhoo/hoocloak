#!/usr/bin/env bash
set -Eeuo pipefail

: "${E2E_PROVIDER_PORT:?E2E_PROVIDER_PORT must be set by Playwright config}"
: "${E2E_API_PORT:?E2E_API_PORT must be set by Playwright config}"
: "${E2E_SPA_PORT:?E2E_SPA_PORT must be set by Playwright config}"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-hoocloak-e2e-$$-$RANDOM}"
export HOOCLOAK_LOGIN_MODE="${HOOCLOAK_LOGIN_MODE:-password}"
export E2E_PROVIDER_ORIGIN="${E2E_PROVIDER_ORIGIN:-http://hoocloak.localhost:${E2E_PROVIDER_PORT}}"
export E2E_API_ORIGIN="${E2E_API_ORIGIN:-http://api.localhost:${E2E_API_PORT}}"
export E2E_SPA_ORIGIN="${E2E_SPA_ORIGIN:-http://localhost:${E2E_SPA_PORT}}"
E2E_CONFIG_PATH="$(mktemp "${TMPDIR:-/tmp}/${COMPOSE_PROJECT_NAME}.config.XXXXXX.yaml")"
export E2E_CONFIG_PATH

sed \
  -e "s/__E2E_PROVIDER_PORT__/${E2E_PROVIDER_PORT}/g" \
  -e "s/__E2E_SPA_PORT__/${E2E_SPA_PORT}/g" \
  tests/e2e/hoocloak.yaml >"$E2E_CONFIG_PATH"
chmod 0644 "$E2E_CONFIG_PATH"

cleanup() {
  docker compose -p "$COMPOSE_PROJECT_NAME" -f tests/e2e/compose.yaml down --volumes --remove-orphans
  rm -f "$E2E_CONFIG_PATH"
}

trap cleanup EXIT INT TERM

if docker compose -p "$COMPOSE_PROJECT_NAME" -f tests/e2e/compose.yaml up --build --wait; then
  :
else
  status=$?
  docker compose -p "$COMPOSE_PROJECT_NAME" -f tests/e2e/compose.yaml logs --no-color || true
  exit "$status"
fi
docker compose -p "$COMPOSE_PROJECT_NAME" -f tests/e2e/compose.yaml logs --follow --no-color &
logs_pid=$!
wait "$logs_pid"
