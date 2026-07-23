#!/usr/bin/env bash
set -Eeuo pipefail

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-hoocloak-e2e}"
export HOOCLOAK_LOGIN_MODE="${HOOCLOAK_LOGIN_MODE:-password}"

cleanup() {
  docker compose -f tests/e2e/compose.yaml down --volumes --remove-orphans
}

trap cleanup EXIT INT TERM

docker compose -f tests/e2e/compose.yaml up --build --wait
docker compose -f tests/e2e/compose.yaml logs --follow --no-color &
logs_pid=$!
wait "$logs_pid"
