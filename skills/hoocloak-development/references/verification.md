# Focused verification

All paths and commands here are relative to the Hoocloak checkout root.

## Browser isolation

`playwright.config.ts` allocates provider/API/SPA ports and a unique Compose
project. `tests/e2e/server.sh` generates a temporary provider configuration,
starts `tests/e2e/compose.yaml`, and removes its own stack on exit.
Keep one worker: browser projects share provider state.

For independent runs with manually coordinated ports, supply all three distinct
`E2E_PROVIDER_PORT`, `E2E_API_PORT`, and `E2E_SPA_PORT` values and a unique
`COMPOSE_PROJECT_NAME`. Partial overrides still acquire the allocation lock.
The Docker daemon must be able to bind-mount the generated config. Use the
package scripts to obtain the supported orchestration. `PW_REUSE_SERVER=1`
transfers state, mode, port, and cleanup responsibility to the caller.

## Charts and Compose

```bash
helm lint charts/hoocloak --strict
helm template hoocloak charts/hoocloak --namespace hoocloak > /dev/null
helm template hoocloak charts/hoocloak --namespace hoocloak \
  --set existingConfigSecret=hoocloak-config \
  --set existingConfigSecretKey=provider.yaml \
  --set-string existingConfigSecretVersion=1 > /dev/null
helm template hoocloak charts/hoocloak --namespace hoocloak \
  --set-string 'theme.image.reference=registry.example.test/hoocloak-theme@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > /dev/null
docker compose config --quiet
```

For theme/chart changes also exercise the rejection variants already maintained
in `.github/workflows/ci.yml`: mutable/malformed image references, legacy PVC
theme fields, security context mismatches, and reserved labels/annotations.
Keep `values.schema.json`, templates, and documented values consistent.

## Releases and performance

For release workflow edits, run `npm ci` and
`npm run test:release-workflow`. Version synchronization is implemented by
`scripts/sync-chart-version.ts`; follow the workflow's invocation when changing
release/version files. Do not increment versions merely to edit skills.

For configuration/storage performance changes:

```bash
go test -tags no_otel -run '^$' -bench . -benchmem -benchtime=100ms \
  ./internal/config ./internal/idp
```

Health, chart rendering, benchmarks, and image construction establish their
own narrow outcomes. Authentication changes need successful and rejected token
flows against the real stack.
