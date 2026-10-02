---
name: hoocloak-development
description: Develop, debug, and test Hoocloak itself, including its Go OIDC provider, strict configuration, Solid login UI, example applications, and Helm chart. Use in a Hoocloak source checkout.
---

# Hoocloak development

Run commands from the Hoocloak repository root. Read `CONTRIBUTING.md` before
changing public contracts. Versions and commands in `go.mod`, lockfiles,
`package.json`, and `.github/workflows/ci.yml` take precedence over this guide.
CI currently uses Go 1.26.6, Node 24, and Helm 4.2.3; release tooling uses Bun.

## Find the implementation

| Change | Start here | Verification |
| --- | --- | --- |
| CLI, startup, hash, health | `cmd/hoocloak/main.go` | Adjacent `main_test.go` |
| Strict YAML and environment overrides | `internal/config/config.go` | Config tests, `examples/hoocloak.yaml` |
| HTTP, discovery, login, themes | `internal/idp/server.go` | `server_test.go`, browser suites |
| Authorization, refresh, activity, revocation | `internal/idp/storage.go`, `client.go` | Storage and server tests |
| Hosted login UI | `ui/login/src/`, `internal/idp/ui/*.html` | Rebuild embedded assets, both login modes |
| Consumer examples | `examples/react-spa/`, `examples/aspnet-api/` | Complete example-stack E2E |
| Deployment contract | `charts/hoocloak/`, `Dockerfile`, `compose*.yaml` | CI chart variants, Compose validation |

## Fast backend loop

The existing embedded UI is tracked, so backend-only work can start without a
Node installation. Use `no_otel` consistently, as CI does:

```bash
go test -tags no_otel ./internal/config ./internal/idp ./cmd/hoocloak
go vet -tags no_otel ./...
go test -race -tags no_otel ./...
go build -tags no_otel -o ./hoocloak ./cmd/hoocloak
./hoocloak serve --config examples/hoocloak.yaml
```

Start with the affected package and a focused `-run` selection when debugging.
Format changed Go files with `gofmt`. Add rejection and boundary tests for
protocol, validation, and theme-preflight changes.

## Login UI and browser loop

The provider login uses Solid; the consumer SPA example uses React. Build the
login UI from its own package, then rebuild the Go binary:

```bash
npm --prefix ui/login ci
npm --prefix ui/login run build
npm ci
npx playwright install chromium firefox webkit
npm run e2e
```

Include regenerated `internal/idp/ui/dist/login.js`, `login.css`, and related
assets with their source changes. Do not hand-edit generated bundles.
`npm run e2e:password -- --project=chromium` and
`npm run e2e:select -- --project=chromium` are focused local checks; the full
suite covers both modes on three browsers. Docker Compose builds and manages
the actual provider/API/SPA stack; host .NET is unnecessary for that path.

Playwright serializes dynamic-port runs with a checkout lock. Do not remove
another run's lock. Both modes reuse report directories, so preserve the
first mode's failure artifacts before the second run overwrites them.
See [verification.md](references/verification.md) for isolation and chart checks.

## Contracts to preserve

- Realm issuer, signing keys, identities, browser policy, and protocol state
  are isolated. Restart loses in-memory state and rotates signing keys.
- SPAs use S256 PKCE and no secret; service clients use HTTP Basic. Refresh
  rotation/reuse, expiry, ownership, scope, and revocation boundaries need tests.
- Keep strict unknown-field and multiple-document rejection, exact redirect
  and origin validation, and duplicate security-parameter rejection.
- Theme form actions and assets are realm-relative. Preserve CSRF and startup
  validation for both password and select modes, plus accessibility controls.
- Maintain one replica and `Recreate`; a readiness probe is not OIDC proof.

Update README configuration/protocol examples alongside contract changes.
Report commands actually run, failed or unavailable gates, and generated files
changed. Documentation-only edits need skill/link checks, not a full image build.
