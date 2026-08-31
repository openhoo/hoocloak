# Contributing

Open an issue before changing OIDC behavior, persisted state, Helm contracts, or
release images. Small fixes may go directly to a pull request.

## Development

Use versions pinned by `go.mod`, workflow environment variables, and lockfiles.

```sh
gofmt -w cmd internal
go vet -tags no_otel ./...
go test -race -tags no_otel ./...
npm ci
npm --prefix ui/login ci
npm --prefix ui/login run build
helm lint charts/hoocloak --strict
```

Protocol and security changes need boundary, rejection, and fail-closed tests.
Chart changes need linted and rendered variants.

Commits use Conventional Commits. Pull requests must explain compatibility,
security, deployment, and rollback impact. Maintainers squash-merge using the
Conventional Commit pull request title. Lockfile changes must accompany
manifest changes.
