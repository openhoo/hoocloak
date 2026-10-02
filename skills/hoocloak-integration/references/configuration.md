# Provider configuration and troubleshooting

Example consumer configuration; replace callbacks, origins, audience, and IDs
with the actual application's values. A user without `password_hash` uses the
development default password `hoo`.

```yaml
base_url: http://hoocloak.localhost:8080/
listen: 0.0.0.0:8080
tokens:
  access_ttl: 5m
  id_ttl: 5m
  refresh_ttl: 8h
realms:
  - name: development
    users:
      - id: developer
        username: developer
        roles: [reader]
        permissions: [api.read]
    clients:
      - id: my-spa
        type: spa
        redirect_uris: [http://localhost:3000/auth/callback]
        post_logout_redirect_uris: [http://localhost:3000/auth/logout/callback]
        origins: [http://localhost:3000]
        audiences: [my-api]
        allowed_scopes: [openid, profile, email, offline_access, api.read]
```

Standalone CLI: `hoocloak serve --config path/to/hoocloak.yaml`. If building
from source, use `go build -tags no_otel -o ./hoocloak ./cmd/hoocloak` at the
source root. `hoocloak health --url http://127.0.0.1:8080/ready` probes readiness.

Generate password/service hashes with `hoocloak hash`, feeding one nonempty
newline-terminated value through stdin. It rejects EOF without a newline and
extra lines. Use secure input for real values, not command arguments/logging.
Configuration expects complete bcrypt hashes at cost 10; do not add a plaintext
`password` or `client_secret` field. Service clients require `secret_hash`,
`audiences`, `allowed_scopes`, and matching `permissions`, and forbid SPA fields.

Configuration rejects unknown fields and multiple YAML documents. Realm names
are lowercase DNS labels; user/client IDs share one namespace within a realm.
Origins are canonical exact origins without a path/query/fragment or explicit
default port. Redirects are exact URLs without fragments or wildcards. HTTP is
allowed only for loopback, `localhost`, and `.localhost`; other hosts need HTTPS.

## Refresh and scopes

Reserved supported scopes are `openid`, `profile`, `email`, `offline_access`.
`phone` and `address` are unsupported. Custom permission names are OAuth scope
tokens and must not reuse reserved names. Service clients forbid reserved scopes.
Refresh families have an absolute configured lifetime; rotation does not extend
it. Serialize refresh requests and discard consumed tokens immediately.

## Diagnose by evidence

| Symptom | Check |
| --- | --- |
| Callback/origin rejected | Exact scheme, host, port, path and realm registration |
| Browser works, API fails discovery | Container DNS/route to the identical public issuer |
| 401 after provider restart | Key rotation, stale JWKS cache, old access/refresh tokens |
| 403 with a valid token | API audience, requested scope, permission/role policy |
| Service token rejected | HTTP Basic, bcrypt hash, custom scope allow-list and permissions |
| Unexpected password-free login | Compose select default vs standalone password default |
| Refresh family stops working | Concurrent/repeated consumption of a rotating refresh token |

For themes, use a complete directory with `login.html`, `logged-out.html`, and
`assets/`. YAML `ui.theme_dir` resolves beside the config; environment override
`HOOCLOAK_UI_THEME_DIR` must be absolute. Templates use `.BasePath` for realm
login/assets and preserve the required CSRF/authRequestID fields. Restart to
load a theme; use the source README's theme contract for custom forms.
