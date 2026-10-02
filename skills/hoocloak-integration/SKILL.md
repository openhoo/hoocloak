---
name: hoocloak-integration
description: Set up Hoocloak as a development OIDC provider and connect an application's SPA, API, or service account; verify login, JWT validation, permissions, refresh, and logout. Use in consumer projects, without requiring Hoocloak source changes.
---

# Integrate with Hoocloak

Hoocloak supplies local-development OIDC. Work in the user's application;
determine its existing OIDC library, browser callback, API audience, and runtime
network before editing configuration. This installed skill is self-contained;
its [configuration guide](references/configuration.md) travels with it.
Use current documentation for the application's chosen OIDC library rather than
inventing framework-specific options.

## Choose the setup

- For the runnable provider/React/API demonstration, use a checkout of
  `openhoo/hoocloak` and `docker compose up --build --wait` in that checkout.
  This requires Docker Compose, not host Go/Node/.NET.
- For an existing application, configure a separate local provider and register
  that application's real redirects, origins, audiences, and scopes. Do not
  replace the app with the example stack.
- For a shared development cluster, use `charts/hoocloak` from a source checkout,
  one replica, and a complete config Secret. Skills installation does not install
  the server, example applications, or chart.

The example stack exposes the SPA at `http://localhost:3000`, API at
`http://api.localhost:5099`, and realm issuer at
`http://hoocloak.localhost:8080/realms/development`. Sample password identities
are `alice` / `alice-password` and `bob` / `bob-password`; the sample service
client is `example-worker` / `dev-secret`. These are public example values.
Compose defaults to trusted identity selection. To exercise passwords:

```bash
HOOCLOAK_LOGIN_MODE=password docker compose up --build --wait
```

## Wire the application

1. Choose an issuer reachable by the browser and by API/container processes.
   Keep its complete value byte-for-byte identical everywhere, including realm.
   Container `localhost` means that container; configure DNS/host routing without
   changing the issuer string. Root `base_url` ends in `/`.
2. Discover endpoints through `{issuer}/.well-known/openid-configuration`.
   JWKS is `{issuer}/keys`; token requests go to `{issuer}/oauth/token`.
3. For a SPA, use Authorization Code with S256 PKCE, an exact registered
   callback and origin, no client secret, and `openid`. Request `offline_access`
   only when refresh is needed. Validate state/nonce through the OIDC library.
4. APIs validate RS256 signatures through discovery/JWKS, issuer, audience,
   expiry, and access-token shape. ID tokens are not API bearer tokens.
   Map `role` and `permission` according to the API's policy.
5. Service accounts request `client_credentials` with HTTP Basic. Requested
   custom scopes must be both allowed and present in that client's permissions.
   Never configure browser redirects or OIDC-reserved scopes for service clients.

Read the configuration guide before creating YAML, hashes, or refresh/logout
handling. Keep real secrets and tokens out of source and diagnostic output.

## Verify the integration

- Confirm discovery and JWKS at the intended issuer, then perform a real login
  or client-credentials request and call the application's protected API.
- Verify missing/invalid tokens return 401 and an authenticated principal
  without the required permission/role returns 403. Include wrong-audience and
  wrong-realm rejection for changed validation configuration.
- If refresh is enabled, prove rotation and serialize refresh requests within
  the consuming session. Reusing a consumed refresh token revokes its family.
- Verify logout with a validated ID-token hint and an exact configured
  post-logout redirect. Clear the application's session too.

The provider health command and `/ready` prove readiness only. Restart rotates
per-realm keys and destroys sessions/protocol state; cached public keys can let
offline APIs accept old JWTs until expiry. Logout/revocation cannot retract an
unexpired JWT from an offline API. Do not present this development provider as
durable production authentication.
