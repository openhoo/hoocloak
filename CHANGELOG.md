# hoocloak Changelog

## Unreleased

## 1.0.2 (2026-07-23)

### Other Changes

- **branding:** add logo and banner (4e5445b)

### Performance

- **container:** minimize image footprint (04b85af)

## 1.0.1 (2026-07-23)

### Other Changes

- publish images to Docker Hub (3ea3461)

### Bug Fixes

- **release:** activate Docker Hub publishing (9fe9c50)

## 1.0.0 (2026-07-23)

### Features

- **helm:** add hardened deployment chart (4367629)

### Breaking Changes

- add path-based realms (c16dd2c)
  - BREAKING: replace top-level issuer, users, and clients with base_url and realms. OIDC endpoints now live below /realms/{name}.

### Other Changes

- pin complete setup-helm release (d88141b)

## 0.2.0 (2026-07-23)

### Features

- add selectable dev identities (8218ff5)

### Bug Fixes

- align example SPA origin (4c4c881)

## 0.1.2 (2026-07-15)

### Performance

- optimize token storage and image delivery (837b75b)

## 0.1.1 (2026-07-15)

### Other Changes

- allow artifact metadata records (e610761)

### Bug Fixes

- harden authentication and container releases (682523e)
- **ci:** use patched Go toolchain (8296017)

## 0.1.0 (2026-07-15)

### Features

- add Hoocloak development identity provider (908e7e5)

### Other Changes

- automate releases with Hooversion (dbd1114)
- use hosted runners for releases (791fd80)
