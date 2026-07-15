package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfigYAML = `issuer: http://hoocloak.localhost:8080/
listen: 127.0.0.1:8080
tokens:
  access_ttl: 5m
  id_ttl: 5m
  refresh_ttl: 8h
users:
  - id: alice
    username: Alice
    password_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
    name: Alice
    email: alice@example.test
    email_verified: true
    roles: [admin]
    permissions: [api.read]
clients:
  - id: react-spa
    type: spa
    redirect_uris: [http://app.localhost:5173/auth/callback]
    post_logout_redirect_uris: [http://app.localhost:5173/auth/logout/callback]
    origins: [http://app.localhost:5173]
    audiences: [hoocloak-api]
    allowed_scopes: [openid, profile, email, offline_access, api.read]
  - id: worker
    type: service
    secret_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
    audiences: [hoocloak-api]
    allowed_scopes: [api.read]
    roles: [worker]
    permissions: [api.read]
`

func TestLoadRejectsStrictInvalidConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"unknown field", func(s string) string { return s + "mystery: true\n" }, "field mystery not found"},
		{"listen missing port", func(s string) string {
			return strings.Replace(s, "listen: 127.0.0.1:8080", "listen: localhost", 1)
		}, "listen must be a valid host:port address"},
		{"listen nonnumeric port", func(s string) string {
			return strings.Replace(s, "listen: 127.0.0.1:8080", "listen: 127.0.0.1:http", 1)
		}, "listen port must be a number"},
		{"listen port out of range", func(s string) string {
			return strings.Replace(s, "listen: 127.0.0.1:8080", "listen: 127.0.0.1:65536", 1)
		}, "listen port must be a number"},
		{"whitespace-padded theme directory", func(s string) string {
			return strings.Replace(s, "listen: 127.0.0.1:8080\n", "listen: 127.0.0.1:8080\nui:\n  theme_dir: \" ./theme\"\n", 1)
		}, "ui.theme_dir must not have surrounding whitespace"},
		{"whitespace-padded username", func(s string) string {
			return strings.Replace(s, "username: Alice", `username: " Alice "`, 1)
		}, "username must not have surrounding whitespace"},
		{"non-local cleartext issuer", func(s string) string {
			return strings.Replace(s, "http://hoocloak.localhost:8080/", "http://id.example.test/", 1)
		}, "cleartext issuer is allowed only"},
		{"issuer path", func(s string) string {
			return strings.Replace(s, "http://hoocloak.localhost:8080/", "http://hoocloak.localhost:8080/tenant/", 1)
		}, "absolute root URL ending in /"},
		{"wildcard redirect", func(s string) string {
			return strings.Replace(s, "http://app.localhost:5173/auth/callback", "http://*.localhost:5173/auth/callback", 1)
		}, "must not contain wildcards"},
		{"redirect fragment", func(s string) string {
			return strings.Replace(s, "http://app.localhost:5173/auth/callback", "http://app.localhost:5173/auth/callback#fragment", 1)
		}, "fragments are not allowed"},
		{"non-local cleartext redirect", func(s string) string {
			return strings.Replace(s, "http://app.localhost:5173/auth/callback", "http://app.example.test/auth/callback", 1)
		}, "cleartext redirect URI is allowed only"},
		{"origin path", func(s string) string {
			return strings.Replace(s, "origins: [http://app.localhost:5173]", "origins: [http://app.localhost:5173/path]", 1)
		}, "must not contain a path, query, or fragment"},
		{"spa secret", func(s string) string {
			return strings.Replace(s, "    type: spa\n", "    type: spa\n    secret_hash: \"$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme\"\n", 1)
		}, "spa clients must not define secret_hash"},
		{"spa missing openid", func(s string) string {
			return strings.Replace(s, "[openid, profile, email, offline_access, api.read]", "[profile, email, offline_access, api.read]", 1)
		}, "spa clients must allow openid"},
		{"invalid allowed scope token", func(s string) string {
			return strings.Replace(s, "[openid, profile, email, offline_access, api.read]", "[openid, profile, email, offline_access, api read]", 1)
		}, "invalid OAuth scope token"},
		{"invalid permission scope token", func(s string) string {
			return strings.Replace(s, "permissions: [api.read]\nclients:", `permissions: ["api read"]
clients:`, 1)
		}, "invalid OAuth scope token"},
		{"service browser redirect", func(s string) string {
			return strings.Replace(s, "    type: service\n", "    type: service\n    redirect_uris: [http://app.localhost:5173/callback]\n", 1)
		}, "service clients must not define browser redirects or origins"},
		{"service reserved scope", func(s string) string {
			return strings.Replace(s, "allowed_scopes: [api.read]\n    roles: [worker]", "allowed_scopes: [openid, api.read]\n    roles: [worker]", 1)
		}, "service clients must not allow reserved OIDC scope"},
		{"empty allowed scopes", func(s string) string {
			return strings.Replace(s, "allowed_scopes: [api.read]\n    roles: [worker]", "allowed_scopes: []\n    roles: [worker]", 1)
		}, "allowed_scopes must not be empty"},
		{"service scope without permission", func(s string) string {
			return strings.Replace(s, "roles: [worker]\n    permissions: [api.read]", "roles: [worker]\n    permissions: [api.write]", 1)
		}, "requires the same permission"},
		{"principal reserved permission", func(s string) string {
			return strings.Replace(s, "permissions: [api.read]\nclients:", "permissions: [openid]\nclients:", 1)
		}, "contains reserved OIDC scope"},
		{"unicode case-fold duplicate username", func(s string) string {
			s = strings.Replace(s, "username: Alice", "username: Σ", 1)
			duplicate := `  - id: unicode-duplicate
    username: ς
    password_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
    name: Duplicate
    email: duplicate@example.test
    email_verified: true
    roles: [reader]
    permissions: [api.read]
`
			return strings.Replace(s, "clients:\n", duplicate+"clients:\n", 1)
		}, "duplicate username"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.edit(validConfigYAML)), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadAcceptsExactLocalConfiguration(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(validConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Issuer != "http://hoocloak.localhost:8080/" || len(cfg.Clients) != 2 {
		t.Fatalf("unexpected parsed config: issuer=%q clients=%d", cfg.Issuer, len(cfg.Clients))
	}
	if cfg.UI.ThemeDir != "" {
		t.Fatalf("theme directory = %q, want empty default", cfg.UI.ThemeDir)
	}
}

func TestLoadResolvesRelativeThemeDirectory(t *testing.T) {
	t.Parallel()
	configured := strings.Replace(
		validConfigYAML,
		"listen: 127.0.0.1:8080\n",
		"listen: 127.0.0.1:8080\nui:\n  theme_dir: ./themes/aurora\n",
		1,
	)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(configured), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := filepath.Join(filepath.Dir(path), "themes", "aurora")
	if cfg.UI.ThemeDir != want {
		t.Fatalf("theme directory = %q, want %q", cfg.UI.ThemeDir, want)
	}
}
