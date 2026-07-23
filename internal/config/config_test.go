package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfigYAML = `base_url: http://hoocloak.localhost:8080/
listen: 127.0.0.1:8080
tokens:
  access_ttl: 5m
  id_ttl: 5m
  refresh_ttl: 8h
realms:
  - name: development
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
  - name: partner
    users:
      - id: alice
        username: Alice
        password_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
        name: Partner Alice
        email: partner-alice@example.test
        email_verified: true
        roles: [partner]
        permissions: [partner.read]
    clients:
      - id: worker
        type: service
        secret_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
        audiences: [partner-api]
        allowed_scopes: [partner.read]
        roles: [partner-worker]
        permissions: [partner.read]
`

func TestLoadRejectsStrictInvalidConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"unknown field", func(s string) string { return s + "mystery: true\n" }, "field mystery not found"},
		{"legacy issuer field", func(s string) string { return "issuer: http://hoocloak.localhost:8080/\n" + s }, "field issuer not found"},
		{"listen missing port", replace("listen: 127.0.0.1:8080", "listen: localhost"), "listen must be a valid host:port address"},
		{"listen nonnumeric port", replace("listen: 127.0.0.1:8080", "listen: 127.0.0.1:http"), "listen port must be a number"},
		{"listen port out of range", replace("listen: 127.0.0.1:8080", "listen: 127.0.0.1:65536"), "listen port must be a number"},
		{"whitespace-padded theme directory", replace("listen: 127.0.0.1:8080\n", "listen: 127.0.0.1:8080\nui:\n  theme_dir: \" ./theme\"\n"), "ui.theme_dir must not have surrounding whitespace"},
		{"empty realms", func(s string) string { return s[:strings.Index(s, "realms:\n")] + "realms: []\n" }, "realms must not be empty"},
		{"missing realm name", replace("  - name: development", "  - name: ''"), "realms[0].name must match"},
		{"invalid realm name", replace("  - name: development", "  - name: Development"), "realms[0].name must match"},
		{"duplicate realm name", replace("  - name: partner", "  - name: development"), "duplicate realm name"},
		{"whitespace-padded username", replace("username: Alice", `username: " Alice "`), "username must not have surrounding whitespace"},
		{"non-local cleartext base URL", replace("http://hoocloak.localhost:8080/", "http://id.example.test/"), "cleartext base_url is allowed only"},
		{"base URL path", replace("http://hoocloak.localhost:8080/", "http://hoocloak.localhost:8080/tenant/"), "absolute root URL ending in /"},
		{"base URL query", replace("http://hoocloak.localhost:8080/", "http://hoocloak.localhost:8080/?tenant=dev"), "absolute root URL ending in /"},
		{"base URL fragment", replace("http://hoocloak.localhost:8080/", "http://hoocloak.localhost:8080/#dev"), "absolute root URL ending in /"},
		{"base URL scheme", replace("http://hoocloak.localhost:8080/", "ftp://hoocloak.localhost:8080/"), "base_url scheme must be http or https"},
		{"base URL missing slash", replace("http://hoocloak.localhost:8080/", "http://hoocloak.localhost:8080"), "absolute root URL ending in /"},
		{"wildcard redirect", replace("http://app.localhost:5173/auth/callback", "http://*.localhost:5173/auth/callback"), "must not contain wildcards"},
		{"redirect fragment", replace("http://app.localhost:5173/auth/callback", "http://app.localhost:5173/auth/callback#fragment"), "fragments are not allowed"},
		{"non-local cleartext redirect", replace("http://app.localhost:5173/auth/callback", "http://app.example.test/auth/callback"), "cleartext redirect URI is allowed only"},
		{"origin path", replace("origins: [http://app.localhost:5173]", "origins: [http://app.localhost:5173/path]"), "must not contain a path, query, or fragment"},
		{"spa secret", replace("        type: spa\n", "        type: spa\n        secret_hash: \"$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme\"\n"), "spa clients must not define secret_hash"},
		{"spa missing openid", replace("[openid, profile, email, offline_access, api.read]", "[profile, email, offline_access, api.read]"), "spa clients must allow openid"},
		{"invalid allowed scope token", replace("[openid, profile, email, offline_access, api.read]", "[openid, profile, email, offline_access, api read]"), "invalid OAuth scope token"},
		{"service browser redirect", replace("        type: service\n", "        type: service\n        redirect_uris: [http://app.localhost:5173/callback]\n"), "service clients must not define browser redirects or origins"},
		{"service reserved scope", replace("allowed_scopes: [api.read]\n        roles: [worker]", "allowed_scopes: [openid, api.read]\n        roles: [worker]"), "service clients must not allow reserved OIDC scope"},
		{"duplicate user in one realm", func(s string) string {
			duplicate := `      - id: alice-two
        username: ALICE
        password_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
        name: Duplicate
        email: duplicate@example.test
        email_verified: true
        roles: [reader]
        permissions: [api.read]
`
			return strings.Replace(s, "    clients:\n", duplicate+"    clients:\n", 1)
		}, "realms[0] has duplicate username"},
		{"duplicate ID in one realm", replace("      - id: react-spa", "      - id: alice"), "duplicate id"},
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

func replace(old, new string) func(string) string {
	return func(value string) string { return strings.Replace(value, old, new, 1) }
}

func TestLoadAcceptsRealmLocalNamespaces(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(validConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.BaseURL != "http://hoocloak.localhost:8080/" || len(cfg.Realms) != 2 {
		t.Fatalf("unexpected parsed config: base_url=%q realms=%d", cfg.BaseURL, len(cfg.Realms))
	}
	if got := cfg.RealmIssuer("development"); got != "http://hoocloak.localhost:8080/realms/development" {
		t.Fatalf("development issuer = %q", got)
	}
	if got := cfg.RealmIssuer("partner"); got != "http://hoocloak.localhost:8080/realms/partner" {
		t.Fatalf("partner issuer = %q", got)
	}
	if cfg.UI.ThemeDir != "" {
		t.Fatalf("theme directory = %q, want empty default", cfg.UI.ThemeDir)
	}
}

func TestLoadResolvesRelativeThemeDirectory(t *testing.T) {
	t.Parallel()
	configured := strings.Replace(validConfigYAML, "listen: 127.0.0.1:8080\n", "listen: 127.0.0.1:8080\nui:\n  theme_dir: ./themes/aurora\n", 1)
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
