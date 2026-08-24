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
        password_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"
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
        secret_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"
        audiences: [hoocloak-api]
        allowed_scopes: [api.read]
        roles: [worker]
        permissions: [api.read]
  - name: partner
    users:
      - id: alice
        username: Alice
        password_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"
        name: Partner Alice
        email: partner-alice@example.test
        email_verified: true
        roles: [partner]
        permissions: [partner.read]
    clients:
      - id: worker
        type: service
        secret_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"
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
		{"base URL uppercase scheme", replace("http://hoocloak.localhost:8080/", "HTTP://hoocloak.localhost:8080/"), "base_url scheme must use canonical lowercase spelling"},
		{"base URL hostless", replace("http://hoocloak.localhost:8080/", "https://:443/"), "base_url must be an absolute URL without credentials"},
		{"base URL empty port", replace("http://hoocloak.localhost:8080/", "https://id.example.test:/"), "base_url port must be a number from 1 to 65535"},
		{"base URL zero port", replace("http://hoocloak.localhost:8080/", "https://id.example.test:0/"), "base_url port must be a number from 1 to 65535"},
		{"base URL oversized port", replace("http://hoocloak.localhost:8080/", "https://id.example.test:65536/"), "base_url port must be a number from 1 to 65535"},
		{"wildcard redirect", replace("http://app.localhost:5173/auth/callback", "http://*.localhost:5173/auth/callback"), "must not contain wildcards"},
		{"redirect fragment", replace("http://app.localhost:5173/auth/callback", "http://app.localhost:5173/auth/callback#fragment"), "fragments are not allowed"},
		{"redirect empty fragment delimiter", replace("http://app.localhost:5173/auth/callback", "http://app.localhost:5173/auth/callback#"), "fragments are not allowed"},
		{"post-logout empty fragment delimiter", replace("http://app.localhost:5173/auth/logout/callback", "http://app.localhost:5173/auth/logout/callback#"), "fragments are not allowed"},
		{"non-local cleartext redirect", replace("http://app.localhost:5173/auth/callback", "http://app.example.test/auth/callback"), "cleartext redirect URI is allowed only"},
		{"redirect hostless", replace("http://app.localhost:5173/auth/callback", "https://:443/callback"), "redirect URI must be an absolute URL without credentials"},
		{"redirect zero port", replace("http://app.localhost:5173/auth/callback", "http://app.localhost:0/callback"), "redirect URI port must be a number from 1 to 65535"},
		{"redirect malformed query escape", replace("http://app.localhost:5173/auth/callback", `"http://app.localhost:5173/auth/callback?next=%ZZ"`), "query contains invalid percent-encoding"},
		{"origin hostless", replace("origins: [http://app.localhost:5173]", "origins: [https://:443]"), "origin must be an absolute URL without credentials"},
		{"origin oversized port", replace("origins: [http://app.localhost:5173]", "origins: [https://app.example.test:65536]"), "origin port must be a number from 1 to 65535"},
		{"origin path", replace("origins: [http://app.localhost:5173]", "origins: [http://app.localhost:5173/path]"), "must not contain a path, query, or fragment"},
		{"origin uppercase scheme", replace("origins: [http://app.localhost:5173]", "origins: [HTTP://app.localhost:5173]"), "must use canonical form"},
		{"origin uppercase host", replace("origins: [http://app.localhost:5173]", "origins: [http://APP.localhost:5173]"), "must use canonical form"},
		{"origin explicit HTTP default port", replace("origins: [http://app.localhost:5173]", "origins: [http://app.localhost:80]"), "must use canonical form"},
		{"origin explicit HTTPS default port", replace("origins: [http://app.localhost:5173]", "origins: [https://app.example.test:443]"), "must use canonical form"},
		{"origin trailing-dot host", replace("origins: [http://app.localhost:5173]", "origins: [http://app.localhost.:5173]"), "must use canonical form"},
		{"spa secret", replace("        type: spa\n", "        type: spa\n        secret_hash: \"$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW\"\n"), "spa clients must not define secret_hash"},
		{"user malformed bcrypt", replace("$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW", "$2a$10$!Wq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"), "password_hash: must be a valid bcrypt hash"},
		{"user bcrypt wrong cost", replace("$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW", "$2a$11$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"), "password_hash: must be a valid bcrypt hash"},
		{"service malformed bcrypt", replace(`secret_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"`, `secret_hash: "$2a$10$!Wq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"`), "secret_hash: must be a valid bcrypt hash"},
		{"service bcrypt wrong cost", replace(`secret_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"`, `secret_hash: "$2a$11$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"`), "secret_hash: must be a valid bcrypt hash"},
		{"user noncanonical checksum tail", replace("$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW", "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylX"), "password_hash: must be a valid bcrypt hash"},
		{"service noncanonical checksum tail", replace(`secret_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"`, `secret_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylX"`), "secret_hash: must be a valid bcrypt hash"},
		{"user noncanonical salt tail", replace("$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW", "$2a$10$vWq8DjfdBvihgDARWb4jaPyhhRpU6Vgygi49GnwKTTVP45M8nPylW"), "password_hash: must be a valid bcrypt hash"},
		{"invalid allowed scope token", replace("[openid, profile, email, offline_access, api.read]", "[openid, profile, email, offline_access, api read]"), "invalid OAuth scope token"},
		{"service browser redirect", replace("        type: service\n", "        type: service\n        redirect_uris: [http://app.localhost:5173/callback]\n"), "service clients must not define browser redirects or origins"},
		{"service reserved scope", replace("allowed_scopes: [api.read]\n        roles: [worker]", "allowed_scopes: [openid, api.read]\n        roles: [worker]"), "service clients must not allow reserved OIDC scope"},
		{"duplicate user in one realm", func(s string) string {
			duplicate := `      - id: alice-two
        username: ALICE
        password_hash: "$2a$10$vWq8DjfdBvihgDARWb4jaOyhhRpU6Vgygi49GnwKTTVP45M8nPylW"
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

func TestLoadAcceptsSupportedBcryptMinorVersions(t *testing.T) {
	t.Parallel()
	for _, minor := range []string{"a", "b", "y"} {
		t.Run(minor, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			hashes := strings.ReplaceAll(validConfigYAML, "$2a$10$", "$2"+minor+"$10$")
			if err := os.WriteFile(path, []byte(hashes), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestValidateOriginAcceptsCanonicalForms(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{
		"http://localhost",
		"http://app.localhost:5173",
		"https://app.example.test",
		"https://app.example.test:8443",
		"http://127.0.0.1:8080",
		"http://[::1]",
		"http://[::1]:8080",
		"https://[::ffff:7f00:1]",
		"https://xn--bcher-kva.example",
	} {
		t.Run(origin, func(t *testing.T) {
			if err := validateOrigin(origin); err != nil {
				t.Fatalf("validateOrigin(%q) error = %v", origin, err)
			}
		})
	}
}

func TestValidateOriginRejectsNonCanonicalForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"expanded IPv6", "http://[0:0:0:0:0:0:0:1]:8080", `must use canonical form "http://[::1]:8080"`},
		{"Unicode host", "https://bücher.example", `must use canonical form "https://xn--bcher-kva.example"`},
		{"decimal IPv4 host", "http://2130706433", `must use canonical form "http://127.0.0.1"`},
		{"hex IPv4 host", "http://0x7f000001", `must use canonical form "http://127.0.0.1"`},
		{"octal IPv4 label", "http://1.2.03", `must use canonical form "http://1.2.0.3"`},
		{"out-of-range IPv4 host", "http://999.1.1.1", "host is not a valid IPv4 address"},
		{"dotted IPv4-mapped IPv6", "https://[::ffff:1.2.3.4]", `must use canonical form "https://[::ffff:102:304]"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateOrigin(tt.origin); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateOrigin(%q) error = %v, want error containing %q", tt.origin, err, tt.want)
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
