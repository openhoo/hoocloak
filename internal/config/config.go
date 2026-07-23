package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/cases"
)

const (
	ClientTypeSPA     = "spa"
	ClientTypeService = "service"
	LoginModePassword = "password"
	LoginModeSelect   = "select"
)

func CanonicalUsername(value string) string {
	return cases.Fold().String(strings.TrimSpace(value))
}

var reservedScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "offline_access": true,
	"phone": true, "address": true,
}

type Config struct {
	Issuer    string      `yaml:"issuer"`
	Listen    string      `yaml:"listen"`
	UI        UIConfig    `yaml:"ui,omitempty"`
	Tokens    TokenConfig `yaml:"tokens"`
	Users     []User      `yaml:"users"`
	Clients   []Client    `yaml:"clients"`
	LoginMode string      `yaml:"-"`
}

type UIConfig struct {
	ThemeDir string `yaml:"theme_dir,omitempty"`
}

type TokenConfig struct {
	AccessTTL  Duration `yaml:"access_ttl"`
	IDTTL      Duration `yaml:"id_ttl"`
	RefreshTTL Duration `yaml:"refresh_ttl"`
}

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

type User struct {
	ID            string   `yaml:"id"`
	Username      string   `yaml:"username"`
	PasswordHash  string   `yaml:"password_hash"`
	Name          string   `yaml:"name"`
	Email         string   `yaml:"email"`
	EmailVerified bool     `yaml:"email_verified"`
	Roles         []string `yaml:"roles"`
	Permissions   []string `yaml:"permissions"`
}

type Client struct {
	ID                     string   `yaml:"id"`
	Type                   string   `yaml:"type"`
	SecretHash             string   `yaml:"secret_hash,omitempty"`
	Name                   string   `yaml:"name,omitempty"`
	RedirectURIs           []string `yaml:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris,omitempty"`
	Origins                []string `yaml:"origins,omitempty"`
	Audiences              []string `yaml:"audiences"`
	AllowedScopes          []string `yaml:"allowed_scopes"`
	Roles                  []string `yaml:"roles,omitempty"`
	Permissions            []string `yaml:"permissions,omitempty"`
}

func Load(path string) (Config, error) {
	// #nosec G304 -- the path is an explicit CLI input, not a server-controlled filename.
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode config: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	if cfg.UI.ThemeDir != "" && !filepath.IsAbs(cfg.UI.ThemeDir) {
		base, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return Config{}, fmt.Errorf("resolve ui.theme_dir: %w", err)
		}
		cfg.UI.ThemeDir = filepath.Join(base, cfg.UI.ThemeDir)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	issuer, err := validateAbsoluteURL(c.Issuer, "issuer")
	if err != nil {
		return err
	}
	if issuer.Path != "/" || issuer.RawPath != "" || issuer.RawQuery != "" || issuer.Fragment != "" || !strings.HasSuffix(c.Issuer, "/") {
		return errors.New("issuer must be an absolute root URL ending in /")
	}
	if err := validateScheme(issuer, "issuer"); err != nil {
		return err
	}
	if err := validateListen(c.Listen); err != nil {
		return err
	}
	if c.Tokens.AccessTTL.Duration <= 0 || c.Tokens.IDTTL.Duration <= 0 || c.Tokens.RefreshTTL.Duration <= 0 {
		return errors.New("all token TTLs must be positive")
	}
	if c.UI.ThemeDir != strings.TrimSpace(c.UI.ThemeDir) {
		return errors.New("ui.theme_dir must not have surrounding whitespace")
	}
	if c.LoginMode != "" && c.LoginMode != LoginModePassword && c.LoginMode != LoginModeSelect {
		return fmt.Errorf("login mode must be %q or %q", LoginModePassword, LoginModeSelect)
	}

	ids := make(map[string]string, len(c.Users)+len(c.Clients))
	usernames := make(map[string]struct{}, len(c.Users))
	for i, user := range c.Users {
		where := fmt.Sprintf("users[%d]", i)
		if err := requireID(user.ID, where, ids); err != nil {
			return err
		}
		username := CanonicalUsername(user.Username)
		if username == "" {
			return fmt.Errorf("%s.username is required", where)
		}
		if user.Username != strings.TrimSpace(user.Username) {
			return fmt.Errorf("%s.username must not have surrounding whitespace", where)
		}
		if _, exists := usernames[username]; exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		usernames[username] = struct{}{}
		if err := validBcrypt(user.PasswordHash); err != nil {
			return fmt.Errorf("%s.password_hash: %w", where, err)
		}
		if err := validatePermissions(user.Permissions, where+".permissions"); err != nil {
			return err
		}
		if err := validateNonemptyUnique(user.Roles, where+".roles"); err != nil {
			return err
		}
	}

	for i, client := range c.Clients {
		where := fmt.Sprintf("clients[%d]", i)
		if err := requireID(client.ID, where, ids); err != nil {
			return err
		}
		if err := validateNonemptyUnique(client.Audiences, where+".audiences"); err != nil || len(client.Audiences) == 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("%s.audiences must not be empty", where)
		}
		if err := validateNonemptyUnique(client.AllowedScopes, where+".allowed_scopes"); err != nil || len(client.AllowedScopes) == 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("%s.allowed_scopes must not be empty", where)
		}
		if err := validateScopeTokens(client.AllowedScopes, where+".allowed_scopes"); err != nil {
			return err
		}
		for _, scope := range client.AllowedScopes {
			if scope == "phone" || scope == "address" {
				return fmt.Errorf("%s.allowed_scopes contains unsupported reserved scope %q", where, scope)
			}
		}
		if err := validatePermissions(client.Permissions, where+".permissions"); err != nil {
			return err
		}
		if err := validateNonemptyUnique(client.Roles, where+".roles"); err != nil {
			return err
		}

		switch client.Type {
		case ClientTypeSPA:
			if client.SecretHash != "" {
				return fmt.Errorf("%s: spa clients must not define secret_hash", where)
			}
			if !slices.Contains(client.AllowedScopes, "openid") {
				return fmt.Errorf("%s: spa clients must allow openid", where)
			}
			if len(client.RedirectURIs) == 0 || len(client.Origins) == 0 {
				return fmt.Errorf("%s: spa clients require redirect_uris and origins", where)
			}
			for _, raw := range append(append([]string(nil), client.RedirectURIs...), client.PostLogoutRedirectURIs...) {
				if err := validateRedirect(raw); err != nil {
					return fmt.Errorf("%s redirect URI %q: %w", where, raw, err)
				}
			}
			for _, raw := range client.Origins {
				if err := validateOrigin(raw); err != nil {
					return fmt.Errorf("%s origin %q: %w", where, raw, err)
				}
			}
		case ClientTypeService:
			if err := validBcrypt(client.SecretHash); err != nil {
				return fmt.Errorf("%s.secret_hash: %w", where, err)
			}
			if len(client.RedirectURIs) != 0 || len(client.PostLogoutRedirectURIs) != 0 || len(client.Origins) != 0 {
				return fmt.Errorf("%s: service clients must not define browser redirects or origins", where)
			}
			for _, scope := range client.AllowedScopes {
				if reservedScopes[scope] {
					return fmt.Errorf("%s: service clients must not allow reserved OIDC scope %q", where, scope)
				}
				if !slices.Contains(client.Permissions, scope) {
					return fmt.Errorf("%s: service allowed scope %q requires the same permission", where, scope)
				}
			}
		default:
			return fmt.Errorf("%s.type must be %q or %q", where, ClientTypeSPA, ClientTypeService)
		}
	}
	return nil
}

func validateListen(value string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return errors.New("listen must be a host:port address without surrounding whitespace")
	}
	_, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("listen must be a valid host:port address")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen port must be a number from 1 to 65535")
	}
	return nil
}

func requireID(id, where string, ids map[string]string) error {
	if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) {
		return fmt.Errorf("%s.id must be nonempty and have no surrounding whitespace", where)
	}
	if previous, exists := ids[id]; exists {
		return fmt.Errorf("duplicate id %q in %s and %s", id, previous, where)
	}
	ids[id] = where
	return nil
}

func validBcrypt(hash string) error {
	if hash == "" {
		return errors.New("a bcrypt hash is required")
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return errors.New("must be a valid bcrypt hash")
	}
	return nil
}

func validatePermissions(values []string, where string) error {
	if err := validateNonemptyUnique(values, where); err != nil {
		return err
	}
	for _, value := range values {
		if reservedScopes[value] {
			return fmt.Errorf("%s contains reserved OIDC scope %q", where, value)
		}
	}
	return validateScopeTokens(values, where)
}

func validateScopeTokens(values []string, where string) error {
	for _, value := range values {
		for index := 0; index < len(value); index++ {
			character := value[index]
			if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
				return fmt.Errorf("%s contains invalid OAuth scope token %q", where, value)
			}
		}
	}
	return nil
}

func validateNonemptyUnique(values []string, where string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%s contains an empty or whitespace-padded value", where)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate value %q", where, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateAbsoluteURL(raw, kind string) (*url.URL, error) {
	if strings.ContainsAny(raw, "*\\") {
		return nil, fmt.Errorf("%s must not contain wildcards or backslashes", kind)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials", kind)
	}
	return u, nil
}

func validateScheme(u *url.URL, kind string) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !IsLocalHost(u.Hostname()) {
			return fmt.Errorf("cleartext %s is allowed only for localhost, loopback IPs, or .localhost names", kind)
		}
		return nil
	default:
		return fmt.Errorf("%s scheme must be http or https", kind)
	}
}

func validateRedirect(raw string) error {
	u, err := validateAbsoluteURL(raw, "redirect URI")
	if err != nil {
		return err
	}
	if u.Fragment != "" {
		return errors.New("fragments are not allowed")
	}
	return validateScheme(u, "redirect URI")
}

func validateOrigin(raw string) error {
	u, err := validateAbsoluteURL(raw, "origin")
	if err != nil {
		return err
	}
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not contain a path, query, or fragment")
	}
	return validateScheme(u, "origin")
}

func IsLocalHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
