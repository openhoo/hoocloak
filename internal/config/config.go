package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/idna"
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
	BaseURL   string      `yaml:"base_url"`
	Listen    string      `yaml:"listen"`
	UI        UIConfig    `yaml:"ui,omitempty"`
	Tokens    TokenConfig `yaml:"tokens"`
	Realms    []Realm     `yaml:"realms"`
	LoginMode string      `yaml:"-"`
}

type Realm struct {
	Name    string   `yaml:"name"`
	Users   []User   `yaml:"users"`
	Clients []Client `yaml:"clients"`
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

func (c Config) RealmIssuer(name string) string {
	return strings.TrimSuffix(c.BaseURL, "/") + "/realms/" + name
}

var realmNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// The final salt and checksum characters encode surplus bits, so canonical
// bcrypt serializations constrain them: the 22nd character (salt padding)
// can only be ., O, e, or u, and the 53rd character (checksum padding) can
// only be one of .CGKOSWaeimquy26. CompareHashAndPassword regenerates the
// canonical checksum, so hashes violating this pass startup but can never
// authenticate.
var bcryptPattern = regexp.MustCompile(`^\$2[aby]\$10\$[./A-Za-z0-9]{21}[.Oeu][./A-Za-z0-9]{30}[.CGKOSWaeimquy26]$`)

func (c Config) Validate() error {
	baseURL, err := validateAbsoluteURL(c.BaseURL, "base_url")
	if err != nil {
		return err
	}
	rawScheme, _, _ := strings.Cut(c.BaseURL, ":")
	if rawScheme != baseURL.Scheme {
		return fmt.Errorf("base_url scheme must use canonical lowercase spelling %q", baseURL.Scheme)
	}
	if baseURL.Path != "/" || baseURL.RawPath != "" || baseURL.RawQuery != "" || baseURL.Fragment != "" || !strings.HasSuffix(c.BaseURL, "/") {
		return errors.New("base_url must be an absolute root URL ending in /")
	}
	if err := validateScheme(baseURL, "base_url"); err != nil {
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
	if len(c.Realms) == 0 {
		return errors.New("realms must not be empty")
	}

	realmNames := make(map[string]struct{}, len(c.Realms))
	for realmIndex, realm := range c.Realms {
		if !realmNamePattern.MatchString(realm.Name) {
			return fmt.Errorf("realms[%d].name must match %s", realmIndex, realmNamePattern.String())
		}
		if _, exists := realmNames[realm.Name]; exists {
			return fmt.Errorf("duplicate realm name %q", realm.Name)
		}
		realmNames[realm.Name] = struct{}{}

		ids := make(map[string]string, len(realm.Users)+len(realm.Clients))
		usernames := make(map[string]struct{}, len(realm.Users))
		for userIndex, user := range realm.Users {
			where := fmt.Sprintf("realms[%d].users[%d]", realmIndex, userIndex)
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
				return fmt.Errorf("realms[%d] has duplicate username %q", realmIndex, user.Username)
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

		for clientIndex, client := range realm.Clients {
			where := fmt.Sprintf("realms[%d].clients[%d]", realmIndex, clientIndex)
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
	if !bcryptPattern.MatchString(hash) {
		return errors.New("must be a valid bcrypt hash")
	}
	if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost != bcrypt.DefaultCost {
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
	if err != nil {
		if strings.Contains(err.Error(), "invalid port") {
			return nil, fmt.Errorf("%s port must be a number from 1 to 65535", kind)
		}
		return nil, fmt.Errorf("%s must be an absolute URL without credentials", kind)
	}
	if !u.IsAbs() || u.Host == "" || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials", kind)
	}
	rawPort := u.Port()
	if strings.HasSuffix(u.Host, ":") || rawPort != "" {
		port, err := strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%s port must be a number from 1 to 65535", kind)
		}
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
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return errors.New("query contains invalid percent-encoding")
	}
	if _, _, found := strings.Cut(raw, "#"); found {
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

	scheme := strings.ToLower(u.Scheme)
	authority, err := canonicalOriginHost(u.Hostname())
	if err != nil {
		return err
	}
	if rawPort := u.Port(); rawPort != "" {
		port, err := strconv.Atoi(rawPort)
		if err != nil {
			return errors.New("port must be numeric")
		}
		if !((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
			authority += ":" + strconv.Itoa(port)
		}
	}
	canonical := scheme + "://" + authority
	if raw != canonical {
		return fmt.Errorf("must use canonical form %q", canonical)
	}
	return validateScheme(u, "origin")
}

// canonicalOriginHost returns an origin host exactly as browsers serialize it
// in an Origin header: ASCII-lowercase, no trailing root dot, punycode for
// internationalized names, and canonical IPv4/IPv6 literals. Rejecting raw
// values that differ from their canonical form keeps the configured origins
// identical to the wire values later matched exactly during userinfo and
// storage origin checks.
func canonicalOriginHost(hostname string) (string, error) {
	if strings.Contains(hostname, ":") {
		return canonicalIPv6Host(hostname)
	}
	host, err := canonicalDomainHost(hostname)
	if err != nil {
		return "", err
	}
	if endsInIPv4Number(host) {
		address, err := parseBrowserIPv4Host(host)
		if err != nil {
			return "", errors.New("host is not a valid IPv4 address")
		}
		return address.String(), nil
	}
	return host, nil
}

// canonicalDomainHost lowercases and strips trailing root dots; hosts
// containing non-ASCII bytes are converted with IDNA the way browsers do, so
// they must be supplied in their punycode form to survive the canonical-form
// comparison.
func canonicalDomainHost(hostname string) (string, error) {
	ascii := true
	for index := range len(hostname) {
		if hostname[index] >= 0x80 {
			ascii = false
			break
		}
	}
	if !ascii {
		converted, err := idna.Lookup.ToASCII(hostname)
		if err != nil {
			return "", errors.New("host must be provided in punycode form")
		}
		hostname = converted
	}
	host := strings.ToLower(strings.TrimRight(hostname, "."))
	if host == "" {
		return "", errors.New("host must not be empty")
	}
	return host, nil
}

func canonicalIPv6Host(literal string) (string, error) {
	if strings.ContainsRune(literal, '%') {
		return "", errors.New("host must not contain an IPv6 zone identifier")
	}
	address, err := netip.ParseAddr(literal)
	if err != nil || !address.Is6() || address.Is4() {
		return "", errors.New("host is not a valid IPv6 address")
	}
	return "[" + serializeIPv6(address) + "]", nil
}

// serializeIPv6 formats an address following the WHATWG URL IPv6 serializer:
// the longest run of at least two zero pieces is compressed, and IPv4-mapped
// tails stay hexadecimal so output always matches browser Origin headers.
func serializeIPv6(address netip.Addr) string {
	bytes := address.As16()
	var pieces [8]uint16
	for index := range pieces {
		pieces[index] = uint16(bytes[2*index])<<8 | uint16(bytes[2*index+1])
	}
	bestIndex, bestLength, currentIndex, currentLength := -1, 1, -1, 0
	for index := range pieces {
		if pieces[index] != 0 {
			if currentLength > bestLength {
				bestIndex, bestLength = currentIndex, currentLength
			}
			currentIndex, currentLength = -1, 0
			continue
		}
		if currentIndex < 0 {
			currentIndex = index
		}
		currentLength++
	}
	if currentLength > bestLength {
		bestIndex, bestLength = currentIndex, currentLength
	}
	var builder strings.Builder
	for index := 0; index < len(pieces); index++ {
		if index == bestIndex {
			if index == 0 {
				builder.WriteByte(':')
			}
			builder.WriteByte(':')
			index += bestLength - 1
			continue
		}
		builder.WriteString(strconv.FormatUint(uint64(pieces[index]), 16))
		if index != 7 {
			builder.WriteByte(':')
		}
	}
	return builder.String()
}

// endsInIPv4Number reports whether a host ends in a decimal or 0x-hex label.
// Browsers parse such hosts as IPv4 addresses, so spellings like 2130706433
// or 1.2.03 never appear verbatim in Origin headers.
func endsInIPv4Number(host string) bool {
	parts := strings.Split(host, ".")
	last := parts[len(parts)-1]
	if last == "" {
		return false
	}
	if isRadixDigits(last, 10) {
		return true
	}
	return len(last) >= 2 && last[0] == '0' && last[1]|0x20 == 'x' &&
		(len(last) == 2 || isRadixDigits(last[2:], 16))
}

// parseBrowserIPv4Host implements the WHATWG URL IPv4 parser, including its
// deprecated hex and octal label radices and left-padding of partial
// addresses, and returns the canonical dotted-decimal form.
func parseBrowserIPv4Host(host string) (netip.Addr, error) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, errors.New("invalid IPv4 address")
	}
	var numbers [4]uint64
	for index, part := range parts {
		value, err := parseBrowserIPv4Number(part)
		if err != nil {
			return netip.Addr{}, err
		}
		if index < len(parts)-1 && value > 255 {
			return netip.Addr{}, errors.New("invalid IPv4 address")
		}
		numbers[index] = value
	}
	if limit := uint64(1) << (8 * (5 - len(parts))); numbers[len(parts)-1] >= limit {
		return netip.Addr{}, errors.New("invalid IPv4 address")
	}
	var value uint64
	for index := range len(parts) {
		if index == len(parts)-1 {
			value += numbers[index]
			break
		}
		value += numbers[index] << (8 * (3 - index))
	}
	var quad [4]byte
	quad[0], quad[1], quad[2], quad[3] = byte(value>>24), byte(value>>16), byte(value>>8), byte(value)
	return netip.AddrFrom4(quad), nil
}

func parseBrowserIPv4Number(part string) (uint64, error) {
	if part == "" {
		return 0, errors.New("invalid IPv4 address")
	}
	base, digits := 10, part
	switch {
	case len(part) >= 2 && part[0] == '0' && part[1]|0x20 == 'x':
		base, digits = 16, part[2:]
	case len(part) >= 2 && part[0] == '0':
		base, digits = 8, part[1:]
	}
	var value uint64
	for index := range len(digits) {
		digit := digits[index]
		switch {
		case digit >= '0' && digit <= '9':
			digit -= '0'
		case digit >= 'a' && digit <= 'f' && base == 16:
			digit -= 'a' - 10
		case digit >= 'A' && digit <= 'F' && base == 16:
			digit -= 'A' - 10
		default:
			return 0, errors.New("invalid IPv4 address")
		}
		if int(digit) >= base {
			return 0, errors.New("invalid IPv4 address")
		}
		value = value*uint64(base) + uint64(digit)
		if value > 0xFFFFFFFF {
			return 0, errors.New("invalid IPv4 address")
		}
	}
	return value, nil
}

func isRadixDigits(value string, base int) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		digit := value[index]
		switch {
		case digit >= '0' && digit <= '9':
		case base == 16 && digit >= 'a' && digit <= 'f':
		case base == 16 && digit >= 'A' && digit <= 'F':
		default:
			return false
		}
	}
	return true
}

func IsLocalHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
