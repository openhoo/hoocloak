package idp

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/openhoo/hoocloak/internal/config"
)

//go:embed ui/*.html ui/dist/*
var uiFiles embed.FS

var uiTemplateFuncs = template.FuncMap{
	"json": func(value any) (string, error) {
		encoded, err := json.Marshal(value)
		return string(encoded), err
	},
}

var defaultUITemplates = template.Must(template.New("embedded").Funcs(uiTemplateFuncs).Option("missingkey=error").ParseFS(uiFiles, "ui/*.html"))

var defaultUIAssets = func() fs.FS {
	assets, err := fs.Sub(uiFiles, "ui/dist")
	if err != nil {
		panic(err)
	}
	return assets
}()

var supportedClaims = []string{
	"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "acr", "amr",
	"c_hash", "at_hash", "azp", "preferred_username", "name", "email", "email_verified",
}

const maxFormBodyBytes = 64 << 10

type SigningKey struct {
	Key *rsa.PrivateKey
	KID string
}

type Server struct {
	Handler http.Handler
	realms  map[string]*realmServer
}

type realmServer struct {
	Handler       http.Handler
	Provider      *op.Provider
	Store         *Store
	loginMode     string
	issuer        string
	basePath      string
	secureCookies bool
	uiTemplates   *template.Template
	uiAssets      fs.FS
	discoveryJSON []byte
	csp           string
	identities    []loginIdentity
}

func NewServer(cfg config.Config, keys map[string]SigningKey, logger *slog.Logger, clock Clock) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	uiTemplates, uiAssets, err := loadUI(cfg.UI.ThemeDir)
	if err != nil {
		return nil, fmtError("load login theme", err)
	}
	if len(keys) != len(cfg.Realms) {
		return nil, fmt.Errorf("signing keys must contain exactly one entry per realm")
	}

	server := &Server{realms: make(map[string]*realmServer, len(cfg.Realms))}
	root := http.NewServeMux()
	probes := make([]op.ProbesFn, 0, len(cfg.Realms))
	for _, realm := range cfg.Realms {
		signing, exists := keys[realm.Name]
		if !exists {
			return nil, fmt.Errorf("signing key for realm %q is required", realm.Name)
		}
		if signing.Key == nil {
			return nil, fmt.Errorf("signing key for realm %q must not be nil", realm.Name)
		}
		if signing.KID == "" {
			return nil, fmt.Errorf("signing key ID for realm %q must not be empty", realm.Name)
		}
		issuer := cfg.RealmIssuer(realm.Name)
		basePath := "/realms/" + realm.Name
		store := NewStore(realm, cfg.Tokens, basePath, signing.Key, signing.KID, clock)
		scopes := configuredScopes(realm)
		providerConfig := &op.Config{
			CryptoKey: keyDerivation(signing.Key), CryptoKeyId: signing.KID, DefaultLogoutRedirectURI: basePath + "/logged-out",
			CodeMethodS256: true, GrantTypeRefreshToken: true, AuthMethodPost: false,
			AuthMethodPrivateKeyJWT: false, SupportedUILocales: []language.Tag{language.English},
			SupportedClaims: slices.Clone(supportedClaims), SupportedScopes: scopes,
		}
		options := []op.Option{op.WithCORSOptions(nil), op.WithLogger(logger)}
		if strings.HasPrefix(cfg.BaseURL, "http://") {
			options = append(options, op.WithAllowInsecure())
		}
		provider, err := op.NewProvider(providerConfig, store, op.StaticIssuer(issuer), options...)
		if err != nil {
			return nil, fmt.Errorf("create OIDC provider for realm %q: %w", realm.Name, err)
		}
		discoveryJSON, err := json.Marshal(discoveryMetadata(issuer, scopes))
		if err != nil {
			return nil, fmt.Errorf("encode OIDC discovery document for realm %q: %w", realm.Name, err)
		}
		discoveryJSON = append(discoveryJSON, '\n')
		identities := make([]loginIdentity, 0, len(realm.Users))
		for _, user := range realm.Users {
			identities = append(identities, loginIdentity{ID: user.ID, Username: user.Username, Name: user.Name, Email: user.Email})
		}
		formActions := append([]string{"'self'"}, configuredRedirectOrigins(realm)...)
		realmRuntime := &realmServer{
			Provider: provider, Store: store, loginMode: cfg.LoginMode,
			issuer: issuer, basePath: basePath, secureCookies: strings.HasPrefix(issuer, "https://"),
			uiTemplates: uiTemplates, uiAssets: uiAssets, discoveryJSON: discoveryJSON,
			csp:        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; form-action " + strings.Join(formActions, " ") + "; base-uri 'none'; frame-ancestors 'none'",
			identities: identities,
		}
		realmMux := http.NewServeMux()
		realmMux.HandleFunc("/.well-known/openid-configuration", realmRuntime.discovery)
		realmMux.HandleFunc("/assets/", realmRuntime.asset)
		realmMux.HandleFunc("/ready", http.NotFound)
		realmMux.HandleFunc("/healthz", http.NotFound)
		issuerInterceptor := op.NewIssuerInterceptor(provider.IssuerFromRequest)
		realmMux.Handle("/login", issuerInterceptor.Handler(http.HandlerFunc(realmRuntime.login)))
		realmMux.Handle("/logged-out", issuerInterceptor.Handler(http.HandlerFunc(realmRuntime.loggedOut)))
		realmMux.Handle("/", realmRuntime.protocolGates(provider))
		corsOptions := cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodHead, http.MethodPost},
			AllowedHeaders: []string{"Accept", "Authorization", "Content-Type"}, AllowCredentials: false, MaxAge: 300,
		}
		if origins := configuredOrigins(realm); len(origins) > 0 {
			corsOptions.AllowedOrigins = origins
		} else {
			corsOptions.AllowOriginFunc = func(string) bool { return false }
		}
		corsPolicy := cors.New(corsOptions)
		realmRuntime.Handler = corsPolicy.Handler(realmMux)
		server.realms[realm.Name] = realmRuntime
		probes = append(probes, op.ReadyStorage(store))
		root.Handle(basePath+"/", http.StripPrefix(basePath, realmRuntime.Handler))
		root.HandleFunc(basePath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, basePath+"/", http.StatusPermanentRedirect)
		})
	}
	for realmName := range keys {
		if _, exists := server.realms[realmName]; !exists {
			return nil, fmt.Errorf("signing key for unknown realm %q", realmName)
		}
	}
	root.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	root.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) { op.Readiness(w, r, probes...) })
	server.Handler = root
	return server, nil
}

func loadUI(themeDir string) (*template.Template, fs.FS, error) {
	if themeDir == "" {
		return defaultUITemplates, defaultUIAssets, nil
	}

	themeFS := os.DirFS(themeDir)
	templates := template.New("theme").Funcs(uiTemplateFuncs).Option("missingkey=error")
	for _, file := range []struct {
		path string
		name string
	}{
		{path: "login.html", name: "login"},
		{path: "logged-out.html", name: "logged-out"},
	} {
		contents, err := fs.ReadFile(themeFS, file.path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", file.path, err)
		}
		if _, err := templates.New(file.name).Parse(string(contents)); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", file.path, err)
		}
	}
	assets, err := fs.Sub(themeFS, "assets")
	if err != nil {
		return nil, nil, fmt.Errorf("open assets: %w", err)
	}
	if _, err := fs.Stat(assets, "."); err != nil {
		return nil, nil, fmt.Errorf("open assets: %w", err)
	}
	if err := preflightUITemplates(templates); err != nil {
		return nil, nil, err
	}
	return templates, assets, nil
}

func preflightUITemplates(templates *template.Template) error {
	const basePath = "/realms/hoocloak-theme-preflight"
	identity := loginIdentity{ID: "user-id", Username: "username", Name: "Example User", Email: "user@example.test"}
	password := loginData{
		BasePath: basePath, RequestID: "request-id", Client: "Example client", CSRF: "csrf-token",
		Mode: config.LoginModePassword, Username: "username", Error: "invalid credentials",
	}
	selection := loginData{
		BasePath: basePath, RequestID: "request-id", Client: "Example client", CSRF: "csrf-token",
		Mode: config.LoginModeSelect, SelectedID: identity.ID, Error: "select a valid identity",
		Identities: []loginIdentity{identity},
	}
	for _, check := range []struct {
		name     string
		template string
		data     any
		mode     string
	}{{name: "login", template: "login", data: password, mode: config.LoginModePassword}, {name: "login select mode", template: "login", data: selection, mode: config.LoginModeSelect}, {name: "logged-out", template: "logged-out", data: loggedOutData{BasePath: basePath}}} {
		var rendered bytes.Buffer
		if err := templates.ExecuteTemplate(&rendered, check.template, check.data); err != nil {
			return fmt.Errorf("execute %s.html: %w", check.name, err)
		}
		output := rendered.String()
		for _, rootRelative := range []string{`="/login`, `='/login`, `="/assets/`, `='/assets/`} {
			if strings.Contains(output, rootRelative) {
				return fmt.Errorf("execute %s.html: root-relative login and asset URLs are not allowed; use .BasePath", check.name)
			}
		}
		if check.template == "login" {
			if err := validateLoginHTML(output, basePath, check.mode); err != nil {
				return fmt.Errorf("execute %s.html: %w", check.name, err)
			}
		}
	}
	return nil
}

type loginFormValidation struct {
	postForms    int
	inPost       bool
	action       string
	controls     map[string]string
	controlCount map[string]int
}

func validateLoginHTML(document, basePath, mode string) error {
	validation := loginFormValidation{controls: make(map[string]string), controlCount: make(map[string]int)}
	for offset := 0; ; {
		name, attributes, closing, next, ok, err := nextHTMLTag(document, offset)
		if err != nil {
			return fmt.Errorf("parse rendered HTML: %w", err)
		}
		if !ok {
			break
		}
		offset = next
		if name == "form" {
			if closing {
				validation.inPost = false
				continue
			}
			if validation.inPost {
				return errors.New("nested forms are not allowed")
			}
			if strings.EqualFold(attributes["method"], http.MethodPost) {
				validation.postForms++
				if validation.postForms > 1 {
					return errors.New("login page must contain exactly one POST form")
				}
				validation.inPost = true
				validation.action = attributes["action"]
				validation.controls = make(map[string]string)
				validation.controlCount = make(map[string]int)
			}
			continue
		}
		if validation.inPost && !closing && (name == "input" || name == "select" || name == "textarea" || name == "button") {
			if controlName := attributes["name"]; controlName != "" {
				switch controlName {
				case "authRequestID", "csrf", "identity", "username", "password":
					validation.controlCount[controlName]++
					if validation.controlCount[controlName] > 1 {
						return fmt.Errorf("login form must not contain duplicate %s controls", controlName)
					}
				}
				validation.controls[controlName] = strings.ToLower(attributes["type"])
			}
		}
	}
	if validation.postForms != 1 {
		return fmt.Errorf("login page must contain exactly one POST form, found %d", validation.postForms)
	}
	if validation.action != basePath+"/login" {
		return fmt.Errorf("login form action must be exactly %q", basePath+"/login")
	}
	for _, hidden := range []string{"authRequestID", "csrf"} {
		if validation.controls[hidden] != "hidden" {
			return fmt.Errorf("login form must contain hidden %s control", hidden)
		}
	}
	if mode == config.LoginModePassword {
		if _, exists := validation.controls["username"]; !exists {
			return errors.New("password login form must contain username control")
		}
		if validation.controls["password"] != "password" {
			return errors.New("password login form must contain password control")
		}
	} else if _, exists := validation.controls["identity"]; !exists {
		return errors.New("select login form must contain identity control")
	}
	return nil
}

func nextHTMLTag(document string, offset int) (string, map[string]string, bool, int, bool, error) {
	for {
		start := strings.IndexByte(document[offset:], '<')
		if start < 0 {
			return "", nil, false, len(document), false, nil
		}
		start += offset
		if strings.HasPrefix(document[start:], "<!--") {
			end := strings.Index(document[start+4:], "-->")
			if end < 0 {
				return "", nil, false, 0, false, errors.New("unterminated comment")
			}
			offset = start + 4 + end + 3
			continue
		}
		quote := byte(0)
		end := start + 1
		for ; end < len(document); end++ {
			character := document[end]
			if quote != 0 {
				if character == quote {
					quote = 0
				}
				continue
			}
			if character == '\'' || character == '"' {
				quote = character
			} else if character == '>' {
				break
			}
		}
		if end == len(document) {
			return "", nil, false, 0, false, errors.New("unterminated tag")
		}
		contents := strings.TrimSpace(document[start+1 : end])
		if contents == "" || contents[0] == '!' || contents[0] == '?' {
			offset = end + 1
			continue
		}
		closing := contents[0] == '/'
		if closing {
			contents = strings.TrimSpace(contents[1:])
		}
		nameEnd := strings.IndexAny(contents, " \t\r\n/")
		if nameEnd < 0 {
			nameEnd = len(contents)
		}
		name := strings.ToLower(contents[:nameEnd])
		attributes, err := parseHTMLAttributes(contents[nameEnd:])
		return name, attributes, closing, end + 1, true, err
	}
}

func parseHTMLAttributes(contents string) (map[string]string, error) {
	attributes := make(map[string]string)
	for offset := 0; offset < len(contents); {
		for offset < len(contents) && (contents[offset] == ' ' || contents[offset] == '\t' || contents[offset] == '\r' || contents[offset] == '\n' || contents[offset] == '/') {
			offset++
		}
		if offset == len(contents) {
			break
		}
		nameStart := offset
		for offset < len(contents) && !strings.ContainsRune(" \t\r\n=/", rune(contents[offset])) {
			offset++
		}
		name := strings.ToLower(contents[nameStart:offset])
		for offset < len(contents) && strings.ContainsRune(" \t\r\n", rune(contents[offset])) {
			offset++
		}
		value := ""
		if offset < len(contents) && contents[offset] == '=' {
			offset++
			for offset < len(contents) && strings.ContainsRune(" \t\r\n", rune(contents[offset])) {
				offset++
			}
			if offset == len(contents) {
				return nil, fmt.Errorf("attribute %q has no value", name)
			}
			if contents[offset] == '\'' || contents[offset] == '"' {
				quote := contents[offset]
				offset++
				valueStart := offset
				for offset < len(contents) && contents[offset] != quote {
					offset++
				}
				if offset == len(contents) {
					return nil, fmt.Errorf("attribute %q has an unterminated value", name)
				}
				value = contents[valueStart:offset]
				offset++
			} else {
				valueStart := offset
				for offset < len(contents) && !strings.ContainsRune(" \t\r\n/", rune(contents[offset])) {
					offset++
				}
				value = contents[valueStart:offset]
			}
		}
		attributes[name] = value
	}
	return attributes, nil
}

func keyDerivation(key *rsa.PrivateKey) [32]byte {
	return sha256.Sum256(x509.MarshalPKCS1PrivateKey(key))
}

func configuredScopes(realm config.Realm) []string {
	seen := make(map[string]struct{})
	for _, client := range realm.Clients {
		for _, scope := range client.AllowedScopes {
			seen[scope] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}
func configuredOrigins(realm config.Realm) []string {
	seen := make(map[string]struct{})
	for _, client := range realm.Clients {
		if client.Type == config.ClientTypeSPA {
			for _, origin := range client.Origins {
				seen[origin] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for origin := range seen {
		result = append(result, origin)
	}
	sort.Strings(result)
	return result
}

func (s *realmServer) discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(s.discoveryJSON)
}

func discoveryMetadata(issuer string, scopes []string) map[string]any {
	endpoint := func(path string) string { return issuer + path }
	return map[string]any{
		"issuer": issuer, "authorization_endpoint": endpoint("/authorize"), "token_endpoint": endpoint("/oauth/token"),
		"introspection_endpoint": endpoint("/oauth/introspect"), "userinfo_endpoint": endpoint("/userinfo"),
		"revocation_endpoint": endpoint("/revoke"), "end_session_endpoint": endpoint("/end_session"), "jwks_uri": endpoint("/keys"),
		"scopes_supported": slices.Clone(scopes), "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
		"grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"code_challenge_methods_supported": []string{"S256"}, "claims_supported": slices.Clone(supportedClaims),
	}
}

func (s *realmServer) protocolGates(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token", "/oauth/introspect", "/revoke":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}
		if r.Method == http.MethodPost {
			switch r.URL.Path {
			case "/authorize", "/oauth/token", "/oauth/introspect", "/revoke", "/end_session":
				r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
			}
		}
		switch r.URL.Path {
		case "/authorize":
			if !s.authorizeGate(w, r) {
				return
			}
		case "/oauth/token":
			if !s.tokenGate(w, r) {
				return
			}
		case "/oauth/introspect", "/revoke":
			if err := r.ParseForm(); err != nil {
				oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
				return
			}
			if !rejectRepeatedFormParameters(w, r, "token", "token_type_hint", "client_id", "client_secret") {
				return
			}
		case "/end_session":
			if err := r.ParseForm(); err != nil {
				oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
				return
			}
			if !rejectRepeatedFormParameters(w, r, "id_token_hint", "post_logout_redirect_uri", "state", "client_id") {
				return
			}
			if strings.TrimSpace(r.Form.Get("id_token_hint")) == "" {
				oauthError(w, http.StatusBadRequest, "invalid_request", "id_token_hint is required", false)
				return
			}
		}
		if r.URL.Path == "/userinfo" {
			s.userinfoResponse(next, w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *realmServer) authorizeGate(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
		return false
	}
	if !rejectRepeatedFormParameters(w, r, "client_id", "response_type", "response_mode", "scope", "redirect_uri", "code_challenge", "code_challenge_method") {
		return false
	}
	client := s.Store.clients[r.Form.Get("client_id")]
	if client == nil || client.config.Type != config.ClientTypeSPA {
		return true
	}
	if r.Form.Get("response_type") != "code" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_type must be code", false)
		return false
	}
	if mode := r.Form.Get("response_mode"); mode != "" && mode != "query" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_mode must be query", false)
		return false
	}
	scopes := strings.Fields(r.Form.Get("scope"))
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "openid is required", false)
		return false
	}
	for _, scope := range scopes {
		if !slices.Contains(client.config.AllowedScopes, scope) {
			oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed", false)
			return false
		}
	}
	if r.Form.Get("code_challenge") == "" || r.Form.Get("code_challenge_method") != "S256" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "PKCE with code_challenge_method=S256 is required", false)
		return false
	}
	return true
}
func rejectRepeatedFormParameters(w http.ResponseWriter, r *http.Request, parameters ...string) bool {
	for _, parameter := range parameters {
		if len(r.Form[parameter]) > 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", parameter+" must not be repeated", false)
			return false
		}
	}
	return true
}

func (s *realmServer) tokenGate(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
		return false
	}
	if !rejectRepeatedFormParameters(w, r, "grant_type", "code", "client_id", "client_secret", "redirect_uri", "code_verifier", "refresh_token", "scope") {
		return false
	}
	if r.Form.Get("grant_type") != "client_credentials" {
		return true
	}
	for _, field := range []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"} {
		if _, exists := r.Form[field]; exists {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "client credentials must use HTTP Basic authentication", true)
			return false
		}
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id == "" || secret == "" {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client credentials must use HTTP Basic authentication", true)
		return false
	}
	return true
}
func oauthError(w http.ResponseWriter, status int, code, description string, basic bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth/token"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

func (s *realmServer) userinfoResponse(next http.Handler, w http.ResponseWriter, r *http.Request) {
	capture := &responseCapture{header: make(http.Header)}
	next.ServeHTTP(capture, r)
	if capture.status == http.StatusUnauthorized || capture.status == http.StatusForbidden {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	for key, values := range capture.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := capture.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, &capture.body)
}

type responseCapture struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *responseCapture) Header() http.Header { return w.header }
func (w *responseCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *responseCapture) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func (s *realmServer) securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", s.csp)
}

func configuredRedirectOrigins(realm config.Realm) []string {
	seen := make(map[string]struct{})
	for _, client := range realm.Clients {
		if client.Type != config.ClientTypeSPA {
			continue
		}
		for _, raw := range client.RedirectURIs {
			redirect, err := url.Parse(raw)
			if err == nil {
				seen[redirect.Scheme+"://"+redirect.Host] = struct{}{}
			}
		}
	}
	origins := make([]string, 0, len(seen))
	for origin := range seen {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins
}
func (s *realmServer) asset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	file, err := s.uiAssets.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	content, ok := file.(io.ReadSeeker)
	if !ok {
		http.Error(w, "unable to serve asset", http.StatusInternalServerError)
		return
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, info.ModTime(), content)
}
func (s *realmServer) login(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w)
	switch r.Method {
	case http.MethodGet:
		s.loginGET(w, r)
	case http.MethodPost:
		s.loginPOST(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type loginIdentity struct{ ID, Username, Name, Email string }

type loginData struct {
	BasePath                                                   string
	RequestID, Client, CSRF, Mode, Username, SelectedID, Error string
	Identities                                                 []loginIdentity
}

type loggedOutData struct{ BasePath string }

func (s *realmServer) loginPageData(requestID, client, csrf string) loginData {
	mode := s.loginMode
	if mode == "" {
		mode = config.LoginModePassword
	}
	data := loginData{BasePath: s.basePath, RequestID: requestID, Client: client, CSRF: csrf, Mode: mode}
	if mode == config.LoginModeSelect {
		data.Identities = s.identities
	}
	return data
}

func (s *realmServer) loginGET(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	client, err := s.Store.LoginInfo(id)
	if err != nil {
		http.Error(w, "invalid or expired authorization request", http.StatusBadRequest)
		return
	}
	csrf, err := randomID()
	if err != nil {
		http.Error(w, "unable to create login", http.StatusInternalServerError)
		return
	}
	// #nosec G124 -- Secure is intentionally false only for validated local HTTP issuers.
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName(id), Value: csrf, Path: s.basePath + "/login", MaxAge: 600, Expires: time.Now().Add(10 * time.Minute), HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	s.renderLogin(w, http.StatusOK, s.loginPageData(id, client, csrf))
}
func (s *realmServer) loginPOST(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "login requires application/x-www-form-urlencoded", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	for _, parameter := range []string{"authRequestID", "csrf", "identity", "username", "password"} {
		if len(r.PostForm[parameter]) > 1 {
			http.Error(w, "invalid login request", http.StatusBadRequest)
			return
		}
	}
	id := r.PostForm.Get("authRequestID")
	client, err := s.Store.LoginInfo(id)
	if err != nil {
		http.Error(w, "invalid or expired authorization request", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(csrfCookieName(id))
	submitted := r.PostForm.Get("csrf")
	if err != nil || submitted == "" || !constantTimeEqual(cookie.Value, submitted) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}
	data := s.loginPageData(id, client, submitted)
	var authenticationError error
	if data.Mode == config.LoginModeSelect {
		data.SelectedID = r.PostForm.Get("identity")
		authenticationError = s.Store.SelectIdentity(id, data.SelectedID)
		data.Error = "Select a valid identity."
	} else {
		data.Username = r.PostForm.Get("username")
		authenticationError = s.Store.Authenticate(id, data.Username, r.PostForm.Get("password"))
		data.Error = "Invalid username or password."
	}
	if authenticationError != nil {
		if !errors.Is(authenticationError, errInvalidCredentials) {
			http.Error(w, "invalid or expired authorization request", http.StatusBadRequest)
			return
		}
		s.renderLogin(w, http.StatusUnauthorized, data)
		return
	}
	// #nosec G124 -- Secure is intentionally false only for validated local HTTP issuers.
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName(id), Value: "", Path: s.basePath + "/login", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, op.AuthCallbackURL(s.Provider)(r.Context(), id), http.StatusSeeOther)
}
func (s *realmServer) renderLogin(w http.ResponseWriter, status int, data loginData) {
	var body bytes.Buffer
	if err := s.uiTemplates.ExecuteTemplate(&body, "login", data); err != nil {
		http.Error(w, "unable to render login", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
func (s *realmServer) loggedOut(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet {
		var body bytes.Buffer
		if err := s.uiTemplates.ExecuteTemplate(&body, "logged-out", loggedOutData{BasePath: s.basePath}); err != nil {
			http.Error(w, "unable to render logged-out page", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = body.WriteTo(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func csrfCookieName(requestID string) string {
	digest := sha256.Sum256([]byte(requestID))
	return "hoocloak_csrf_" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

func fmtError(prefix string, err error) error { return fmt.Errorf("%s: %w", prefix, err) }
