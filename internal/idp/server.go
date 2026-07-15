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

var defaultUITemplates = template.Must(template.New("embedded").Option("missingkey=error").ParseFS(uiFiles, "ui/*.html"))

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

type Server struct {
	Handler       http.Handler
	Provider      *op.Provider
	Store         *Store
	cfg           config.Config
	secureCookies bool
	uiTemplates   *template.Template
	uiAssets      fs.FS
	discoveryJSON []byte
}

func NewServer(cfg config.Config, key *rsa.PrivateKey, kid string, logger *slog.Logger, clock Clock) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	uiTemplates, uiAssets, err := loadUI(cfg.UI.ThemeDir)
	if err != nil {
		return nil, fmtError("load login theme", err)
	}
	store := NewStore(cfg, key, kid, clock)
	scopes := configuredScopes(cfg)
	derivation := keyDerivation(key)
	providerConfig := &op.Config{
		CryptoKey: derivation, CryptoKeyId: kid, DefaultLogoutRedirectURI: "/logged-out",
		CodeMethodS256: true, GrantTypeRefreshToken: true, AuthMethodPost: false,
		AuthMethodPrivateKeyJWT: false, SupportedUILocales: []language.Tag{language.English},
		SupportedClaims: slices.Clone(supportedClaims), SupportedScopes: scopes,
	}
	options := []op.Option{op.WithCORSOptions(nil), op.WithLogger(logger)}
	if strings.HasPrefix(cfg.Issuer, "http://") {
		options = append(options, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(providerConfig, store, op.StaticIssuer(cfg.Issuer), options...)
	if err != nil {
		return nil, fmtError("create OIDC provider", err)
	}
	discoveryJSON, err := json.Marshal(discoveryMetadata(cfg, scopes))
	if err != nil {
		return nil, fmtError("encode OIDC discovery document", err)
	}
	discoveryJSON = append(discoveryJSON, '\n')

	s := &Server{
		Provider: provider, Store: store, cfg: cfg,
		secureCookies: strings.HasPrefix(cfg.Issuer, "https://"),
		uiTemplates:   uiTemplates, uiAssets: uiAssets, discoveryJSON: discoveryJSON,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/assets/", s.asset)
	issuer := op.NewIssuerInterceptor(provider.IssuerFromRequest)
	mux.Handle("/login", issuer.Handler(http.HandlerFunc(s.login)))
	mux.Handle("/logged-out", issuer.Handler(http.HandlerFunc(s.loggedOut)))
	mux.Handle("/", s.protocolGates(provider))
	origins := configuredOrigins(cfg)
	corsPolicy := cors.New(cors.Options{
		AllowedOrigins: origins, AllowedMethods: []string{http.MethodGet, http.MethodHead, http.MethodPost},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false, MaxAge: 300,
	})
	s.Handler = corsPolicy.Handler(mux)
	return s, nil
}

func loadUI(themeDir string) (*template.Template, fs.FS, error) {
	if themeDir == "" {
		return defaultUITemplates, defaultUIAssets, nil
	}

	themeFS := os.DirFS(themeDir)
	templates := template.New("theme").Option("missingkey=error")
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
	login := loginData{
		RequestID: "request-id", Client: "Example client", CSRF: "csrf-token",
		Username: "username", Error: "invalid credentials",
	}
	for _, check := range []struct {
		name string
		data any
	}{{name: "login", data: login}, {name: "logged-out", data: nil}} {
		if err := templates.ExecuteTemplate(io.Discard, check.name, check.data); err != nil {
			return fmt.Errorf("execute %s.html: %w", check.name, err)
		}
	}
	return nil
}

func keyDerivation(key *rsa.PrivateKey) [32]byte {
	return sha256.Sum256(x509.MarshalPKCS1PrivateKey(key))
}

func configuredScopes(cfg config.Config) []string {
	seen := make(map[string]struct{})
	for _, client := range cfg.Clients {
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
func configuredOrigins(cfg config.Config) []string {
	seen := make(map[string]struct{})
	for _, client := range cfg.Clients {
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

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
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

func discoveryMetadata(cfg config.Config, scopes []string) map[string]any {
	endpoint := func(path string) string { return cfg.Issuer + strings.TrimPrefix(path, "/") }
	metadata := map[string]any{
		"issuer": cfg.Issuer, "authorization_endpoint": endpoint("/authorize"), "token_endpoint": endpoint("/oauth/token"),
		"introspection_endpoint": endpoint("/oauth/introspect"), "userinfo_endpoint": endpoint("/userinfo"),
		"revocation_endpoint": endpoint("/revoke"), "end_session_endpoint": endpoint("/end_session"), "jwks_uri": endpoint("/keys"),
		"scopes_supported": slices.Clone(scopes), "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
		"grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"code_challenge_methods_supported": []string{"S256"}, "claims_supported": slices.Clone(supportedClaims),
	}
	return metadata
}

func (s *Server) protocolGates(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			switch r.URL.Path {
			case "/oauth/token", "/oauth/introspect", "/revoke", "/end_session":
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
		case "/end_session":
			if err := r.ParseForm(); err != nil {
				oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
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

func (s *Server) authorizeGate(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()
	client := s.Store.clients[query.Get("client_id")]
	if client == nil || client.config.Type != config.ClientTypeSPA {
		return true
	}
	if query.Get("response_type") != "code" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_type must be code", false)
		return false
	}
	if mode := query.Get("response_mode"); mode != "" && mode != "query" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_mode must be query", false)
		return false
	}
	scopes := strings.Fields(query.Get("scope"))
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
	if query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "PKCE with code_challenge_method=S256 is required", false)
		return false
	}
	return true
}
func (s *Server) tokenGate(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
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

func (s *Server) userinfoResponse(next http.Handler, w http.ResponseWriter, r *http.Request) {
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

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}
func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
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

type loginData struct{ RequestID, Client, CSRF, Username, Error string }

func (s *Server) loginGET(w http.ResponseWriter, r *http.Request) {
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
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName(id), Value: csrf, Path: "/login", MaxAge: 600, Expires: time.Now().Add(10 * time.Minute), HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	s.renderLogin(w, http.StatusOK, loginData{RequestID: id, Client: client, CSRF: csrf})
}
func (s *Server) loginPOST(w http.ResponseWriter, r *http.Request) {
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
	id, username := r.PostForm.Get("authRequestID"), r.PostForm.Get("username")
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
	if err := s.Store.Authenticate(id, username, r.PostForm.Get("password")); err != nil {
		if !errors.Is(err, errInvalidCredentials) {
			http.Error(w, "invalid or expired authorization request", http.StatusBadRequest)
			return
		}
		s.renderLogin(w, http.StatusUnauthorized, loginData{RequestID: id, Client: client, CSRF: submitted, Username: username, Error: "Invalid username or password."})
		return
	}
	// #nosec G124 -- Secure is intentionally false only for validated local HTTP issuers.
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName(id), Value: "", Path: "/login", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, op.AuthCallbackURL(s.Provider)(r.Context(), id), http.StatusSeeOther)
}
func (s *Server) renderLogin(w http.ResponseWriter, status int, data loginData) {
	var body bytes.Buffer
	if err := s.uiTemplates.ExecuteTemplate(&body, "login", data); err != nil {
		http.Error(w, "unable to render login", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
func (s *Server) loggedOut(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet {
		var body bytes.Buffer
		if err := s.uiTemplates.ExecuteTemplate(&body, "logged-out", nil); err != nil {
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
