package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/openhoo/hoocloak/internal/config"
)

var (
	testHashesOnce sync.Once
	testSecretHash string
	testUserHash   string
)

func testConfig(t testing.TB) config.Config {
	t.Helper()
	testHashesOnce.Do(func() {
		secretHash, err := bcrypt.GenerateFromPassword([]byte("worker-secret"), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		userHash, err := bcrypt.GenerateFromPassword([]byte("alice-password"), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		testSecretHash = string(secretHash)
		testUserHash = string(userHash)
	})
	cfg := config.Config{
		BaseURL: "http://hoocloak.localhost:8080/",
		Listen:  "127.0.0.1:8080",
		Tokens: config.TokenConfig{
			AccessTTL:  config.Duration{Duration: 5 * time.Minute},
			IDTTL:      config.Duration{Duration: 5 * time.Minute},
			RefreshTTL: config.Duration{Duration: 8 * time.Hour},
		},
		Realms: []config.Realm{{
			Name: "development",
			Users: []config.User{{
				ID: "alice", Username: "alice", PasswordHash: testUserHash,
				Name: "Alice Admin", Email: "alice@example.test", EmailVerified: true,
				Roles: []string{"admin"}, Permissions: []string{"api.read"},
			}},
			Clients: []config.Client{
				{
					ID: "react-spa", Type: config.ClientTypeSPA, Name: "React SPA",
					RedirectURIs:           []string{"http://app.localhost:5173/auth/callback"},
					PostLogoutRedirectURIs: []string{"http://app.localhost:5173/auth/logout/callback"},
					Origins:                []string{"http://app.localhost:5173"}, Audiences: []string{"hoocloak-api"},
					AllowedScopes: []string{"openid", "profile", "email", "offline_access", "api.read"},
				},
				{
					ID: "worker", Type: config.ClientTypeService, SecretHash: testSecretHash,
					Audiences: []string{"hoocloak-api"}, AllowedScopes: []string{"api.read"},
					Roles: []string{"worker"}, Permissions: []string{"api.read"},
				},
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config is invalid: %v", err)
	}
	return cfg
}

func testServer(t testing.TB, clock Clock) *realmServer {
	t.Helper()
	return testServerWithConfig(t, testConfig(t), clock)
}

func testServerWithConfig(t testing.TB, cfg config.Config, clock Clock) *realmServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewServer(cfg, map[string]SigningKey{"development": {Key: key, KID: "test-kid"}}, slog.New(slog.NewTextHandler(io.Discard, nil)), clock)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	realm := application.realms["development"]
	realm.Handler = realmPathAdapter(application.Handler, realm.basePath)
	return realm
}

func realmPathAdapter(application http.Handler, basePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		urlCopy := *r.URL
		urlCopy.Path = basePath + r.URL.Path
		clone.URL = &urlCopy
		application.ServeHTTP(w, clone)
	})
}

func BenchmarkDiscovery(b *testing.B) {
	server := testServer(b, nil)
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		server.Handler.ServeHTTP(httptest.NewRecorder(), request)
	}
}

func performRequest(handler http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestDiscoveryAdvertisesOnlyImplementedProtocol(t *testing.T) {
	server := testServer(t, nil)
	response := performRequest(server.Handler, http.MethodGet, "/.well-known/openid-configuration", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, body = %s", response.Code, response.Body.String())
	}
	var metadata map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["issuer"] != "http://hoocloak.localhost:8080/realms/development" || metadata["jwks_uri"] != "http://hoocloak.localhost:8080/realms/development/keys" {
		t.Fatalf("wrong issuer endpoints: %#v", metadata)
	}
	assertStrings := func(field string, want []string) {
		t.Helper()
		values, ok := metadata[field].([]any)
		if !ok || len(values) != len(want) {
			t.Fatalf("%s = %#v, want %v", field, metadata[field], want)
		}
		for i, value := range values {
			if value != want[i] {
				t.Fatalf("%s[%d] = %#v, want %q", field, i, value, want[i])
			}
		}
	}
	assertStrings("response_types_supported", []string{"code"})
	assertStrings("grant_types_supported", []string{"authorization_code", "refresh_token", "client_credentials"})
	assertStrings("code_challenge_methods_supported", []string{"S256"})
	assertStrings("id_token_signing_alg_values_supported", []string{"RS256"})
	assertStrings("token_endpoint_auth_methods_supported", []string{"none", "client_secret_basic"})
	for _, forbidden := range []string{"device_authorization_endpoint", "registration_endpoint", "request_parameter_supported", "check_session_iframe"} {
		if _, exists := metadata[forbidden]; exists {
			t.Errorf("discovery unexpectedly advertises %s", forbidden)
		}
	}
}

func TestApplicationOwnedProtocolGates(t *testing.T) {
	server := testServer(t, nil)
	authorizeBase := "/authorize?client_id=react-spa&response_type=code&scope=openid&redirect_uri=" + url.QueryEscape("http://app.localhost:5173/auth/callback")
	tests := []struct {
		name      string
		method    string
		target    string
		body      string
		headers   map[string]string
		status    int
		errorCode string
		challenge bool
	}{
		{"missing PKCE", http.MethodGet, authorizeBase, "", nil, http.StatusBadRequest, "invalid_request", false},
		{"plain PKCE", http.MethodGet, authorizeBase + "&code_challenge=value&code_challenge_method=plain", "", nil, http.StatusBadRequest, "invalid_request", false},
		{"unadvertised response mode", http.MethodGet, authorizeBase + "&response_mode=form_post&code_challenge=value&code_challenge_method=S256", "", nil, http.StatusBadRequest, "invalid_request", false},
		{"scope bypass", http.MethodGet, "/authorize?client_id=react-spa&response_type=code&scope=openid%20api.write&redirect_uri=" + url.QueryEscape("http://app.localhost:5173/auth/callback") + "&code_challenge=value&code_challenge_method=S256", "", nil, http.StatusBadRequest, "invalid_scope", false},
		{"form client secret", http.MethodPost, "/oauth/token", "grant_type=client_credentials&client_id=worker&client_secret=worker-secret&scope=api.read", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusUnauthorized, "invalid_client", true},
		{"query client secret", http.MethodPost, "/oauth/token?grant_type=client_credentials&client_id=worker&client_secret=worker-secret&scope=api.read", "", nil, http.StatusUnauthorized, "invalid_client", true},
		{"mixed basic and form identity", http.MethodPost, "/oauth/token", "grant_type=client_credentials&client_id=worker&scope=api.read", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic d29ya2VyOndvcmtlci1zZWNyZXQ="}, http.StatusUnauthorized, "invalid_client", true},
		{"missing logout hint", http.MethodGet, "/end_session", "", nil, http.StatusBadRequest, "invalid_request", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := performRequest(server.Handler, tt.method, tt.target, tt.body, tt.headers)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tt.status, response.Body.String())
			}
			var oauthResponse map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &oauthResponse); err != nil {
				t.Fatalf("decode OAuth error: %v; body=%s", err, response.Body.String())
			}
			if oauthResponse["error"] != tt.errorCode {
				t.Fatalf("error = %#v, want %q", oauthResponse["error"], tt.errorCode)
			}
			if tt.challenge && !strings.HasPrefix(response.Header().Get("WWW-Authenticate"), "Basic ") {
				t.Fatalf("WWW-Authenticate = %q, want Basic challenge", response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestProtocolFormsHaveBoundedBodies(t *testing.T) {
	server := testServer(t, nil)
	body := "grant_type=client_credentials&scope=" + strings.Repeat("a", maxFormBodyBytes)
	response := performRequest(server.Handler, http.MethodPost, "/oauth/token", body, map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic d29ya2VyOndvcmtlci1zZWNyZXQ=",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized token request status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestLoginRejectsNonFormContent(t *testing.T) {
	server := testServer(t, nil)
	response := performRequest(server.Handler, http.MethodPost, "/login", `{}`, map[string]string{"Content-Type": "application/json"})
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("JSON login status = %d, want 415", response.Code)
	}
}

func TestLogoutGateAcceptsFormPostedHint(t *testing.T) {
	server := testServer(t, nil)
	nextCalled := false
	handler := server.protocolGates(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	response := performRequest(
		handler,
		http.MethodPost,
		"/end_session",
		"id_token_hint=posted-token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	)
	if response.Code != http.StatusNoContent || !nextCalled {
		t.Fatalf("POSTed logout hint did not reach provider: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUserinfoInvalidBearerAlwaysReturnsChallenge(t *testing.T) {
	server := testServer(t, nil)
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				server.userinfoResponse(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "invalid bearer", status)
				}), w, r)
			})
			response := performRequest(handler, http.MethodGet, "/userinfo", "", nil)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.Code)
			}
			if got := response.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
				t.Fatalf("WWW-Authenticate = %q", got)
			}
		})
	}
}

func TestCORSUsesExactConfiguredOriginsWithoutCredentials(t *testing.T) {
	server := testServer(t, nil)
	tests := []struct {
		name       string
		origin     string
		wantOrigin string
	}{
		{"configured origin", "http://app.localhost:5173", "http://app.localhost:5173"},
		{"prefix lookalike denied", "http://app.localhost:5173.evil.test", ""},
		{"other localhost denied", "http://other.localhost:5173", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := performRequest(server.Handler, http.MethodGet, "/.well-known/openid-configuration", "", map[string]string{"Origin": tt.origin})
			if response.Header().Get("Access-Control-Allow-Origin") != tt.wantOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", response.Header().Get("Access-Control-Allow-Origin"), tt.wantOrigin)
			}
			if response.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("credentialed CORS unexpectedly enabled: %q", response.Header().Get("Access-Control-Allow-Credentials"))
			}
			if !headerContains(response.Header().Values("Vary"), "Origin") {
				t.Fatalf("Vary = %q, want Origin", response.Header().Values("Vary"))
			}
		})
	}

	preflight := performRequest(server.Handler, http.MethodOptions, "/oauth/token", "", map[string]string{
		"Origin":                         "http://app.localhost:5173",
		"Access-Control-Request-Method":  http.MethodPost,
		"Access-Control-Request-Headers": "authorization, content-type",
	})
	if preflight.Code != http.StatusNoContent || preflight.Header().Get("Access-Control-Allow-Origin") != "http://app.localhost:5173" {
		t.Fatalf("preflight status=%d origin=%q headers=%v", preflight.Code, preflight.Header().Get("Access-Control-Allow-Origin"), preflight.Header())
	}
	if !headerContains(preflight.Header().Values("Vary"), "Access-Control-Request-Method") || !headerContains(preflight.Header().Values("Vary"), "Access-Control-Request-Headers") {
		t.Fatalf("preflight Vary = %q", preflight.Header().Values("Vary"))
	}
}

func headerContains(values []string, want string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), want) {
				return true
			}
		}
	}
	return false
}

func TestServiceTokenIsRS256JWTValidatedByServedJWKS(t *testing.T) {
	server := testServer(t, nil)
	form := "grant_type=client_credentials&scope=api.read"
	response := performRequest(server.Handler, http.MethodPost, "/oauth/token", form, map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic d29ya2VyOndvcmtlci1zZWNyZXQ=",
	})
	if response.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", response.Code, response.Body.String())
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	if tokenResponse.AccessToken == "" || !strings.EqualFold(tokenResponse.TokenType, "Bearer") {
		t.Fatalf("invalid token response: %#v", tokenResponse)
	}

	keysResponse := performRequest(server.Handler, http.MethodGet, "/keys", "", nil)
	if keysResponse.Code != http.StatusOK {
		t.Fatalf("JWKS status = %d, body = %s", keysResponse.Code, keysResponse.Body.String())
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(keysResponse.Body.Bytes(), &keySet); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	keys := keySet.Key("test-kid")
	if len(keys) != 1 || keys[0].Algorithm != string(jose.RS256) || keys[0].Use != "sig" {
		t.Fatalf("served signing key = %#v", keys)
	}

	signed, err := jwt.ParseSigned(tokenResponse.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse access JWT: %v", err)
	}
	if len(signed.Headers) != 1 || signed.Headers[0].KeyID != "test-kid" || signed.Headers[0].Algorithm != string(jose.RS256) {
		t.Fatalf("JWT protected header = %#v", signed.Headers)
	}
	var claims struct {
		jwt.Claims
		ClientID          string   `json:"client_id"`
		Scope             string   `json:"scope"`
		Roles             []string `json:"role"`
		Permissions       []string `json:"permission"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
	}
	if err := signed.Claims(keys[0].Key, &claims); err != nil {
		t.Fatalf("verify JWT against served JWKS: %v", err)
	}
	if claims.Issuer != "http://hoocloak.localhost:8080/realms/development" || claims.Subject != "worker" || claims.ClientID != "worker" {
		t.Fatalf("wrong registered/principal claims: %#v", claims)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "hoocloak-api" || claims.Scope != "api.read" {
		t.Fatalf("wrong audience/scope: aud=%v scope=%q", claims.Audience, claims.Scope)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "worker" || len(claims.Permissions) != 1 || claims.Permissions[0] != "api.read" {
		t.Fatalf("wrong authorization claims: roles=%v permissions=%v", claims.Roles, claims.Permissions)
	}
	if claims.Name != "" || claims.PreferredUsername != "" {
		t.Fatalf("service token leaked human claims: name=%q username=%q", claims.Name, claims.PreferredUsername)
	}
	if claims.ID == "" || claims.Expiry == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		t.Fatalf("missing access-token time/id claims: %#v", claims.Claims)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: "http://hoocloak.localhost:8080/realms/development", Subject: "worker", Time: time.Now()}, 5*time.Second); err != nil {
		t.Fatalf("registered claims validation failed: %v", err)
	}
}

func TestServiceAccountRejectsSecretAndScopeFailures(t *testing.T) {
	server := testServer(t, nil)
	tests := []struct {
		name       string
		secret     string
		scope      string
		wantStatus int
		wantError  string
	}{
		{"wrong secret", "wrong", "api.read", http.StatusUnauthorized, "invalid_client"},
		{"missing scope", "worker-secret", "", http.StatusBadRequest, "invalid_scope"},
		{"unallowed scope", "worker-secret", "api.write", http.StatusBadRequest, "invalid_scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{"grant_type": {"client_credentials"}}
			if tt.scope != "" {
				form.Set("scope", tt.scope)
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth("worker", tt.secret)
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, req)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tt.wantStatus, response.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["error"] != tt.wantError {
				t.Fatalf("error = %#v, want %q", body["error"], tt.wantError)
			}
		})
	}
}

func TestSolidLoginShellAndEmbeddedAssets(t *testing.T) {
	server := testServer(t, nil)
	response := httptest.NewRecorder()
	server.renderLogin(response, http.StatusUnauthorized, loginData{
		BasePath:  "/realms/development",
		RequestID: "request-id",
		Client:    `client"><script>alert(1)</script>`,
		CSRF:      "csrf-token",
		Username:  "alice",
		Error:     "Invalid username or password.",
	})
	body := response.Body.String()
	for _, expected := range []string{
		`id="login-root"`,
		`data-request-id="request-id"`,
		`data-csrf="csrf-token"`,
		`data-username="alice"`,
		`src="/realms/development/assets/login.js"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("login shell is missing %q", expected)
		}
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("client name was not escaped in the login dataset")
	}

	for _, asset := range []struct {
		path        string
		contentType string
	}{
		{"/assets/login.js", "text/javascript; charset=utf-8"},
		{"/assets/login.css", "text/css; charset=utf-8"},
		{"/assets/hoocloak-logo.png", "image/png"},
	} {
		assetResponse := performRequest(server.Handler, http.MethodGet, asset.path, "", nil)
		if assetResponse.Code != http.StatusOK || assetResponse.Body.Len() == 0 {
			t.Fatalf("%s response = %d with %d bytes", asset.path, assetResponse.Code, assetResponse.Body.Len())
		}
		if got := assetResponse.Header().Get("Content-Type"); got != asset.contentType {
			t.Errorf("%s Content-Type = %q, want %q", asset.path, got, asset.contentType)
		}
		headResponse := performRequest(server.Handler, http.MethodHead, asset.path, "", nil)
		if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 || headResponse.Header().Get("Content-Length") == "" {
			t.Errorf("HEAD %s status=%d body=%d content-length=%q", asset.path, headResponse.Code, headResponse.Body.Len(), headResponse.Header().Get("Content-Length"))
		}
	}

	headers := httptest.NewRecorder()
	server.securityHeaders(headers)
	csp := headers.Header().Get("Content-Security-Policy")
	for _, expected := range []string{"script-src 'self'", "form-action 'self' http://app.localhost:5173"} {
		if !strings.Contains(csp, expected) {
			t.Fatalf("login CSP is missing %q: %q", expected, csp)
		}
	}
}

func TestLoginCSRFCookiesAreIsolatedPerAuthorizationRequest(t *testing.T) {
	server := testServer(t, nil)
	cookies := make([]*http.Cookie, 0, 2)
	for _, requestID := range []string{"request-a", "request-b"} {
		server.Store.authRequests[requestID] = &AuthRequest{
			id: requestID, clientID: "react-spa", expires: time.Now().Add(5 * time.Minute),
		}
		response := performRequest(server.Handler, http.MethodGet, "/login?authRequestID="+requestID, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("GET login for %s = %d", requestID, response.Code)
		}
		responseCookies := response.Result().Cookies()
		if len(responseCookies) != 1 {
			t.Fatalf("GET login for %s set %d cookies", requestID, len(responseCookies))
		}
		cookies = append(cookies, responseCookies[0])
	}
	if cookies[0].Name == cookies[1].Name {
		t.Fatalf("parallel authorization requests shared CSRF cookie %q", cookies[0].Name)
	}
	for _, cookie := range cookies {
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/realms/development/login" {
			t.Fatalf("unsafe CSRF cookie: %#v", cookie)
		}
	}

	form := url.Values{
		"authRequestID": {"request-a"},
		"csrf":          {cookies[0].Value},
		"username":      {"alice"},
		"password":      {"wrong-password"},
	}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	request.AddCookie(cookies[1])
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("first parallel login POST = %d, body=%s", response.Code, response.Body.String())
	}
}
func TestIdentitySelectionLogin(t *testing.T) {
	cfg := testConfig(t)
	cfg.LoginMode = config.LoginModeSelect
	server := testServerWithConfig(t, cfg, nil)
	server.Store.authRequests["request-id"] = &AuthRequest{
		id: "request-id", clientID: "react-spa", expires: time.Now().Add(5 * time.Minute), scopes: []string{"openid", "api.read"},
	}

	page := performRequest(server.Handler, http.MethodGet, "/login?authRequestID=request-id", "", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET login = %d, body=%s", page.Code, page.Body.String())
	}
	for _, expected := range []string{`data-mode="select"`, `&#34;ID&#34;:&#34;alice&#34;`, `&#34;Name&#34;:&#34;Alice Admin&#34;`} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("identity selection page is missing %q", expected)
		}
	}
	cookies := page.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("GET login set %d cookies", len(cookies))
	}
	form := url.Values{"authRequestID": {"request-id"}, "csrf": {cookies[0].Value}, "identity": {"alice"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("POST identity login = %d, body=%s", response.Code, response.Body.String())
	}
	if request := server.Store.authRequests["request-id"]; !request.done || request.subject != "alice" || !slices.Equal(request.amr, []string{"dev-select"}) {
		t.Fatalf("selected authentication state = %#v", request)
	}
}

func TestExternalLoginThemeSelection(t *testing.T) {
	themeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(themeDir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"login.html":       `<!doctype html><html lang="en"><head><title>Aurora sign in</title><link rel="stylesheet" href="{{.BasePath}}/assets/theme.css"></head><body><main class="aurora"><h1>Welcome through Aurora</h1><p>{{.Client}}</p>{{if .Error}}<p role="alert">Try again</p>{{end}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID" value="{{.RequestID}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input name="username" value="{{.Username}}"><input name="password" type="password"><button>Continue</button></form><script type="module" src="{{.BasePath}}/assets/theme.js"></script></main></body></html>`,
		"logged-out.html":  `<!doctype html><html lang="en"><head><title>Aurora signed out</title><link rel="stylesheet" href="{{.BasePath}}/assets/theme.css"></head><body><p>Session ended</p></body></html>`,
		"assets/theme.css": `.aurora { color: rebeccapurple; }`,
		"assets/theme.js":  `document.documentElement.dataset.themeReady = "true";`,
		"assets/logo.svg":  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><circle r="1"/></svg>`,
	}
	for name, contents := range files {
		path := filepath.Join(themeDir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	cfg := testConfig(t)
	cfg.UI.ThemeDir = themeDir
	server := testServerWithConfig(t, cfg, nil)

	response := httptest.NewRecorder()
	server.renderLogin(response, http.StatusUnauthorized, loginData{
		BasePath:  "/realms/development",
		RequestID: "request-id", Client: `client"><script>alert(1)</script>`,
		CSRF: "csrf-token", Username: "alice", Error: "invalid",
	})
	body := response.Body.String()
	for _, expected := range []string{
		`<title>Aurora sign in</title>`,
		`Welcome through Aurora`,
		`name="authRequestID" value="request-id"`,
		`name="csrf" value="csrf-token"`,
		`name="username" value="alice"`,
		`role="alert"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("external login theme is missing %q", expected)
		}
	}
	if strings.Contains(body, `<script>alert(1)</script>`) {
		t.Fatal("external login theme did not escape client data")
	}

	loggedOut := performRequest(server.Handler, http.MethodGet, "/logged-out", "", nil)
	if !strings.Contains(loggedOut.Body.String(), "Aurora signed out") {
		t.Fatal("external logged-out theme was not rendered")
	}

	for _, asset := range []struct {
		path        string
		contentType string
	}{
		{path: "/assets/theme.css", contentType: "text/css; charset=utf-8"},
		{path: "/assets/theme.js", contentType: "text/javascript; charset=utf-8"},
		{path: "/assets/logo.svg", contentType: "image/svg+xml"},
	} {
		assetResponse := performRequest(server.Handler, http.MethodGet, asset.path, "", nil)
		if assetResponse.Code != http.StatusOK {
			t.Errorf("%s status = %d", asset.path, assetResponse.Code)
		}
		if got := assetResponse.Header().Get("Content-Type"); got != asset.contentType {
			t.Errorf("%s Content-Type = %q, want %q", asset.path, got, asset.contentType)
		}
	}
}

func TestApplicationRouterAndRealmIsolation(t *testing.T) {
	cfg := testConfig(t)
	partnerSecretHash, err := bcrypt.GenerateFromPassword([]byte("partner-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Realms = append(cfg.Realms, config.Realm{
		Name: "partner",
		Clients: []config.Client{
			{
				ID: "partner-spa", Type: config.ClientTypeSPA,
				RedirectURIs: []string{"http://partner.localhost:5174/auth/callback"}, Origins: []string{"http://partner.localhost:5174"},
				Audiences: []string{"partner-api"}, AllowedScopes: []string{"openid", "partner.read"},
			},
			{
				ID: "worker", Type: config.ClientTypeService, SecretHash: string(partnerSecretHash),
				Audiences: []string{"partner-api"}, AllowedScopes: []string{"partner.read"},
				Roles: []string{"partner-worker"}, Permissions: []string{"partner.read"},
			},
		},
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("multi-realm config is invalid: %v", err)
	}
	developmentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	partnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewServer(cfg, map[string]SigningKey{
		"development": {Key: developmentKey, KID: "development-kid"},
		"partner":     {Key: partnerKey, KID: "partner-kid"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		path   string
		status int
	}{
		{"/healthz", http.StatusOK}, {"/ready", http.StatusOK},
		{"/.well-known/openid-configuration", http.StatusNotFound}, {"/oauth/token", http.StatusNotFound}, {"/login", http.StatusNotFound}, {"/assets/login.js", http.StatusNotFound},
		{"/realms/missing/.well-known/openid-configuration", http.StatusNotFound}, {"/realms/development/ready", http.StatusNotFound}, {"/realms/development/healthz", http.StatusNotFound},
		{"/realms/development", http.StatusPermanentRedirect},
	} {
		response := performRequest(application.Handler, http.MethodGet, check.path, "", nil)
		if response.Code != check.status {
			t.Errorf("GET %s = %d, want %d", check.path, response.Code, check.status)
		}
	}

	developmentDiscovery := performRequest(application.Handler, http.MethodGet, "/realms/development/.well-known/openid-configuration", "", map[string]string{"Origin": "http://app.localhost:5173"})
	partnerDiscovery := performRequest(application.Handler, http.MethodGet, "/realms/partner/.well-known/openid-configuration", "", map[string]string{"Origin": "http://app.localhost:5173"})
	if developmentDiscovery.Code != http.StatusOK || partnerDiscovery.Code != http.StatusOK {
		t.Fatalf("discovery statuses = %d, %d", developmentDiscovery.Code, partnerDiscovery.Code)
	}
	if developmentDiscovery.Header().Get("Access-Control-Allow-Origin") != "http://app.localhost:5173" || partnerDiscovery.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("cross-realm CORS leak: development=%q partner=%q", developmentDiscovery.Header().Get("Access-Control-Allow-Origin"), partnerDiscovery.Header().Get("Access-Control-Allow-Origin"))
	}
	var developmentMetadata, partnerMetadata map[string]any
	if err := json.Unmarshal(developmentDiscovery.Body.Bytes(), &developmentMetadata); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(partnerDiscovery.Body.Bytes(), &partnerMetadata); err != nil {
		t.Fatal(err)
	}
	if developmentMetadata["issuer"] != cfg.RealmIssuer("development") || partnerMetadata["issuer"] != cfg.RealmIssuer("partner") {
		t.Fatalf("realm issuers = %#v, %#v", developmentMetadata["issuer"], partnerMetadata["issuer"])
	}

	requestToken := func(path, secret, scope string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth("worker", secret)
		response := httptest.NewRecorder()
		application.Handler.ServeHTTP(response, request)
		return response
	}
	developmentToken := requestToken("/realms/development/oauth/token", "worker-secret", "api.read")
	partnerToken := requestToken("/realms/partner/oauth/token", "partner-secret", "partner.read")
	wrongRealm := requestToken("/realms/partner/oauth/token", "worker-secret", "partner.read")
	if developmentToken.Code != http.StatusOK || partnerToken.Code != http.StatusOK || wrongRealm.Code != http.StatusUnauthorized {
		t.Fatalf("realm token statuses = development %d, partner %d, wrong realm %d", developmentToken.Code, partnerToken.Code, wrongRealm.Code)
	}
	var developmentTokens, partnerTokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(developmentToken.Body.Bytes(), &developmentTokens); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(partnerToken.Body.Bytes(), &partnerTokens); err != nil {
		t.Fatal(err)
	}
	developmentJWKSResponse := performRequest(application.Handler, http.MethodGet, "/realms/development/keys", "", nil)
	partnerJWKSResponse := performRequest(application.Handler, http.MethodGet, "/realms/partner/keys", "", nil)
	var developmentJWKS, partnerJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(developmentJWKSResponse.Body.Bytes(), &developmentJWKS); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(partnerJWKSResponse.Body.Bytes(), &partnerJWKS); err != nil {
		t.Fatal(err)
	}
	if len(developmentJWKS.Keys) != 1 || len(partnerJWKS.Keys) != 1 || developmentJWKS.Keys[0].KeyID == partnerJWKS.Keys[0].KeyID {
		t.Fatalf("realm keys are not isolated: development=%#v partner=%#v", developmentJWKS.Keys, partnerJWKS.Keys)
	}
	developmentSigned, err := jwt.ParseSigned(developmentTokens.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	partnerSigned, err := jwt.ParseSigned(partnerTokens.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var developmentClaims, partnerClaims jwt.Claims
	if err := developmentSigned.Claims(developmentJWKS.Keys[0].Key, &developmentClaims); err != nil {
		t.Fatal(err)
	}
	if err := partnerSigned.Claims(partnerJWKS.Keys[0].Key, &partnerClaims); err != nil {
		t.Fatal(err)
	}
	if developmentClaims.Issuer != cfg.RealmIssuer("development") || partnerClaims.Issuer != cfg.RealmIssuer("partner") {
		t.Fatalf("token issuers = %q, %q", developmentClaims.Issuer, partnerClaims.Issuer)
	}
	if err := partnerSigned.Claims(developmentJWKS.Keys[0].Key, &jwt.Claims{}); err == nil {
		t.Fatal("partner token verified with development JWKS")
	}
}

func TestRealmQualifiedLoginCallbackAndAssets(t *testing.T) {
	server := testServer(t, nil)
	server.Store.authRequests["request-id"] = &AuthRequest{
		id: "request-id", clientID: "react-spa", expires: time.Now().Add(5 * time.Minute), scopes: []string{"openid", "api.read"},
	}
	page := performRequest(server.Handler, http.MethodGet, "/login?authRequestID=request-id", "", nil)
	for _, expected := range []string{`data-base-path="/realms/development"`, `href="/realms/development/assets/login.css"`, `src="/realms/development/assets/login.js"`} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("login page missing %q", expected)
		}
	}
	cookies := page.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/realms/development/login" {
		t.Fatalf("realm CSRF cookie = %#v", cookies)
	}
	form := url.Values{"authRequestID": {"request-id"}, "csrf": {cookies[0].Value}, "username": {"alice"}, "password": {"alice-password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(response.Header().Get("Location"), "http://hoocloak.localhost:8080/realms/development/authorize/callback?id=") {
		t.Fatalf("login callback = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestExternalLoginThemeRequiresCompletePackage(t *testing.T) {
	_, _, err := loadUI(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "read login.html") {
		t.Fatalf("loadUI() error = %v, want missing login.html", err)
	}
}

func TestExternalLoginThemeRejectsRootRelativeRealmURLs(t *testing.T) {
	themeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(themeDir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"login.html":      `<!doctype html><link rel="stylesheet" href="/assets/theme.css"><form action="/login"></form>`,
		"logged-out.html": `<!doctype html><link rel="stylesheet" href="/assets/theme.css">`,
	} {
		if err := os.WriteFile(filepath.Join(themeDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := loadUI(themeDir)
	if err == nil || !strings.Contains(err.Error(), "use .BasePath") {
		t.Fatalf("loadUI() error = %v, want realm-safe BasePath error", err)
	}
}

func TestExternalLoginThemeRejectsExecutionErrorsAtStartup(t *testing.T) {
	themeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(themeDir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"login.html":      `<!doctype html><title>{{.MissingField}}</title>`,
		"logged-out.html": `<!doctype html><title>Signed out</title>`,
	} {
		if err := os.WriteFile(filepath.Join(themeDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := loadUI(themeDir)
	if err == nil || !strings.Contains(err.Error(), "execute login.html") {
		t.Fatalf("loadUI() error = %v, want login execution error", err)
	}
}
