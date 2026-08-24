package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/crypto/bcrypt"

	"github.com/openhoo/hoocloak/internal/config"
)

var (
	testHashesOnce sync.Once
	testSecretHash string
	testUserHash   string
)

const testCodeChallenge = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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

func BenchmarkHTTPHandlers(b *testing.B) {
	benchmarks := []struct {
		name   string
		method string
		target string
		body   string
		header map[string]string
	}{
		{name: "Discovery", method: http.MethodGet, target: "/.well-known/openid-configuration"},
		{name: "DiscoveryHead", method: http.MethodHead, target: "/.well-known/openid-configuration"},
		{
			name: "AuthorizeGate", method: http.MethodGet,
			target: "/authorize?client_id=react-spa&response_type=code&scope=openid+profile+api.read&redirect_uri=" + url.QueryEscape("http://app.localhost:5173/auth/callback") + "&code_challenge=" + testCodeChallenge + "&code_challenge_method=S256",
		},
		{
			name: "ClientCredentialsGate", method: http.MethodPost, target: "/oauth/token",
			body:   "grant_type=client_credentials&scope=api.read",
			header: map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("worker:worker-secret")), "Content-Type": "application/x-www-form-urlencoded"},
		},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			server := testServer(b, nil)
			b.ReportAllocs()
			iterations := 0
			for b.Loop() {
				request := httptest.NewRequest(benchmark.method, benchmark.target, strings.NewReader(benchmark.body))
				for key, value := range benchmark.header {
					request.Header.Set(key, value)
				}
				server.Handler.ServeHTTP(httptest.NewRecorder(), request)
				iterations++
				if benchmark.name == "AuthorizeGate" && iterations%512 == 0 {
					b.StopTimer()
					server.Store.mu.Lock()
					clear(server.Store.authRequests)
					server.Store.mu.Unlock()
					b.StartTimer()
				}
			}
		})
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

func TestAuthorizationPreservesSpecialCharacterRedirectURI(t *testing.T) {
	t.Parallel()
	for _, registered := range []string{
		"http://app.localhost:5173/auth/callback+mobile",
		"http://app.localhost:5173/auth/callback%2Fmobile",
	} {
		t.Run(registered, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Realms[0].Clients[0].RedirectURIs = []string{registered}
			server := testServerWithConfig(t, cfg, nil)
			alias := strings.Replace(registered, "+mobile", " mobile", 1)
			alias = strings.Replace(alias, "%2Fmobile", "/mobile", 1)
			aliasTarget := "/authorize?client_id=react-spa&response_type=code&scope=openid&redirect_uri=" +
				url.QueryEscape(alias) + "&code_challenge=" + testCodeChallenge + "&code_challenge_method=S256"
			aliasResponse := performRequest(server.Handler, http.MethodGet, aliasTarget, "", nil)
			if aliasResponse.Code != http.StatusBadRequest {
				t.Fatalf("alias redirect %q status = %d, want %d", alias, aliasResponse.Code, http.StatusBadRequest)
			}
			target := "/authorize?client_id=react-spa&response_type=code&scope=openid&redirect_uri=" +
				url.QueryEscape(registered) + "&code_challenge=" + testCodeChallenge + "&code_challenge_method=S256"
			authorize := performRequest(server.Handler, http.MethodGet, target, "", nil)
			if authorize.Code != http.StatusFound {
				t.Fatalf("authorize status = %d, want %d; location=%q body=%s", authorize.Code, http.StatusFound, authorize.Header().Get("Location"), authorize.Body.String())
			}
			loginURL := authorize.Header().Get("Location")
			parsedLogin, err := url.Parse(loginURL)
			if err != nil {
				t.Fatalf("parse login location: %v", err)
			}
			authRequestID := parsedLogin.Query().Get("authRequestID")
			if authRequestID == "" {
				t.Fatalf("login location %q has no authRequestID", loginURL)
			}
			loginPath := strings.TrimPrefix(loginURL, server.basePath)
			login := performRequest(server.Handler, http.MethodGet, loginPath, "", nil)
			if login.Code != http.StatusOK {
				t.Fatalf("login status = %d, want %d; body=%s", login.Code, http.StatusOK, login.Body.String())
			}
			cookies := login.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("login set %d cookies, want one", len(cookies))
			}
			form := url.Values{
				"authRequestID": {authRequestID},
				"csrf":          {cookies[0].Value},
				"username":      {"alice"},
				"password":      {"alice-password"},
			}
			request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookies[0])
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther {
				t.Fatalf("login status = %d, want %d; location=%q body=%s", response.Code, http.StatusSeeOther, response.Header().Get("Location"), response.Body.String())
			}
			callbackURL, err := url.Parse(response.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse callback location: %v", err)
			}
			callbackPath := strings.TrimPrefix(callbackURL.Path, server.basePath)
			if callbackURL.RawQuery != "" {
				callbackPath += "?" + callbackURL.RawQuery
			}
			completionCookies := response.Result().Cookies()
			var completionCookie *http.Cookie
			for _, cookie := range completionCookies {
				if strings.HasPrefix(cookie.Name, "hoocloak_completion_") && cookie.Value != "" {
					completionCookie = cookie
					break
				}
			}
			if completionCookie == nil {
				t.Fatalf("login did not set completion cookie: %#v", completionCookies)
			}
			callbackRequest := httptest.NewRequest(http.MethodGet, callbackPath, nil)
			callbackRequest.AddCookie(completionCookie)
			callbackRecorder := httptest.NewRecorder()
			server.Handler.ServeHTTP(callbackRecorder, callbackRequest)
			callback := callbackRecorder
			if callback.Code != http.StatusFound {
				t.Fatalf("callback status = %d, want %d; location=%q body=%s", callback.Code, http.StatusFound, callback.Header().Get("Location"), callback.Body.String())
			}
			if got := callback.Header().Get("Location"); !strings.HasPrefix(got, registered+"?code=") {
				t.Fatalf("client callback location = %q, want prefix %q", got, registered+"?code=")
			}
		})
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
func TestAuthorizationCallbackRequiresAuthenticatingBrowser(t *testing.T) {
	server := testServer(t, nil)
	authorize := performRequest(server.Handler, http.MethodGet, "/authorize?client_id=react-spa&response_type=code&scope=openid&redirect_uri="+url.QueryEscape("http://app.localhost:5173/auth/callback")+"&code_challenge="+testCodeChallenge+"&code_challenge_method=S256", "", nil)
	if authorize.Code != http.StatusFound {
		t.Fatalf("authorize status = %d", authorize.Code)
	}
	loginURL, err := url.Parse(authorize.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	requestID := loginURL.Query().Get("authRequestID")
	login := performRequest(server.Handler, http.MethodGet, strings.TrimPrefix(loginURL.Path, server.basePath)+"?authRequestID="+url.QueryEscape(requestID), "", nil)
	csrfCookies := login.Result().Cookies()
	if len(csrfCookies) != 1 {
		t.Fatalf("login cookies = %#v", csrfCookies)
	}
	form := url.Values{"authRequestID": {requestID}, "csrf": {csrfCookies[0].Value}, "username": {"alice"}, "password": {"alice-password"}}
	post := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(csrfCookies[0])
	postResponse := httptest.NewRecorder()
	server.Handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusSeeOther {
		t.Fatalf("login POST status = %d, body=%s", postResponse.Code, postResponse.Body.String())
	}
	callbackURL, err := url.Parse(postResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callbackPath := strings.TrimPrefix(callbackURL.Path, server.basePath) + "?" + callbackURL.RawQuery
	attacker := performRequest(server.Handler, http.MethodGet, callbackPath, "", nil)
	if attacker.Code != http.StatusBadRequest {
		t.Fatalf("unauthenticated callback status = %d, want 400", attacker.Code)
	}
	var completion *http.Cookie
	for _, cookie := range postResponse.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "hoocloak_completion_") && cookie.Value != "" {
			completion = cookie
			break
		}
	}
	if completion == nil {
		t.Fatalf("successful login did not set completion cookie: %#v", postResponse.Result().Cookies())
	}
	victimRequest := httptest.NewRequest(http.MethodGet, callbackPath, nil)
	victimRequest.AddCookie(completion)
	victimResponse := httptest.NewRecorder()
	server.Handler.ServeHTTP(victimResponse, victimRequest)
	if victimResponse.Code != http.StatusFound {
		t.Fatalf("authenticated callback status = %d, want 302; body=%s", victimResponse.Code, victimResponse.Body.String())
	}
	replayRequest := httptest.NewRequest(http.MethodGet, callbackPath, nil)
	replayRequest.AddCookie(completion)
	replayResponse := httptest.NewRecorder()
	server.Handler.ServeHTTP(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want 400", replayResponse.Code)
	}
}

func TestAuthorizeGateValidatesPostedParameters(t *testing.T) {
	server := testServer(t, nil)
	valid := url.Values{
		"client_id": {"react-spa"}, "response_type": {"code"}, "scope": {"openid"},
		"redirect_uri": {"http://app.localhost:5173/auth/callback"}, "code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
	}
	tests := []struct {
		name, field, value, errorCode string
	}{
		{name: "missing PKCE", field: "code_challenge", errorCode: "invalid_request"},
		{name: "plain PKCE", field: "code_challenge_method", value: "plain", errorCode: "invalid_request"},
		{name: "short PKCE", field: "code_challenge", value: "short", errorCode: "invalid_request"},
		{name: "invalid PKCE character", field: "code_challenge", value: strings.Repeat("a", 42) + "!", errorCode: "invalid_request"},
		{name: "disallowed scope", field: "scope", value: "openid api.write", errorCode: "invalid_scope"},
		{name: "response type", field: "response_type", value: "token", errorCode: "invalid_request"},
		{name: "response mode", field: "response_mode", value: "form_post", errorCode: "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := make(url.Values, len(valid))
			for key, values := range valid {
				form[key] = slices.Clone(values)
			}
			if tt.value == "" {
				form.Del(tt.field)
			} else {
				form.Set(tt.field, tt.value)
			}
			response := performRequest(server.Handler, http.MethodPost, "/authorize", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
			}
			var oauthResponse map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &oauthResponse); err != nil {
				t.Fatal(err)
			}
			if oauthResponse["error"] != tt.errorCode {
				t.Fatalf("error = %q, want %q", oauthResponse["error"], tt.errorCode)
			}
		})
	}
}

func TestAuthorizeGateRejectsDuplicateSecurityParameters(t *testing.T) {
	server := testServer(t, nil)
	valid := url.Values{
		"client_id": {"react-spa"}, "response_type": {"code"}, "scope": {"openid"},
		"redirect_uri": {"http://app.localhost:5173/auth/callback"}, "code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
		"state": {"state-value"}, "nonce": {"nonce-value"},
	}
	for _, parameter := range []string{"client_id", "response_type", "response_mode", "scope", "redirect_uri", "code_challenge", "code_challenge_method", "state", "nonce"} {
		t.Run("GET "+parameter, func(t *testing.T) {
			query := make(url.Values, len(valid))
			for key, values := range valid {
				query[key] = slices.Clone(values)
			}
			if parameter == "response_mode" {
				query[parameter] = []string{"query", "form_post"}
			} else {
				query.Add(parameter, "attacker-value")
			}
			assertInvalidAuthorizeRequest(t, performRequest(server.Handler, http.MethodGet, "/authorize?"+query.Encode(), "", nil))
		})
		t.Run("POST query-body mismatch "+parameter, func(t *testing.T) {
			body := make(url.Values, len(valid))
			for key, values := range valid {
				body[key] = slices.Clone(values)
			}
			if parameter == "response_mode" {
				body.Set(parameter, "query")
			}
			assertInvalidAuthorizeRequest(t, performRequest(server.Handler, http.MethodPost, "/authorize?"+url.Values{parameter: {"attacker-value"}}.Encode(), body.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}))
		})
	}
}
func TestMutationGatesRejectDuplicateSecurityParameters(t *testing.T) {
	server := testServer(t, nil)
	tests := []struct {
		path       string
		parameters []string
	}{
		{path: "/oauth/token", parameters: []string{"grant_type", "code", "client_id", "client_secret", "redirect_uri", "code_verifier", "refresh_token", "scope"}},
		{path: "/oauth/introspect", parameters: []string{"token", "token_type_hint", "client_id", "client_secret"}},
		{path: "/revoke", parameters: []string{"token", "token_type_hint", "client_id", "client_secret"}},
	}
	for _, tt := range tests {
		for _, parameter := range tt.parameters {
			t.Run(tt.path+" "+parameter, func(t *testing.T) {
				form := url.Values{parameter: {"first", "second"}}
				response := performRequest(server.Handler, http.MethodPost, tt.path, form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
				assertInvalidAuthorizeRequest(t, response)
			})
		}
	}
}

func assertInvalidAuthorizeRequest(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	var oauthResponse map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &oauthResponse); err != nil {
		t.Fatalf("decode OAuth error: %v; body=%s", err, response.Body.String())
	}
	if oauthResponse["error"] != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", oauthResponse["error"])
	}
}

func TestMutationEndpointsRejectGET(t *testing.T) {
	server := testServer(t, nil)
	for _, path := range []string{"/oauth/token", "/oauth/introspect", "/revoke"} {
		t.Run(path, func(t *testing.T) {
			response := performRequest(server.Handler, http.MethodGet, path, "", nil)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405; body=%s", response.Code, response.Body.String())
			}
			if allow := response.Header().Get("Allow"); allow != http.MethodPost {
				t.Fatalf("Allow = %q, want POST", allow)
			}
		})
	}
}

func TestLogoutGateRejectsDuplicateSecurityParameters(t *testing.T) {
	server := testServer(t, nil)
	for _, parameter := range []string{"id_token_hint", "post_logout_redirect_uri", "state", "client_id"} {
		t.Run(parameter, func(t *testing.T) {
			form := url.Values{"id_token_hint": {"token"}}
			form[parameter] = []string{"first", "second"}
			response := performRequest(server.Handler, http.MethodPost, "/end_session", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
			assertInvalidAuthorizeRequest(t, response)
		})
	}
}

func TestFailedAuthorizationCodeExchangeCanRetry(t *testing.T) {
	server := testServer(t, nil)
	verifier := "correct-verifier"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	request := &AuthRequest{
		id: "request-id", clientID: "react-spa", redirectURI: "http://app.localhost:5173/auth/callback",
		subject: "alice", done: true, expires: time.Now().Add(5 * time.Minute), scopes: []string{"openid", "api.read"},
		audience: []string{"hoocloak-api"}, authTime: time.Now(), amr: []string{"pwd"},
		codeChallenge: &oidc.CodeChallenge{Challenge: challenge, Method: oidc.CodeChallengeMethodS256},
	}
	server.Store.authRequests[request.id] = request
	if err := server.Store.SaveAuthCode(context.Background(), request.id, "retryable-code"); err != nil {
		t.Fatal(err)
	}
	exchange := func(codeVerifier, clientID, redirectURI string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {"retryable-code"}, "client_id": {clientID},
			"redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
		}
		return performRequest(server.Handler, http.MethodPost, "/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
	for _, failed := range []struct{ name, verifier, clientID, redirectURI string }{
		{name: "verifier", verifier: "wrong-verifier", clientID: "react-spa", redirectURI: request.redirectURI},
		{name: "client", verifier: verifier, clientID: "missing-client", redirectURI: request.redirectURI},
		{name: "redirect", verifier: verifier, clientID: "react-spa", redirectURI: "http://app.localhost:5173/wrong"},
	} {
		t.Run(failed.name, func(t *testing.T) {
			response := exchange(failed.verifier, failed.clientID, failed.redirectURI)
			if response.Code == http.StatusOK {
				t.Fatalf("invalid exchange succeeded: %s", response.Body.String())
			}
		})
	}
	response := exchange(verifier, "react-spa", request.redirectURI)
	if response.Code != http.StatusOK {
		t.Fatalf("valid retry status = %d, body=%s", response.Code, response.Body.String())
	}
	second := exchange(verifier, "react-spa", request.redirectURI)
	if second.Code == http.StatusOK {
		t.Fatalf("authorization code redeemed twice: %s", second.Body.String())
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

func TestServiceOnlyRealmDeniesAllCORS(t *testing.T) {
	cfg := testConfig(t)
	cfg.Realms[0].Users = nil
	cfg.Realms[0].Clients = cfg.Realms[0].Clients[1:]
	if err := cfg.Validate(); err != nil {
		t.Fatalf("service-only config is invalid: %v", err)
	}
	server := testServerWithConfig(t, cfg, nil)
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		headers := map[string]string{"Origin": "https://attacker.example"}
		if method == http.MethodOptions {
			headers["Access-Control-Request-Method"] = http.MethodPost
		}
		response := performRequest(server.Handler, method, "/.well-known/openid-configuration", "", headers)
		if origin := response.Header().Get("Access-Control-Allow-Origin"); origin != "" {
			t.Fatalf("%s Access-Control-Allow-Origin = %q, want empty", method, origin)
		}
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
func TestLoginRejectsDuplicateSecurityParameters(t *testing.T) {
	server := testServer(t, nil)
	server.Store.authRequests["request-id"] = &AuthRequest{id: "request-id", clientID: "react-spa", expires: time.Now().Add(5 * time.Minute)}
	page := performRequest(server.Handler, http.MethodGet, "/login?authRequestID=request-id", "", nil)
	cookies := page.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("GET login set %d cookies", len(cookies))
	}
	valid := url.Values{"authRequestID": {"request-id"}, "csrf": {cookies[0].Value}, "identity": {"alice"}, "username": {"alice"}, "password": {"wrong-password"}}
	for _, parameter := range []string{"authRequestID", "csrf", "identity", "username", "password"} {
		t.Run(parameter, func(t *testing.T) {
			form := make(url.Values, len(valid)+1)
			for key, values := range valid {
				form[key] = slices.Clone(values)
			}
			form.Add(parameter, "attacker-value")
			request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookies[0])
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
			}
		})
	}
}
func TestConfiguredRedirectOriginsCanonicalizeCSPHosts(t *testing.T) {
	tests := []struct {
		name, raw, want string
	}{
		{"unicode", "https://BÜCHER.example/callback", "https://xn--bcher-kva.example"},
		{"trailing dot", "https://APP.example./callback", "https://app.example"},
		{"IPv6", "https://[2001:DB8::1]:8443/callback", "https://[2001:db8::1]:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalRedirectOrigin(tt.raw)
			if err != nil || got != tt.want {
				t.Fatalf("canonicalRedirectOrigin(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
			}
		})
	}
	if _, err := canonicalRedirectOrigin("https://under_score.example/callback"); err == nil {
		t.Fatal("underscore hostname accepted as CSP origin")
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
		"login.html":       `<!doctype html><html lang="en"><head><title>Aurora sign in</title><link rel="stylesheet" href="{{.BasePath}}/assets/theme.css"></head><body><main class="aurora"><h1>Welcome through Aurora</h1><p>{{.Client}}</p>{{if .Error}}<p role="alert">Try again</p>{{end}}{{if eq .Mode "select"}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID" value="{{.RequestID}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><select name="identity">{{range .Identities}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select><button>Continue</button></form>{{else}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID" value="{{.RequestID}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input name="username" value="{{.Username}}"><input name="password" type="password"><button>Continue</button></form>{{end}}<script type="module" src="{{.BasePath}}/assets/theme.js"></script></main></body></html>`,
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
func TestLoginRejectsMismatchedAndReplayedCSRF(t *testing.T) {
	for _, mode := range []string{config.LoginModePassword, config.LoginModeSelect} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.LoginMode = mode
			server := testServerWithConfig(t, cfg, nil)
			requestID := "csrf-" + mode
			server.Store.authRequests[requestID] = &AuthRequest{id: requestID, clientID: "react-spa", expires: time.Now().Add(5 * time.Minute), scopes: []string{"openid"}}
			page := performRequest(server.Handler, http.MethodGet, "/login?authRequestID="+requestID, "", nil)
			cookies := page.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("login cookies = %#v", cookies)
			}
			form := url.Values{"authRequestID": {requestID}, "csrf": {"wrong-csrf"}}
			if mode == config.LoginModePassword {
				form.Set("username", "alice")
				form.Set("password", "alice-password")
			} else {
				form.Set("identity", "alice")
			}
			post := func(values url.Values) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(cookies[0])
				response := httptest.NewRecorder()
				server.Handler.ServeHTTP(response, req)
				return response
			}
			mismatch := post(form)
			if mismatch.Code != http.StatusBadRequest || !strings.Contains(mismatch.Body.String(), "invalid CSRF token") {
				t.Fatalf("mismatched CSRF response = %d %q", mismatch.Code, mismatch.Body.String())
			}
			if server.Store.authRequests[requestID].done {
				t.Fatal("mismatched CSRF completed authorization")
			}
			form.Set("csrf", cookies[0].Value)
			success := post(form)
			if success.Code != http.StatusSeeOther {
				t.Fatalf("successful login status = %d, body=%s", success.Code, success.Body.String())
			}
			request := server.Store.authRequests[requestID]
			subject, amr := request.subject, slices.Clone(request.amr)
			replay := post(form)
			if replay.Code != http.StatusBadRequest {
				t.Fatalf("replayed login status = %d, want 400", replay.Code)
			}
			if request.subject != subject || !slices.Equal(request.amr, amr) {
				t.Fatalf("replay changed authentication state: subject=%q amr=%v", request.subject, request.amr)
			}
		})
	}
}

func TestApplicationRouterAndRealmIsolation(t *testing.T) {
	cfg := testConfig(t)
	partnerSecretHash, err := bcrypt.GenerateFromPassword([]byte("partner-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	partnerUserHash, err := bcrypt.GenerateFromPassword([]byte("partner-alice-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Realms = append(cfg.Realms, config.Realm{
		Name: "partner",
		Users: []config.User{{
			ID: "alice", Username: "alice", PasswordHash: string(partnerUserHash),
			Name: "Alice Partner", Email: "alice@partner.example", Roles: []string{"partner-admin"}, Permissions: []string{"partner.read"},
		}},
		Clients: []config.Client{
			{
				ID: "react-spa", Type: config.ClientTypeSPA,
				RedirectURIs: []string{"http://partner.localhost:5174/auth/callback"}, Origins: []string{"http://partner.localhost:5174"},
				Audiences: []string{"partner-api"}, AllowedScopes: []string{"openid", "profile", "partner.read"},
			},
			{
				ID: "partner-spa", Type: config.ClientTypeSPA,
				RedirectURIs: []string{"http://partner.localhost:5174/other-callback"}, Origins: []string{"http://partner.localhost:5174"},
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
	verifier := "interactive-verifier"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	interactive := func(realm, password, redirect string) (string, string) {
		runtime := application.realms[realm]
		requestID := "same-request-id"
		runtime.Store.authRequests[requestID] = &AuthRequest{
			id: requestID, clientID: "react-spa", redirectURI: redirect, subject: "alice",
			responseType: oidc.ResponseType("code"), responseMode: oidc.ResponseMode("query"),
			expires: time.Now().Add(5 * time.Minute), scopes: []string{"openid", "profile"},
			audience: []string{"partner-api"}, codeChallenge: &oidc.CodeChallenge{Challenge: challenge, Method: oidc.CodeChallengeMethodS256},
		}
		page := performRequest(application.Handler, http.MethodGet, "/realms/"+realm+"/login?authRequestID="+requestID, "", nil)
		if page.Code != http.StatusOK {
			t.Fatalf("%s login page status = %d", realm, page.Code)
		}
		csrf := page.Result().Cookies()[0]
		form := url.Values{"authRequestID": {requestID}, "csrf": {csrf.Value}, "username": {"alice"}, "password": {password}}
		req := httptest.NewRequest(http.MethodPost, "/realms/"+realm+"/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrf)
		response := httptest.NewRecorder()
		application.Handler.ServeHTTP(response, req)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("%s login POST status = %d, body=%s", realm, response.Code, response.Body.String())
		}
		var completion *http.Cookie
		for _, cookie := range response.Result().Cookies() {
			if strings.HasPrefix(cookie.Name, "hoocloak_completion_") && cookie.Value != "" {
				completion = cookie
				break
			}
		}
		if completion == nil {
			t.Fatalf("%s missing completion cookie", realm)
		}
		callbackURL, err := url.Parse(response.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		callback := httptest.NewRequest(http.MethodGet, callbackURL.Path+"?"+callbackURL.RawQuery, nil)
		callback.AddCookie(completion)
		callbackResponse := httptest.NewRecorder()
		application.Handler.ServeHTTP(callbackResponse, callback)
		if callbackResponse.Code != http.StatusFound {
			t.Fatalf("%s callback status = %d, body=%s", realm, callbackResponse.Code, callbackResponse.Body.String())
		}
		redirectURL, err := url.Parse(callbackResponse.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse %s callback redirect: %v", realm, err)
		}
		code := redirectURL.Query().Get("code")
		if code == "" {
			t.Fatalf("%s callback redirect = %q", realm, callbackResponse.Header().Get("Location"))
		}
		return code, completion.Name
	}
	developmentCode, _ := interactive("development", "alice-password", "http://app.localhost:5173/auth/callback")
	partnerCode, _ := interactive("partner", "partner-alice-password", "http://partner.localhost:5174/auth/callback")
	if developmentCode == "" || partnerCode == "" || developmentCode == partnerCode {
		t.Fatalf("interactive realm codes = %q, %q", developmentCode, partnerCode)
	}
	exchange := func(realm, code string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"react-spa"},
			"redirect_uri":  {map[string]string{"development": "http://app.localhost:5173/auth/callback", "partner": "http://partner.localhost:5174/auth/callback"}[realm]},
			"code_verifier": {verifier}}
		return performRequest(application.Handler, http.MethodPost, "/realms/"+realm+"/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
	if cross := exchange("partner", developmentCode); cross.Code == http.StatusOK {
		t.Fatal("development authorization code redeemed in partner realm")
	}
	if cross := exchange("development", partnerCode); cross.Code == http.StatusOK {
		t.Fatal("partner authorization code redeemed in development realm")
	}
	developmentInteractive := exchange("development", developmentCode)
	partnerInteractive := exchange("partner", partnerCode)
	if developmentInteractive.Code != http.StatusOK || partnerInteractive.Code != http.StatusOK {
		t.Fatalf("interactive token status = %d, %d", developmentInteractive.Code, partnerInteractive.Code)
	}
	var developmentInteractiveToken, partnerInteractiveToken struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(developmentInteractive.Body.Bytes(), &developmentInteractiveToken); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(partnerInteractive.Body.Bytes(), &partnerInteractiveToken); err != nil {
		t.Fatal(err)
	}
	developmentSigned, err = jwt.ParseSigned(developmentInteractiveToken.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	partnerSigned, err = jwt.ParseSigned(partnerInteractiveToken.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var developmentProfile, partnerProfile struct {
		jwt.Claims
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := developmentSigned.Claims(developmentJWKS.Keys[0].Key, &developmentProfile); err != nil {
		t.Fatal(err)
	}
	if err := partnerSigned.Claims(partnerJWKS.Keys[0].Key, &partnerProfile); err != nil {
		t.Fatal(err)
	}
	if developmentProfile.Issuer != cfg.RealmIssuer("development") || partnerProfile.Issuer != cfg.RealmIssuer("partner") ||
		developmentProfile.Name != "Alice Admin" || partnerProfile.Name != "Alice Partner" ||
		developmentProfile.PreferredUsername != "alice" || partnerProfile.PreferredUsername != "alice" {
		t.Fatalf("interactive realm profiles = %#v, %#v", developmentProfile, partnerProfile)
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
		"login.html":      `<!doctype html><link rel="stylesheet" href="/assets/theme.css"><form method="post" action="/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`,
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

func TestExternalLoginThemePreflightsSelectMode(t *testing.T) {
	themeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(themeDir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"login.html":      `<!doctype html>{{if eq .Mode "select"}}{{(index .Identities 0).MissingField}}{{end}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID" value="{{.RequestID}}"><input type="hidden" name="csrf" value="{{.CSRF}}">{{if eq .Mode "select"}}<select name="identity"></select>{{else}}<input name="username"><input name="password" type="password">{{end}}</form>`,
		"logged-out.html": `<!doctype html><title>Signed out</title>`,
	} {
		if err := os.WriteFile(filepath.Join(themeDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := loadUI(themeDir)
	if err == nil || !strings.Contains(err.Error(), "login select mode") {
		t.Fatalf("loadUI() error = %v, want select-mode execution error", err)
	}
}

func TestExternalLoginThemeStructurallyValidatesEveryMode(t *testing.T) {
	tests := []struct {
		name, login, want string
	}{
		{name: "absolute action", login: `<form method="post" action="https://evil.example/realms/hoocloak-theme-preflight/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, want: "action must be exactly"},
		{name: "protocol-relative action", login: `<form method="post" action="//evil.example/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, want: "action must be exactly"},
		{name: "multiple post forms", login: `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form><form method="post" action="{{.BasePath}}/login"></form>`, want: "exactly one POST form"},
		{name: "separated post forms", login: `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form><form method="get"></form><form method="post" action="{{.BasePath}}/login"></form>`, want: "exactly one POST form"},
		{name: "non-hidden csrf", login: `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input name="csrf"><input name="username"><input name="password" type="password"></form>`, want: "hidden csrf"},
		{name: "password controls only", login: `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, want: "select login form must contain identity"},
		{name: "select controls only", login: `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><select name="identity"></select></form>`, want: "password login form must contain username"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			themeDir := writeExternalTheme(t, tt.login)
			_, _, err := loadUI(themeDir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadUI() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestExternalLoginThemeRejectsDuplicateSensitiveControls(t *testing.T) {
	tests := []struct {
		name      string
		duplicate string
	}{
		{name: "auth request ID", duplicate: `<input type="hidden" name="authRequestID">`},
		{name: "CSRF", duplicate: `<input type="hidden" name="csrf">`},
		{name: "identity", duplicate: `{{if eq .Mode "select"}}<select name="identity"></select>{{end}}`},
		{name: "username", duplicate: `{{if eq .Mode "password"}}<input name="username">{{end}}`},
		{name: "password", duplicate: `{{if eq .Mode "password"}}<input name="password" type="password">{{end}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			login := `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf">{{if eq .Mode "select"}}<select name="identity"></select>{{else}}<input name="username"><input name="password" type="password">{{end}}` + tt.duplicate + `</form>`
			_, _, err := loadUI(writeExternalTheme(t, login))
			if err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("loadUI() error = %v, want duplicate-control error", err)
			}
		})
	}
}

func TestExternalLoginThemeAcceptsValidDualModeForms(t *testing.T) {
	themeDir := writeExternalTheme(t, `{{if eq .Mode "select"}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><select name="identity"><option value="user-id">Example User</option></select></form>{{else}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>{{end}}`)
	if _, _, err := loadUI(themeDir); err != nil {
		t.Fatalf("loadUI() error = %v", err)
	}
}

func TestProviderEndpointPolicyAndThemeAssetConfine(t *testing.T) {
	server := testServer(t, nil)
	for _, tt := range []struct {
		path, method, allow string
	}{
		{"/authorize", http.MethodPut, "GET, POST"},
		{"/authorize/callback", http.MethodPost, "GET"},
		{"/oauth/token", http.MethodGet, "POST"},
		{"/oauth/introspect", http.MethodGet, "POST"},
		{"/revoke", http.MethodGet, "POST"},
		{"/userinfo", http.MethodPut, "GET, POST"},
		{"/end_session", http.MethodPut, "GET, POST"},
		{"/keys", http.MethodPost, "GET, HEAD"},
	} {
		t.Run(tt.path+" "+tt.method, func(t *testing.T) {
			response := performRequest(server.Handler, tt.method, tt.path, "", nil)
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != tt.allow {
				t.Fatalf("status=%d allow=%q, want 405/%q", response.Code, response.Header().Get("Allow"), tt.allow)
			}
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
		response := performRequest(server.Handler, method, "/device_authorization", "", nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s device endpoint status=%d, want 404", method, response.Code)
		}
	}
	preflightRequest := httptest.NewRequest(http.MethodOptions, "/device_authorization", nil)
	preflightRequest.Header.Set("Origin", "http://app.localhost:5173")
	preflightRequest.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflightResponse := httptest.NewRecorder()
	server.Handler.ServeHTTP(preflightResponse, preflightRequest)
	if preflightResponse.Code != http.StatusNotFound {
		t.Fatalf("device preflight status=%d, want 404", preflightResponse.Code)
	}
	token := performRequest(server.Handler, http.MethodPost, "/oauth/token", "grant_type=client_credentials", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if token.Code != http.StatusUnauthorized {
		t.Fatalf("token status = %d, want 401; body=%s", token.Code, token.Body.String())
	}
	if token.Header().Get("Cache-Control") != "no-store" || token.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token response headers = %#v", token.Header())
	}

	themeDir := writeExternalTheme(t, `{{if eq .Mode "select"}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><select name="identity"><option value="user-id">Example User</option></select></form>{{else}}<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>{{end}}`)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(themeDir, "assets", "leak.txt")); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.UI.ThemeDir = themeDir
	external := testServerWithConfig(t, cfg, nil)
	response := performRequest(external.Handler, http.MethodGet, "/assets/leak.txt", "", nil)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "secret outside") {
		t.Fatalf("symlink asset response=%d body=%q, want confined 404", response.Code, response.Body.String())
	}
}

func TestAuthorizeRejectsOversizedStateAndNonce(t *testing.T) {
	server := testServer(t, nil)
	base := url.Values{
		"client_id": {"react-spa"}, "response_type": {"code"}, "scope": {"openid"},
		"redirect_uri": {"http://app.localhost:5173/auth/callback"}, "code_challenge": {testCodeChallenge}, "code_challenge_method": {"S256"},
	}
	for _, field := range []string{"state", "nonce"} {
		t.Run(field, func(t *testing.T) {
			form := make(url.Values, len(base)+1)
			for key, values := range base {
				form[key] = slices.Clone(values)
			}
			form.Set(field, strings.Repeat("x", maxAuthorizeFieldBytes+1))
			response := performRequest(server.Handler, http.MethodPost, "/authorize", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s status=%d, want 400", field, response.Code)
			}
			if len(server.Store.authRequests) != 0 {
				t.Fatalf("%s created pending authorization state", field)
			}
		})
	}
}

func TestExternalLoginThemePreflightBrowserEffectiveControls(t *testing.T) {
	tests := []struct {
		name, login, want string
	}{
		{"literal duplicate attribute", `<form method="get" method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "must not be repeated"},
		{"nested form inside GET form", `<form method="get"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form></form>`, "nested forms"},
		{"associated submitter override", `<form id="login" method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form><button type="submit" form="login" formmethod="get">Continue</button>`, "form method"},
		{"form-feed duplicate attribute", `<form method="post"` + "\f" + `method="get" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "must not be repeated"},
		{"encoded attribute name stays literal", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input na&#x6d;e="username"><input name="password" type="password"></form>`, "username control"},
		{"unquoted root asset", `<img src=/assets/leak.css><form method=post action="{{.BasePath}}/login"><input type=hidden name=authRequestID><input type=hidden name=csrf><input name=username><input name=password type=password></form>`, "root-relative"},
		{"disabled password", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password" disabled></form>`, "must not be disabled"},
		{"disabled fieldset", `<form method="post" action="{{.BasePath}}/login"><fieldset disabled><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></fieldset></form>`, "must not be disabled"},
		{"form action override", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"><button type="submit" formaction="http://app.localhost:5173/steal">Continue</button></form>`, "override"},
		{"form method override", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"><button type="submit" formmethod="get">Continue</button></form>`, "form method"},
		{"form encoding", `<form method="post" enctype="multipart/form-data" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "urlencoded"},
		{"form encoding override", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"><button type="submit" formenctype="text/plain">Continue</button></form>`, "form encoding"},
		{"fragmented root asset", `<img src="/assets#icon"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root asset in srcset", `<img srcset="https://app.example.test/asset.png 1x, /assets/image.png 2x"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root video poster", `<video poster="/assets/video.png"></video><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root SVG image", `<svg><image xlink:href="/assets/logo.svg"></image></svg><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root object data", `<object data="/assets/document.html"></object><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root legacy background", `<table background="/assets/table.png"></table><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root asset with backslashes", `<img src="/assets\logo.svg"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root login with backslashes", `<a href="/login\x">Broken login</a><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root login through dot segment", `<a href="/x/../login">Broken login</a><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root asset through encoded dot segment", `<img src="/x/%2e%2e/assets/logo.svg"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root asset with ignored tab", `<img src="/ass&#x09;ets/logo.svg"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root asset with leading C0 control", `<img src="&#x01;/assets/logo.svg"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root asset with invalid percent escape", `<img src="/assets/%zz"><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"root login with invalid percent escape", `<a href="/login/%zz">Broken login</a><form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></form>`, "root-relative"},
		{"nested legend remains disabled", `<form method="post" action="{{.BasePath}}/login"><fieldset disabled><div><legend><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></legend></div></fieldset></form>`, "must not be disabled"},
		{"second legend remains disabled", `<form method="post" action="{{.BasePath}}/login"><fieldset disabled><legend>Label</legend><legend><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password"></legend></fieldset></form>`, "must not be disabled"},
		{"whitespace hidden value", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name='authRequestID' value=' {{.RequestID}} '><input type="hidden" name='csrf' value='{{.CSRF}}'><input name="username"><input name="password" type="password"></form>`, "exactly match"},
		{"reassociated password", `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf"><input name="username"><input name="password" type="password" form="other"></form>`, "reassociation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeExternalTheme(t, tt.login)
			_, _, err := loadUI(dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadUI() error=%v, want %q", err, tt.want)
			}
		})
	}
	t.Run("disabled fieldset first legend exemption", func(t *testing.T) {
		const basePath = "/realms/theme-test"
		login := `<form method="post" enctype="application/x-www-form-urlencoded" action="` + basePath + `/login"><fieldset disabled><legend><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="username"><input name="password" type="password"></legend></fieldset></form>`
		if err := validateLoginHTML(login, basePath, config.LoginModePassword, "request-id", "csrf-token"); err != nil {
			t.Fatalf("validateLoginHTML() error=%v", err)
		}
	})
	for _, tt := range []struct {
		name, requestID, csrf string
	}{
		{"missing request ID", "", "csrf-token"},
		{"wrong request ID", "wrong", "csrf-token"},
		{"missing csrf", "request-id", ""},
		{"wrong csrf", "request-id", "wrong"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			login := `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID" value="` + tt.requestID + `"><input type="hidden" name="csrf" value="` + tt.csrf + `"><input name="username"><input name="password" type="password"></form>`
			dir := writeExternalTheme(t, login)
			if err := os.WriteFile(filepath.Join(dir, "login.html"), []byte(login), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadUI(dir)
			if err == nil || !strings.Contains(err.Error(), "exactly match") {
				t.Fatalf("loadUI() error=%v, want hidden-value rejection", err)
			}
		})
	}
}

func TestThemePreflightUsesBrowserTokenization(t *testing.T) {
	const basePath = "/realms/theme-test"
	for _, tt := range []struct {
		name string
		body string
	}{
		{
			name: "textarea text is not markup",
			body: `<form method="post" action="` + basePath + `/login"><textarea name="username"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="password" type="password"></textarea></form>`,
		},
		{
			name: "template controls are inert",
			body: `<form method="post" action="` + basePath + `/login"><input name="username"><template><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="password" type="password"></template></form>`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateLoginHTML(tt.body, basePath, config.LoginModePassword, "request-id", "csrf-token"); err == nil {
				t.Fatal("validateLoginHTML() accepted inert required controls")
			}
		})
	}
	for _, mode := range []string{"open", "closed"} {
		shadow := `<div><template shadowrootmode="` + mode + `"><form method="post" action="` + basePath + `/login"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="username"><input name="password" type="password"></form></template></div>`
		if err := validateLoginHTML(shadow, basePath, config.LoginModePassword, "request-id", "csrf-token"); err != nil {
			t.Fatalf("%s declarative shadow login rejected: %v", mode, err)
		}
	}
	if err := validateLoginHTML(`<form method="post" action="`+basePath+`/login"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="username"><input name="password" type="password"></form><template shadowrootmode="open"><form method="post" action="`+basePath+`/login"></form></template>`, basePath, config.LoginModePassword, "request-id", "csrf-token"); err == nil {
		t.Fatal("additional declarative shadow POST form was accepted")
	}
	if err := validateRealmRelativeURLs(`<svg><style><div><img src="/assets/breakout.png"></div></style></svg>`); err == nil {
		t.Fatal("foreign raw-text breakout URL was accepted")
	}
	if err := validateRealmRelativeURLs(`<template shadowrootmode="open"><img src="/assets/shadow.png"></template>`); err == nil {
		t.Fatal("declarative shadow root URL was accepted")
	}
	if err := validateRealmRelativeURLs(`<img srcset="data:image/svg+xml,%3Csvg%3E,/assets/logo.svg%3C/svg%3E 1x">`); err != nil {
		t.Fatalf("data URL with internal comma rejected: %v", err)
	}
	if err := validateRealmRelativeURLs(`<img srcset="https://example.test/image.png 1x, /assets/logo.svg 2x">`); err == nil {
		t.Fatal("genuine later root-relative srcset candidate was accepted")
	}
	if err := validateLoginHTML(`<form method="get"><button type="submit" formaction="/search">Search</button></form><form method="post" action="`+basePath+`/login"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="username"><input name="password" type="password"></form>`, basePath, config.LoginModePassword, "request-id", "csrf-token"); err != nil {
		t.Fatalf("unrelated GET submitter override rejected: %v", err)
	}
	if err := validateRealmRelativeURLs(`<script>const example = '<img src="/assets/example.png">'</script><template><img src="/assets/template.png"></template><img src="` + basePath + `/assets/live.png">`); err != nil {
		t.Fatalf("validateRealmRelativeURLs() rejected inert markup: %v", err)
	}
	if err := validateRealmRelativeURLs(`<img src="%2Fassets/relative.png"><a href="login%2Frelative">Relative</a>`); err != nil {
		t.Fatalf("validateRealmRelativeURLs() rejected encoded relative URLs: %v", err)
	}
}

func writeExternalTheme(t *testing.T, login string) string {
	t.Helper()
	themeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(themeDir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	login = strings.ReplaceAll(login, `name="authRequestID"`, `name="authRequestID" value="{{.RequestID}}"`)
	login = strings.ReplaceAll(login, `name="csrf"`, `name="csrf" value="{{.CSRF}}"`)
	for name, contents := range map[string]string{"login.html": login, "logged-out.html": `<!doctype html><title>Signed out</title>`} {
		if err := os.WriteFile(filepath.Join(themeDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return themeDir
}
