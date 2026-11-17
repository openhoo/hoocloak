package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAuthorizationCodeVerifierSyntaxBoundaries(t *testing.T) {
	server := testServer(t, nil)
	for _, tt := range []struct {
		name, verifier string
		valid          bool
	}{
		{name: "minimum", verifier: strings.Repeat("a", 43), valid: true},
		{name: "maximum", verifier: strings.Repeat("z", 128), valid: true},
		{name: "unreserved", verifier: strings.Repeat("A", 39) + "-._~", valid: true},
		{name: "too short", verifier: strings.Repeat("a", 42)},
		{name: "too long", verifier: strings.Repeat("a", 129)},
		{name: "reserved character", verifier: strings.Repeat("a", 42) + "+"},
		{name: "space", verifier: strings.Repeat("a", 42) + " "},
		{name: "non ASCII", verifier: strings.Repeat("a", 42) + "é"},
		{name: "empty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request, code := reviewAuthorizationCode(t, server, tt.name, tt.verifier)
			response := reviewCodeExchange(server, code, request.redirectURI, tt.verifier)
			if tt.valid {
				if response.Code != http.StatusOK {
					t.Fatalf("valid verifier status = %d", response.Code)
				}
				return
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest || body.Error != "invalid_request" {
				t.Fatalf("malformed matching verifier response = (%d, %q), want (400, invalid_request)", response.Code, body.Error)
			}
			if stored, err := server.Store.AuthRequestByCode(context.Background(), code); err != nil || stored != request {
				t.Fatalf("malformed verifier consumed authorization code: %v", err)
			}
		})
	}
}

func TestMalformedVerifierDoesNotConsumeAuthorizationCode(t *testing.T) {
	server := testServer(t, nil)
	verifier := strings.Repeat("a", 43)
	request, code := reviewAuthorizationCode(t, server, "retry after malformed verifier", verifier)
	for _, invalid := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+"} {
		if response := reviewCodeExchange(server, code, request.redirectURI, invalid); response.Code != http.StatusBadRequest {
			t.Fatalf("malformed verifier status = %d", response.Code)
		}
	}
	if response := reviewCodeExchange(server, code, request.redirectURI, verifier); response.Code != http.StatusOK {
		t.Fatalf("valid retry after malformed verifier status = %d", response.Code)
	}
}

func reviewAuthorizationCode(t *testing.T, server *realmServer, name, verifier string) (*AuthRequest, string) {
	t.Helper()
	digest := sha256.Sum256([]byte(verifier))
	request := &AuthRequest{
		id: "review-request-" + name, clientID: "react-spa", redirectURI: "http://app.localhost:5173/auth/callback",
		subject: "alice", done: true, expires: time.Now().Add(5 * time.Minute), scopes: []string{"openid", "api.read"},
		audience: []string{"hoocloak-api"}, authTime: time.Now(), amr: []string{"pwd"},
		responseType:  oidc.ResponseTypeCode,
		codeChallenge: &oidc.CodeChallenge{Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), Method: oidc.CodeChallengeMethodS256},
	}
	server.Store.authRequests[request.id] = request
	code := "review-code-" + name
	if err := server.Store.SaveAuthCode(context.Background(), request.id, code); err != nil {
		t.Fatal(err)
	}
	return request, code
}

func reviewCodeExchange(server *realmServer, code, redirectURI, verifier string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"react-spa"}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	return performRequest(server.Handler, http.MethodPost, "/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

func TestRefreshKeepsOriginalGrantAfterNarrowAccessToken(t *testing.T) {
	server := testServer(t, nil)
	verifier := strings.Repeat("v", 43)
	request, code := reviewAuthorizationCode(t, server, "scope", verifier)
	request.scopes = []string{"openid", "offline_access", "api.read"}
	read := func(resp *httptest.ResponseRecorder, scopes []string) string {
		t.Helper()
		var result oidc.AccessTokenResponse
		if resp.Code != http.StatusOK || json.Unmarshal(resp.Body.Bytes(), &result) != nil || result.RefreshToken == "" {
			t.Fatalf("token response status=%d, missing successful rotation", resp.Code)
		}
		if !slices.Equal(result.Scope, scopes) {
			t.Fatalf("granted access scopes=%v, want %v", result.Scope, scopes)
		}
		signed, err := jwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Scopes      oidc.SpaceDelimitedArray `json:"scope"`
			Permissions []string                 `json:"permission"`
		}
		if err := signed.Claims(&server.Store.signing.key.PublicKey, &claims); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(claims.Scopes, scopes) || slices.Contains(claims.Permissions, "api.read") != slices.Contains(scopes, "api.read") {
			t.Fatalf("signed access token scopes=%v permissions=%v, want scopes %v", claims.Scopes, claims.Permissions, scopes)
		}
		return result.RefreshToken
	}
	refresh := func(token, scope string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {request.clientID}, "refresh_token": {token}}
		if scope != "" {
			form.Set("scope", scope)
		}
		return performRequest(server.Handler, http.MethodPost, "/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
	first := read(reviewCodeExchange(server, code, request.redirectURI, verifier), request.scopes)
	second := read(refresh(first, "openid"), []string{"openid"})
	denied := refresh(second, "api.write")
	var failure struct {
		Error string `json:"error"`
	}
	if denied.Code != http.StatusBadRequest || json.Unmarshal(denied.Body.Bytes(), &failure) != nil || failure.Error != "invalid_scope" {
		t.Fatalf("scope outside the original grant: status=%d error=%q", denied.Code, failure.Error)
	}
	read(refresh(second, ""), request.scopes)
}

func TestProtocolPassesOnlyExactParametersToProvider(t *testing.T) {
	server := testServer(t, nil)
	form := url.Values{
		"client_id": {"react-spa"}, "response_type": {"code"}, "scope": {"openid"}, "display": {"page"},
		"redirect_uri": {"http://app.localhost:5173/auth/callback"}, "code_challenge": {testCodeChallenge},
		"code_challenge_method": {"S256"}, "Display": {"popup"}, "example_extension": {"local"},
	}
	handler := server.protocolGates(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Form.Get("display") != "page" || r.Form.Has("Display") || r.Form.Has("example_extension") || r.PostForm.Has("Display") {
			t.Error("downstream form differs from the exact protocol fields checked by the gate")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if got := performRequest(handler, http.MethodPost, "/authorize", form.Encode(), headers); got.Code != http.StatusNoContent {
		t.Fatalf("valid authorization request blocked: %d", got.Code)
	}
	form["prompt"] = []string{"login", "login"}
	assertInvalidAuthorizeRequest(t, performRequest(handler, http.MethodPost, "/authorize", form.Encode(), headers))
}

func TestPublicTokenGrantsRejectUnconfiguredAuthenticationMethods(t *testing.T) {
	server := testServer(t, nil)
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, field := range []string{"Authorization", "client_secret", "client_assertion", "client_assertion_type"} {
			t.Run(grant+"/"+field, func(t *testing.T) {
				form := url.Values{"grant_type": {grant}, "code_verifier": {strings.Repeat("v", 43)}, "client_id": {"react-spa"}}
				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if field == "Authorization" {
					headers[field] = "Basic " + base64.StdEncoding.EncodeToString([]byte("react-spa:unused"))
				} else {
					form.Set(field, "unused")
				}
				called := false
				handler := server.protocolGates(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
				resp := performRequest(handler, http.MethodPost, "/oauth/token", form.Encode(), headers)
				var body struct {
					Error string `json:"error"`
				}
				if called || resp.Code != http.StatusUnauthorized || json.Unmarshal(resp.Body.Bytes(), &body) != nil || body.Error != "invalid_client" {
					t.Fatalf("unexpected public client authentication result: passed=%t status=%d error=%q", called, resp.Code, body.Error)
				}
			})
		}
	}
}

func TestCredentialEndpointsRequireOneTokenTransport(t *testing.T) {
	server := testServer(t, nil)
	for _, tc := range []struct{ name, path, body, auth string }{
		{"token endpoint URL", "/oauth/token?scope=api.read", "grant_type=client_credentials", "Basic " + base64.StdEncoding.EncodeToString([]byte("worker:fixture"))},
		{"revocation URL", "/revoke?token=fixture", "client_id=react-spa", ""},
		{"missing revocation token", "/revoke", "client_id=react-spa", ""},
		{"userinfo URL", "/userinfo?access_token=fixture", "", ""},
		{"mixed userinfo credentials", "/userinfo", "access_token=fixture", "Bearer fixture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := server.protocolGates(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid transport reached provider") }))
			headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			if tc.auth != "" {
				headers["Authorization"] = tc.auth
			}
			resp := performRequest(handler, http.MethodPost, tc.path, tc.body, headers)
			assertInvalidAuthorizeRequest(t, resp)
			if resp.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("credential response may be cached")
			}
		})
	}
}
