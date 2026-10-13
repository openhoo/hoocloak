package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
