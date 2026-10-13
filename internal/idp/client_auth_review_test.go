package idp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMutationClientAuthenticationRejectsBodyAndMixedCredentials(t *testing.T) {
	server := testServer(t, nil)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("worker:worker-secret"))
	for _, endpoint := range []string{"/revoke", "/oauth/introspect"} {
		for _, credentials := range []struct {
			name   string
			form   url.Values
			header string
			query  bool
		}{
			{name: "body secret", form: url.Values{"client_id": {"worker"}, "client_secret": {"worker-secret"}}},
			{name: "query secret", form: url.Values{"client_id": {"worker"}, "client_secret": {"worker-secret"}}, query: true},
			{name: "empty secret with Basic", form: url.Values{"client_secret": {""}}, header: basic},
			{name: "mixed client identity", form: url.Values{"client_id": {"react-spa"}}, header: basic},
			{name: "client assertion", form: url.Values{"client_assertion": {"unsupported"}}, header: basic},
			{name: "assertion type", form: url.Values{"client_assertion_type": {"unsupported"}}, header: basic},
		} {
			t.Run(endpoint+"/"+credentials.name, func(t *testing.T) {
				tokenResponse := performRequest(server.Handler, http.MethodPost, "/oauth/token", "grant_type=client_credentials&scope=api.read", map[string]string{
					"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic,
				})
				var token struct {
					AccessToken string `json:"access_token"`
				}
				if tokenResponse.Code != http.StatusOK || json.Unmarshal(tokenResponse.Body.Bytes(), &token) != nil || token.AccessToken == "" {
					t.Fatal("unable to issue service access token")
				}
				form := url.Values{"token": {token.AccessToken}, "token_type_hint": {"access_token"}}
				for key, values := range credentials.form {
					form[key] = values
				}
				target, body := endpoint, form.Encode()
				if credentials.query {
					target += "?" + credentials.form.Encode()
					body = url.Values{"token": {token.AccessToken}, "token_type_hint": {"access_token"}}.Encode()
				}
				response := performRequest(server.Handler, http.MethodPost, target, body, map[string]string{
					"Content-Type": "application/x-www-form-urlencoded", "Authorization": credentials.header,
				})
				var oauthResponse map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &oauthResponse); err != nil {
					t.Fatal(err)
				}
				if response.Code != http.StatusUnauthorized || oauthResponse["error"] != "invalid_client" {
					t.Fatalf("status=%d error=%v, want 401 invalid_client", response.Code, oauthResponse["error"])
				}
				if !strings.HasPrefix(response.Header().Get("WWW-Authenticate"), "Basic ") {
					t.Fatal("missing Basic authentication challenge")
				}
				introspection := performRequest(server.Handler, http.MethodPost, "/oauth/introspect", url.Values{"token": {token.AccessToken}}.Encode(), map[string]string{
					"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic,
				})
				var activity struct {
					Active bool `json:"active"`
				}
				if introspection.Code != http.StatusOK || json.Unmarshal(introspection.Body.Bytes(), &activity) != nil || !activity.Active {
					t.Fatal("rejected mutation altered the token's active state")
				}
				if endpoint == "/revoke" {
					revocation := performRequest(server.Handler, http.MethodPost, endpoint, url.Values{"token": {token.AccessToken}}.Encode(), map[string]string{
						"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic,
					})
					if revocation.Code != http.StatusOK {
						t.Fatalf("Basic revocation status=%d, want 200", revocation.Code)
					}
					introspection = performRequest(server.Handler, http.MethodPost, "/oauth/introspect", url.Values{"token": {token.AccessToken}}.Encode(), map[string]string{
						"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic,
					})
					activity.Active = true
					if introspection.Code != http.StatusOK || json.Unmarshal(introspection.Body.Bytes(), &activity) != nil || activity.Active {
						t.Fatal("Basic revocation did not deactivate the token")
					}
				}
			})
		}
	}
}

func TestPublicClientRevocationAndBasicOnlyIntrospection(t *testing.T) {
	server := testServer(t, nil)
	form := url.Values{"client_id": {"react-spa"}, "token": {"unknown-token"}}.Encode()
	revocation := performRequest(server.Handler, http.MethodPost, "/revoke", form, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if revocation.Code != http.StatusOK {
		t.Fatalf("public SPA revocation status=%d, want 200", revocation.Code)
	}
	introspection := performRequest(server.Handler, http.MethodPost, "/oauth/introspect", form, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if introspection.Code != http.StatusUnauthorized {
		t.Fatalf("public introspection status=%d, want 401", introspection.Code)
	}
}
