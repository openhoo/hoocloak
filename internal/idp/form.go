package idp

import (
	"net/http"
	"slices"
)

// OAuth parameter names are case-sensitive. The provider's struct decoder
// also accepts case-insensitive aliases and dotted field paths. Give it only
// the exact wire fields that this endpoint recognizes and has checked.
var protocolFields = map[string][]string{
	"/authorize": {"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
		"display", "prompt", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values",
		"code_challenge", "code_challenge_method", "request", "request_uri"},
	"/authorize/callback": {"id"},
	"/oauth/token": {"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope",
		"client_id", "client_secret", "client_assertion", "client_assertion_type"},
	"/oauth/introspect": {"token", "token_type_hint", "client_id", "client_secret", "client_assertion", "client_assertion_type"},
	"/revoke":           {"token", "token_type_hint", "client_id", "client_secret", "client_assertion", "client_assertion_type"},
	"/userinfo":         {"access_token"},
	"/end_session":      {"id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales"},
}

func parseProtocolForm(w http.ResponseWriter, r *http.Request, fields []string) bool {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
		return false
	}
	for name, values := range r.Form {
		if !slices.Contains(fields, name) {
			delete(r.Form, name)
			delete(r.PostForm, name)
			continue
		}
		if len(values) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", name+" must not be repeated", false)
			return false
		}
	}
	return true
}

func protocolFieldsInBody(w http.ResponseWriter, r *http.Request) bool {
	// The merged form has already been checked for duplicates, including
	// collisions across the URL and body. Every remaining field needs a body value.
	for name := range r.Form {
		if !r.PostForm.Has(name) {
			oauthError(w, http.StatusBadRequest, "invalid_request", "send protocol parameters in the POST body", false)
			return false
		}
	}
	return true
}

func hasClientSecretFields(r *http.Request) bool {
	return r.Form.Has("client_secret") || r.Form.Has("client_assertion") || r.Form.Has("client_assertion_type")
}

func parseLoginForm(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return false
	}
	for _, field := range []string{"authRequestID", "csrf", "identity", "username", "password"} {
		values, present := r.Form[field]
		if !present {
			continue
		}
		// Only the link that opens the login page carries its request ID in
		// the URL. Every submitted login field belongs in the form body.
		queryAllowed := r.Method == http.MethodGet && field == "authRequestID"
		if len(values) != 1 || (!queryAllowed && !r.PostForm.Has(field)) {
			http.Error(w, "invalid login request", http.StatusBadRequest)
			return false
		}
	}
	return true
}
