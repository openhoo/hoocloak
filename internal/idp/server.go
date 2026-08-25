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
	"net"
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
	xhtml "golang.org/x/net/html"
	"golang.org/x/net/idna"
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

const (
	maxFormBodyBytes       = 64 << 10
	maxAuthorizeFieldBytes = 1024
)

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
		formOrigins, err := configuredRedirectOrigins(realm)
		if err != nil {
			return nil, fmt.Errorf("canonicalize redirect origins for realm %q: %w", realm.Name, err)
		}
		formActions := append([]string{"'self'"}, formOrigins...)
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
		protectedRealmHandler := corsPolicy.Handler(realmMux)
		realmRuntime.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/device_authorization" {
				http.NotFound(w, r)
				return
			}
			protectedRealmHandler.ServeHTTP(w, r)
		})
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

	root, err := os.OpenRoot(themeDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open theme root: %w", err)
	}
	themeFS := root.FS()
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
		if err := validateRealmRelativeURLs(output); err != nil {
			return fmt.Errorf("execute %s.html: %w", check.name, err)
		}
		if check.template == "login" {
			data := check.data.(loginData)
			if err := validateLoginHTML(output, basePath, check.mode, data.RequestID, data.CSRF); err != nil {
				return fmt.Errorf("execute %s.html: %w", check.name, err)
			}
		}
	}
	return nil
}

type loginControlValidation struct {
	kind  string
	value string
}

type loginFieldsetValidation struct {
	depth           int
	disabled        bool
	firstLegendSeen bool
	firstLegendOpen bool
	legendDepth     int
}
type htmlNS uint8

const (
	nsHTML htmlNS = iota
	nsSVG
	nsMath
)

type htmlElementFrame struct {
	name           string
	namespace      htmlNS
	integratesHTML bool
}

type browserHTMLWalker struct {
	tokenizer *xhtml.Tokenizer
	stack     []htmlElementFrame
}

func newBrowserHTMLWalker(document string) *browserHTMLWalker {
	return &browserHTMLWalker{tokenizer: xhtml.NewTokenizer(strings.NewReader(document))}
}

func (w *browserHTMLWalker) currentNamespace() htmlNS {
	if len(w.stack) == 0 || w.stack[len(w.stack)-1].integratesHTML {
		return nsHTML
	}
	return w.stack[len(w.stack)-1].namespace
}

func (w *browserHTMLWalker) truncateForeign() {
	w.stack = nil
}

func foreignBreakoutElement(name string, attributes map[string]string) bool {
	switch name {
	case "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em", "embed",
		"form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta",
		"nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong", "strike", "sub", "sup", "table", "tt",
		"u", "ul", "var":
		return true
	case "font":
		_, color := attributes["color"]
		_, face := attributes["face"]
		_, size := attributes["size"]
		return color || face || size
	default:
		return false
	}
}

func foreignIntegrationPoint(namespace htmlNS, name string, attributes map[string]string) bool {
	switch namespace {
	case nsSVG:
		return name == "foreignobject" || name == "desc" || name == "title"
	case nsMath:
		if name == "mi" || name == "mo" || name == "mn" || name == "ms" || name == "mtext" {
			return true
		}
		encoding := strings.ToLower(attributes["encoding"])
		return name == "annotation-xml" && (encoding == "text/html" || encoding == "application/xhtml+xml")
	default:
		return false
	}
}

func foreignRawTextElement(name string) bool {
	switch name {
	case "title", "textarea", "style", "script", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext":
		return true
	default:
		return false
	}
}

func (w *browserHTMLWalker) close(name string) {
	for index := len(w.stack) - 1; index >= 0; index-- {
		if w.stack[index].name == name {
			w.stack = w.stack[:index]
			return
		}
	}
}

func (w *browserHTMLWalker) next() (xhtml.TokenType, string, map[string]string, error) {
	tokenType := w.tokenizer.Next()
	if tokenType == xhtml.ErrorToken {
		return tokenType, "", nil, w.tokenizer.Err()
	}
	if tokenType != xhtml.StartTagToken && tokenType != xhtml.SelfClosingTagToken && tokenType != xhtml.EndTagToken {
		return tokenType, "", nil, nil
	}
	closing := tokenType == xhtml.EndTagToken
	name, attributes, err := validatedHTMLTag(w.tokenizer, closing)
	if err != nil {
		return tokenType, "", nil, err
	}
	if closing {
		w.close(name)
		return tokenType, name, nil, nil
	}
	namespace := w.currentNamespace()
	if namespace != nsHTML && foreignBreakoutElement(name, attributes) {
		w.truncateForeign()
		namespace = nsHTML
	}
	foreign := namespace != nsHTML
	if tokenType != xhtml.SelfClosingTagToken {
		switch namespace {
		case nsHTML:
			if name == "svg" {
				w.stack = append(w.stack, htmlElementFrame{name: name, namespace: nsSVG})
			} else if name == "math" {
				w.stack = append(w.stack, htmlElementFrame{name: name, namespace: nsMath})
			}
		case nsSVG, nsMath:
			w.stack = append(w.stack, htmlElementFrame{name: name, namespace: namespace, integratesHTML: foreignIntegrationPoint(namespace, name, attributes)})
		}
	}
	if foreign && foreignRawTextElement(name) {
		w.tokenizer.NextIsNotRawText()
	}
	return tokenType, name, attributes, nil
}

type loginFormRecord struct {
	id   string
	post bool
}

type loginSubmitOverride struct {
	kind, inputType, formID  string
	owner                    int
	action, method, encoding bool
}

type loginFormScope struct {
	inPost   bool
	postForm int
	forms    []int
	inert    bool
}

type loginFormValidation struct {
	postForms int
	postForm  int
	action    string
	controls  map[string]loginControlValidation
	fieldsets []loginFieldsetValidation
	elements  []string
	forms     []loginFormRecord
	formIDs   map[string]int
	overrides []loginSubmitOverride
}

func validateLoginHTML(document, basePath, mode, requestID, csrf string) error {
	validation := loginFormValidation{
		postForm: -1, controls: make(map[string]loginControlValidation),
		formIDs: make(map[string]int),
	}
	walker := newBrowserHTMLWalker(document)
	scopes := []loginFormScope{{postForm: -1}}
	for {
		tokenType, name, attributes, err := walker.next()
		if tokenType == xhtml.ErrorToken {
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("parse rendered HTML: %w", err)
			}
			break
		}
		if err != nil {
			return fmt.Errorf("parse rendered HTML: %w", err)
		}
		if tokenType != xhtml.StartTagToken && tokenType != xhtml.SelfClosingTagToken && tokenType != xhtml.EndTagToken {
			continue
		}
		closing := tokenType == xhtml.EndTagToken
		if name == "template" {
			if closing {
				if len(scopes) > 1 {
					scopes = scopes[:len(scopes)-1]
				}
			} else if tokenType != xhtml.SelfClosingTagToken {
				inert := scopes[len(scopes)-1].inert || (strings.ToLower(attributes["shadowrootmode"]) != "open" && strings.ToLower(attributes["shadowrootmode"]) != "closed")
				scopes = append(scopes, loginFormScope{postForm: -1, inert: inert})
			}
			continue
		}
		scope := &scopes[len(scopes)-1]
		if scope.inert {
			continue
		}
		if closing {
			match := -1
			for index := len(validation.elements) - 1; index >= 0; index-- {
				if validation.elements[index] == name {
					match = index
					break
				}
			}
			if match >= 0 {
				if name == "legend" {
					for index := len(validation.fieldsets) - 1; index >= 0; index-- {
						fieldset := &validation.fieldsets[index]
						if fieldset.firstLegendOpen && fieldset.legendDepth == match {
							fieldset.firstLegendOpen = false
							break
						}
					}
				}
				validation.elements = validation.elements[:match]
				for len(validation.fieldsets) > 0 && validation.fieldsets[len(validation.fieldsets)-1].depth >= match {
					validation.fieldsets = validation.fieldsets[:len(validation.fieldsets)-1]
				}
			}
			if name == "form" && len(scope.forms) > 0 {
				scope.forms = scope.forms[:len(scope.forms)-1]
				scope.postForm = -1
				scope.inPost = false
			}
			if scope.postForm >= 0 && len(scope.forms) == 0 {
				scope.postForm = -1
				scope.inPost = false
			}
			continue
		}
		if name == "legend" && len(validation.elements) > 0 && validation.elements[len(validation.elements)-1] == "fieldset" {
			fieldsetDepth := len(validation.elements) - 1
			for index := len(validation.fieldsets) - 1; index >= 0; index-- {
				fieldset := &validation.fieldsets[index]
				if fieldset.depth == fieldsetDepth {
					if !fieldset.firstLegendSeen {
						fieldset.firstLegendSeen = true
						fieldset.firstLegendOpen = true
						fieldset.legendDepth = len(validation.elements)
					}
					break
				}
			}
		}
		if name == "fieldset" {
			_, disabled := attributes["disabled"]
			validation.fieldsets = append(validation.fieldsets, loginFieldsetValidation{depth: len(validation.elements), disabled: disabled, legendDepth: -1})
		}
		if name == "form" {
			if len(scope.forms) > 0 {
				return errors.New("nested forms are not allowed")
			}
			if enctype := attributes["enctype"]; strings.EqualFold(enctype, "multipart/form-data") || strings.EqualFold(enctype, "text/plain") {
				return errors.New("login form must use application/x-www-form-urlencoded encoding")
			}
			formIndex := len(validation.forms)
			formID := attributes["id"]
			validation.forms = append(validation.forms, loginFormRecord{id: formID, post: strings.EqualFold(attributes["method"], http.MethodPost)})
			if formID != "" {
				if _, exists := validation.formIDs[formID]; !exists {
					validation.formIDs[formID] = formIndex
				}
			}
			scope.forms = append(scope.forms, formIndex)
			if validation.forms[formIndex].post {
				validation.postForms++
				if validation.postForms > 1 {
					return errors.New("login page must contain exactly one POST form")
				}
				scope.inPost = true
				scope.postForm = formIndex
				validation.postForm = formIndex
				validation.action = attributes["action"]
				validation.controls = make(map[string]loginControlValidation)
			}
		}
		if name == "input" || name == "select" || name == "textarea" || name == "button" {
			controlName := attributes["name"]
			sensitive := strings.EqualFold(controlName, "authRequestID") ||
				strings.EqualFold(controlName, "csrf") ||
				strings.EqualFold(controlName, "identity") ||
				strings.EqualFold(controlName, "username") ||
				strings.EqualFold(controlName, "password")
			owner := -1
			if len(scope.forms) > 0 {
				owner = scope.forms[len(scope.forms)-1]
			}
			if name == "input" || name == "button" {
				_, action := attributes["formaction"]
				_, method := attributes["formmethod"]
				_, encoding := attributes["formenctype"]
				if action || method || encoding {
					validation.overrides = append(validation.overrides, loginSubmitOverride{
						kind: name, inputType: strings.ToLower(attributes["type"]), formID: attributes["form"],
						owner: owner, action: action, method: method, encoding: encoding,
					})
				}
			}
			if sensitive {
				disabled := false
				for _, fieldset := range validation.fieldsets {
					if fieldset.disabled && !fieldset.firstLegendOpen {
						disabled = true
						break
					}
				}
				if _, exists := attributes["disabled"]; exists || disabled {
					return fmt.Errorf("login form %s control must not be disabled", controlName)
				}
				if _, exists := attributes["form"]; exists {
					return fmt.Errorf("login form %s control must not use form reassociation", controlName)
				}
			}
			if scope.inPost && controlName != "" {
				if sensitive {
					for existing := range validation.controls {
						if strings.EqualFold(existing, controlName) {
							return fmt.Errorf("login form must not contain duplicate %s controls", controlName)
						}
					}
				}
				validation.controls[controlName] = loginControlValidation{kind: strings.ToLower(attributes["type"]), value: attributes["value"]}
			}
		}
		if !isVoidHTMLElement(name) {
			validation.elements = append(validation.elements, name)
		}
	}
	for _, override := range validation.overrides {
		owner := override.owner
		if override.formID != "" {
			var ok bool
			owner, ok = validation.formIDs[override.formID]
			if !ok {
				continue
			}
		}
		submitter := (override.kind == "button" && override.inputType != "button" && override.inputType != "reset") ||
			(override.kind == "input" && (override.inputType == "submit" || override.inputType == "image"))
		if !submitter || owner != validation.postForm {
			continue
		}
		switch {
		case override.action:
			return errors.New("login controls must not override the form action")
		case override.method:
			return errors.New("login controls must not override the form method")
		default:
			return errors.New("login controls must not override the form encoding")
		}
	}
	if validation.postForms != 1 {
		return fmt.Errorf("login page must contain exactly one POST form, found %d", validation.postForms)
	}
	if validation.action != basePath+"/login" {
		return fmt.Errorf("login form action must be exactly %q", basePath+"/login")
	}
	for _, hidden := range []struct {
		name  string
		value string
	}{{name: "authRequestID", value: requestID}, {name: "csrf", value: csrf}} {
		control := validation.controls[hidden.name]
		if control.kind != "hidden" {
			return fmt.Errorf("login form must contain hidden %s control", hidden.name)
		}
		if control.value != hidden.value {
			return fmt.Errorf("login form hidden %s value must exactly match rendered data", hidden.name)
		}
	}
	if mode == config.LoginModePassword {
		if _, exists := validation.controls["username"]; !exists {
			return errors.New("password login form must contain username control")
		}
		if validation.controls["password"].kind != "password" {
			return errors.New("password login form must contain password control")
		}
	} else if _, exists := validation.controls["identity"]; !exists {
		return errors.New("select login form must contain identity control")
	}
	return nil
}

func validatedHTMLTag(tokenizer *xhtml.Tokenizer, closing bool) (string, map[string]string, error) {
	rawName, hasAttributes := tokenizer.TagName()
	name := string(rawName)
	if closing {
		return name, nil, nil
	}
	if err := validateRawHTMLAttributeNames(tokenizer.Raw()); err != nil {
		return "", nil, err
	}
	attributes := make(map[string]string)
	for hasAttributes {
		rawKey, rawValue, more := tokenizer.TagAttr()
		key := string(rawKey)
		if _, exists := attributes[key]; exists {
			return "", nil, fmt.Errorf("attribute %q must not be repeated", key)
		}
		attributes[key] = string(rawValue)
		hasAttributes = more
	}
	return name, attributes, nil
}

func validateRawHTMLAttributeNames(raw []byte) error {
	offset := 1
	for offset < len(raw) && !strings.ContainsRune(" \t\r\n\f/>", rune(raw[offset])) {
		offset++
	}
	seen := make(map[string]struct{})
	for offset < len(raw) {
		for offset < len(raw) && strings.ContainsRune(" \t\r\n\f/", rune(raw[offset])) {
			offset++
		}
		if offset >= len(raw) || raw[offset] == '>' {
			return nil
		}
		nameStart := offset
		for offset < len(raw) && !strings.ContainsRune(" \t\r\n\f=/>", rune(raw[offset])) {
			offset++
		}
		if nameStart == offset {
			return errors.New("attribute name must not be empty")
		}
		name := strings.ToLower(string(raw[nameStart:offset]))
		if _, exists := seen[name]; exists {
			return fmt.Errorf("attribute %q must not be repeated", name)
		}
		seen[name] = struct{}{}
		for offset < len(raw) && strings.ContainsRune(" \t\r\n\f", rune(raw[offset])) {
			offset++
		}
		if offset >= len(raw) || raw[offset] != '=' {
			continue
		}
		offset++
		for offset < len(raw) && strings.ContainsRune(" \t\r\n\f", rune(raw[offset])) {
			offset++
		}
		if offset >= len(raw) {
			return fmt.Errorf("attribute %q has no value", name)
		}
		if raw[offset] == '\'' || raw[offset] == '"' {
			quote := raw[offset]
			offset++
			for offset < len(raw) && raw[offset] != quote {
				offset++
			}
			if offset >= len(raw) {
				return fmt.Errorf("attribute %q has an unterminated value", name)
			}
			offset++
			continue
		}
		for offset < len(raw) && !strings.ContainsRune(" \t\r\n\f>", rune(raw[offset])) {
			offset++
		}
	}
	return nil
}

func isVoidHTMLElement(name string) bool {
	switch name {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr":
		return true
	default:
		return false
	}
}

func validateRealmRelativeURLs(document string) error {
	walker := newBrowserHTMLWalker(document)
	scopes := []bool{false}
	for {
		tokenType, name, attributes, err := walker.next()
		if tokenType == xhtml.ErrorToken {
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("parse rendered HTML: %w", err)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse rendered HTML: %w", err)
		}
		if tokenType != xhtml.StartTagToken && tokenType != xhtml.SelfClosingTagToken && tokenType != xhtml.EndTagToken {
			continue
		}
		if name == "template" {
			if tokenType == xhtml.EndTagToken {
				if len(scopes) > 1 {
					scopes = scopes[:len(scopes)-1]
				}
			} else if tokenType != xhtml.SelfClosingTagToken {
				inert := scopes[len(scopes)-1] || (strings.ToLower(attributes["shadowrootmode"]) != "open" && strings.ToLower(attributes["shadowrootmode"]) != "closed")
				scopes = append(scopes, inert)
			}
			continue
		}
		if scopes[len(scopes)-1] || tokenType == xhtml.EndTagToken {
			continue
		}
		for _, attribute := range []string{"action", "background", "data", "formaction", "href", "poster", "src", "xlink:href"} {
			if isRootRelativeLoginURL(attributes[attribute]) {
				return errors.New("root-relative login and asset URLs are not allowed; use .BasePath")
			}
		}
		for _, sourceSet := range []string{attributes["imagesrcset"], attributes["srcset"]} {
			for _, candidate := range srcsetCandidates(sourceSet) {
				if isRootRelativeLoginURL(candidate) {
					return errors.New("root-relative login and asset URLs are not allowed; use .BasePath")
				}
			}
		}
		for _, urlList := range []string{attributes["archive"], attributes["ping"]} {
			for _, candidate := range strings.Fields(urlList) {
				if isRootRelativeLoginURL(candidate) {
					return errors.New("root-relative login and asset URLs are not allowed; use .BasePath")
				}
			}
		}
	}
}

func srcsetCandidates(value string) []string {
	var candidates []string
	for position := 0; position < len(value); {
		for position < len(value) && (value[position] == ',' || value[position] == ' ' || value[position] == '\t' || value[position] == '\r' || value[position] == '\n' || value[position] == '\f') {
			position++
		}
		if position >= len(value) {
			break
		}
		start := position
		for position < len(value) && value[position] != ' ' && value[position] != '\t' && value[position] != '\r' && value[position] != '\n' && value[position] != '\f' {
			position++
		}
		urlValue := value[start:position]
		if strings.HasSuffix(urlValue, ",") {
			urlValue = strings.TrimRight(urlValue, ",")
		}
		if urlValue != "" {
			candidates = append(candidates, urlValue)
		}
		// A descriptor is separated by whitespace; consume it through the next
		// comma while retaining only the URL candidate above.
		for position < len(value) && value[position] != ',' {
			position++
		}
		if position < len(value) {
			position++
		}
	}
	return candidates
}
func isRootRelativeLoginURL(value string) bool {
	candidate := strings.Map(func(character rune) rune {
		switch character {
		case '\t', '\n', '\r':
			return -1
		default:
			return character
		}
	}, strings.TrimFunc(value, func(character rune) bool { return character <= 0x20 }))
	candidate = strings.ReplaceAll(candidate, `\`, "/")
	if !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") {
		return false
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return true
	}
	if parsed.IsAbs() || parsed.Host != "" {
		return false
	}
	normalizedPath := path.Clean(parsed.Path)
	return normalizedPath == "/login" || strings.HasPrefix(normalizedPath, "/login/") ||
		normalizedPath == "/assets" || strings.HasPrefix(normalizedPath, "/assets/")
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
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		if r.URL.Path == "/device_authorization" {
			http.NotFound(w, r)
			return
		}
		if allow, known := providerEndpointMethods(r.URL.Path); known && !methodAllowed(r.Method, allow) {
			w.Header().Set("Allow", allow)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodPost {
			switch r.URL.Path {
			case "/authorize", "/oauth/token", "/oauth/introspect", "/revoke", "/userinfo", "/end_session":
				r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
			}
		}
		switch r.URL.Path {
		case "/authorize":
			if !s.authorizeGate(w, r) {
				return
			}
		case "/authorize/callback":
			if !s.callbackGate(w, r) {
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
		case "/userinfo":
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
					return
				}
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
func (s *realmServer) callbackGate(w http.ResponseWriter, r *http.Request) bool {
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		http.Error(w, "invalid authorization completion", http.StatusBadRequest)
		return false
	}
	cookie, err := r.Cookie(completionCookieName(requestID))
	if err != nil || cookie.Value == "" || s.Store.ConsumeCompletionSecret(requestID, cookie.Value) != nil {
		http.Error(w, "invalid authorization completion", http.StatusBadRequest)
		return false
	}
	// #nosec G124 -- Secure is intentionally false only for validated local HTTP issuers.
	http.SetCookie(w, &http.Cookie{Name: completionCookieName(requestID), Value: "", Path: s.basePath + "/authorize/callback", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	return true
}

func providerEndpointMethods(providerPath string) (string, bool) {
	switch providerPath {
	case "/authorize":
		return "GET, POST", true
	case "/authorize/callback":
		return http.MethodGet, true
	case "/oauth/token", "/oauth/introspect", "/revoke":
		return http.MethodPost, true
	case "/userinfo", "/end_session":
		return "GET, POST", true
	case "/keys":
		return "GET, HEAD", true
	default:
		return "", false
	}
}

func methodAllowed(method, allow string) bool {
	for _, allowed := range strings.Split(allow, ", ") {
		if method == allowed {
			return true
		}
	}
	return false
}
func validS256CodeChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func (s *realmServer) authorizeGate(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unable to parse request", false)
		return false
	}
	if !rejectRepeatedFormParameters(w, r, "client_id", "response_type", "response_mode", "scope", "redirect_uri", "code_challenge", "code_challenge_method", "state", "nonce") {
		return false
	}
	for _, field := range []string{"state", "nonce"} {
		if len(r.Form.Get(field)) > maxAuthorizeFieldBytes {
			oauthError(w, http.StatusBadRequest, "invalid_request", field+" must not exceed 1024 bytes", false)
			return false
		}
	}
	client := s.Store.clients[r.Form.Get("client_id")]
	if client == nil || client.config.Type != config.ClientTypeSPA {
		return true
	}
	if redirectURI := r.Form.Get("redirect_uri"); !slices.Contains(client.config.RedirectURIs, redirectURI) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered", false)
		return false
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
	if !validS256CodeChallenge(r.Form.Get("code_challenge")) || r.Form.Get("code_challenge_method") != "S256" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "PKCE requires a 43-character S256 code challenge", false)
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

func configuredRedirectOrigins(realm config.Realm) ([]string, error) {
	seen := make(map[string]struct{})
	for _, client := range realm.Clients {
		if client.Type != config.ClientTypeSPA {
			continue
		}
		for _, raw := range client.RedirectURIs {
			origin, err := canonicalRedirectOrigin(raw)
			if err != nil {
				return nil, fmt.Errorf("redirect URI %q cannot be represented as a CSP origin: %w", raw, err)
			}
			seen[origin] = struct{}{}
		}
	}
	origins := make([]string, 0, len(seen))
	for origin := range seen {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins, nil
}

func canonicalRedirectOrigin(raw string) (string, error) {
	redirect, err := url.Parse(raw)
	if err != nil || redirect.Host == "" || redirect.Hostname() == "" {
		return "", errors.New("absolute URL with a host is required")
	}
	if redirect.Scheme != "http" && redirect.Scheme != "https" {
		return "", errors.New("only HTTP(S) origins are supported")
	}
	if strings.HasSuffix(redirect.Host, ":") {
		return "", errors.New("empty port is not a valid CSP host")
	}
	port := redirect.Port()
	if strings.Contains(redirect.Hostname(), ":") {
		if net.ParseIP(redirect.Hostname()) == nil {
			return "", errors.New("invalid IPv6 host")
		}
		if !validPort(port) {
			return "", errors.New("invalid port")
		}
		return redirect.Scheme + "://[" + strings.ToLower(redirect.Hostname()) + "]" + portSuffix(redirect.Scheme, port), nil
	}
	host := strings.TrimSuffix(strings.ToLower(redirect.Hostname()), ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", errors.New("invalid IDNA hostname")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid hostname label")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("invalid hostname character")
			}
		}
	}
	if !validPort(port) {
		return "", errors.New("invalid port")
	}
	return redirect.Scheme + "://" + ascii + portSuffix(redirect.Scheme, port), nil
}

func validPort(port string) bool {
	if port == "" {
		return true
	}
	value := 0
	for _, char := range port {
		if char < '0' || char > '9' {
			return false
		}
		value = value*10 + int(char-'0')
		if value > 65535 {
			return false
		}
	}
	return value > 0
}

func portSuffix(scheme, port string) string {
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return ""
	}
	return ":" + port
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
	completionSecret, err := s.Store.IssueCompletionSecret(id)
	if err != nil {
		http.Error(w, "unable to create authorization completion", http.StatusInternalServerError)
		return
	}
	// #nosec G124 -- Secure is intentionally false only for validated local HTTP issuers.
	http.SetCookie(w, &http.Cookie{Name: completionCookieName(id), Value: completionSecret, Path: s.basePath + "/authorize/callback", MaxAge: 600, Expires: time.Now().Add(10 * time.Minute), HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	// #nosec G124 -- deleting the login CSRF cookie; attributes retained so the
	// clearing cookie matches the one it replaces.
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
func completionCookieName(requestID string) string {
	digest := sha256.Sum256([]byte(requestID))
	return "hoocloak_completion_" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

func csrfCookieName(requestID string) string {
	digest := sha256.Sum256([]byte(requestID))
	return "hoocloak_csrf_" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

func fmtError(prefix string, err error) error { return fmt.Errorf("%s: %w", prefix, err) }
