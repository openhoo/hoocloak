package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"

	"github.com/openhoo/hoocloak/internal/config"
)

const dummyPasswordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"

var (
	_ op.Storage                        = (*Store)(nil)
	_ op.ClientCredentialsStorage       = (*Store)(nil)
	_ op.CanGetPrivateClaimsFromRequest = (*Store)(nil)
	_ op.CanSetUserinfoFromRequest      = (*Store)(nil)
)

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Store struct {
	mu           sync.Mutex
	cfg          config.Config
	clock        Clock
	clients      map[string]*Client
	users        map[string]config.User
	usernames    map[string]string
	authRequests map[string]*AuthRequest
	codes        map[string]codeRecord
	access       map[string]accessRecord
	refresh      map[[32]byte]*refreshRecord
	families     map[string]*refreshFamily
	signing      signingKey
}

type codeRecord struct {
	requestID string
	expires   time.Time
}
type accessRecord struct {
	id, clientID, subject       string
	audience, scopes            []string
	expires, issuedAt, authTime time.Time
	amr                         []string
	familyID                    string
}
type refreshRecord struct {
	hash                  [32]byte
	familyID              string
	clientID, subject     string
	audience, scopes, amr []string
	authTime              time.Time
	consumed              bool
	accessID              string
}
type refreshFamily struct {
	id, clientID, subject string
	expires               time.Time
	revoked               bool
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) ID() string                                  { return k.id }

type publicKey struct{ *signingKey }

func (k *publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *publicKey) Use() string                        { return "sig" }
func (k *publicKey) Key() any                           { return &k.signingKey.key.PublicKey }

func NewStore(cfg config.Config, key *rsa.PrivateKey, kid string, clock Clock) *Store {
	if clock == nil {
		clock = systemClock{}
	}
	s := &Store{
		cfg: cfg, clock: clock,
		clients: make(map[string]*Client, len(cfg.Clients)), users: make(map[string]config.User, len(cfg.Users)),
		usernames: make(map[string]string, len(cfg.Users)), authRequests: make(map[string]*AuthRequest),
		codes: make(map[string]codeRecord), access: make(map[string]accessRecord),
		refresh: make(map[[32]byte]*refreshRecord), families: make(map[string]*refreshFamily),
		signing: signingKey{id: kid, key: key},
	}
	for _, c := range cfg.Clients {
		s.clients[c.ID] = newClient(c, cfg.Tokens.IDTTL.Duration)
	}
	for _, u := range cfg.Users {
		s.users[u.ID] = u
		s.usernames[config.CanonicalUsername(u.Username)] = u.ID
	}
	return s
}

func randomID() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (s *Store) now() time.Time { return s.clock.Now().UTC() }
func (s *Store) pruneLocked(now time.Time) {
	for id, request := range s.authRequests {
		if !now.Before(request.expires) {
			delete(s.authRequests, id)
		}
	}
	for code, record := range s.codes {
		if !now.Before(record.expires) {
			delete(s.codes, code)
		}
	}
	for id, record := range s.access {
		if !now.Before(record.expires) {
			delete(s.access, id)
		}
	}
	for id, family := range s.families {
		if !now.Before(family.expires) {
			delete(s.families, id)
			for hash, record := range s.refresh {
				if record.familyID == id {
					delete(s.refresh, hash)
				}
			}
		}
	}
}

func (s *Store) CreateAuthRequest(_ context.Context, request *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if slices.Contains(request.Prompt, oidc.PromptNone) {
		return nil, oidc.ErrLoginRequired()
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	challenge := (*oidc.CodeChallenge)(nil)
	if request.CodeChallenge != "" {
		challenge = &oidc.CodeChallenge{Challenge: request.CodeChallenge, Method: request.CodeChallengeMethod}
	}
	now := s.now()
	client := s.clients[request.ClientID]
	if client == nil {
		return nil, oidc.ErrInvalidRequest()
	}
	auth := &AuthRequest{
		id: id, clientID: request.ClientID, redirectURI: request.RedirectURI, state: request.State,
		nonce: request.Nonce, codeChallenge: challenge, scopes: slices.Clone(request.Scopes), audience: slices.Clone(client.config.Audiences),
		responseType: request.ResponseType, responseMode: request.ResponseMode, subject: userID,
		created: now, expires: now.Add(5 * time.Minute),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.authRequests[id] = auth
	return auth, nil
}

func (s *Store) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	request, ok := s.authRequests[id]
	if !ok {
		return nil, oidc.ErrInvalidRequest().WithDescription("authorization request is missing or expired")
	}
	return request, nil
}

func (s *Store) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	record, ok := s.codes[code]
	if !ok {
		return nil, oidc.ErrInvalidGrant()
	}
	delete(s.codes, code)
	request, ok := s.authRequests[record.requestID]
	if !ok || !request.done || !now.Before(record.expires) {
		return nil, oidc.ErrInvalidGrant()
	}
	return request, nil
}

func (s *Store) SaveAuthCode(_ context.Context, requestID, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	request, ok := s.authRequests[requestID]
	if !ok || !request.done || !now.Before(request.expires) {
		return oidc.ErrInvalidGrant()
	}
	s.codes[code] = codeRecord{requestID: requestID, expires: request.expires}
	return nil
}

func (s *Store) DeleteAuthRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authRequests, id)
	for code, record := range s.codes {
		if record.requestID == id {
			delete(s.codes, code)
		}
	}
	return nil
}

func (s *Store) Authenticate(requestID, username, password string) error {
	now := s.now()
	s.mu.Lock()
	s.pruneLocked(now)
	request, requestOK := s.authRequests[requestID]
	userID, userOK := s.usernames[config.CanonicalUsername(username)]
	user := s.users[userID]
	hash := dummyPasswordHash
	if userOK {
		hash = user.PasswordHash
	}
	s.mu.Unlock()
	passwordOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if !requestOK {
		return errors.New("authorization request is missing or expired")
	}
	if !userOK || !passwordOK {
		return errors.New("Invalid username or password.")
	}

	now = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	request, requestOK = s.authRequests[requestID]
	if !requestOK {
		return errors.New("authorization request is missing or expired")
	}
	client := s.clients[request.clientID]
	if client == nil {
		return errors.New("authorization client is unavailable")
	}
	granted := make([]string, 0, len(request.scopes))
	for _, scope := range request.scopes {
		if !slices.Contains(client.config.AllowedScopes, scope) {
			continue
		}
		switch scope {
		case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess:
			granted = append(granted, scope)
		default:
			if slices.Contains(user.Permissions, scope) {
				granted = append(granted, scope)
			}
		}
	}
	request.subject, request.scopes, request.authTime, request.amr, request.done = user.ID, granted, now, []string{"pwd"}, true
	return nil
}

func (s *Store) LoginInfo(requestID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	request, ok := s.authRequests[requestID]
	if !ok {
		return "", errors.New("authorization request is missing or expired")
	}
	client := s.clients[request.clientID]
	if client == nil {
		return "", errors.New("authorization client is unavailable")
	}
	if client.config.Name != "" {
		return client.config.Name, nil
	}
	return client.config.ID, nil
}

func (s *Store) CreateAccessToken(_ context.Context, request op.TokenRequest) (string, time.Time, error) {
	return s.createAccessToken(request, "")
}

func (s *Store) createAccessToken(request op.TokenRequest, familyID string) (string, time.Time, error) {
	id, err := randomID()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expires := now.Add(s.cfg.Tokens.AccessTTL.Duration)
	clientID, authTime, amr, err := tokenRequestInfo(request)
	if err != nil {
		return "", time.Time{}, err
	}
	audience := slices.Clone(s.clients[clientID].config.Audiences)
	record := accessRecord{id: id, clientID: clientID, subject: request.GetSubject(), audience: audience, scopes: slices.Clone(request.GetScopes()), expires: expires, issuedAt: now, authTime: authTime, amr: slices.Clone(amr), familyID: familyID}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.access[id] = record
	return id, expires, nil
}

func (s *Store) CreateAccessAndRefreshTokens(_ context.Context, request op.TokenRequest, current string) (string, string, time.Time, error) {
	now := s.now()
	clientID, authTime, amr, err := tokenRequestInfo(request)
	if err != nil {
		return "", "", time.Time{}, err
	}
	newToken, err := randomID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	newHash := sha256.Sum256([]byte(newToken))
	accessID, err := randomID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires := now.Add(s.cfg.Tokens.AccessTTL.Duration)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	var family *refreshFamily
	if current == "" {
		familyID, e := randomID()
		if e != nil {
			return "", "", time.Time{}, e
		}
		family = &refreshFamily{id: familyID, clientID: clientID, subject: request.GetSubject(), expires: now.Add(s.cfg.Tokens.RefreshTTL.Duration)}
		s.families[familyID] = family
	} else {
		oldHash := sha256.Sum256([]byte(current))
		old := s.refresh[oldHash]
		if old == nil || old.consumed {
			if old != nil {
				s.revokeFamilyLocked(old.familyID)
			}
			return "", "", time.Time{}, oidc.ErrInvalidGrant()
		}
		family = s.families[old.familyID]
		if family == nil || family.revoked || !now.Before(family.expires) || old.clientID != clientID {
			return "", "", time.Time{}, oidc.ErrInvalidGrant()
		}
		old.consumed = true
		delete(s.access, old.accessID)
	}
	audience := slices.Clone(s.clients[clientID].config.Audiences)
	record := &refreshRecord{hash: newHash, familyID: family.id, clientID: clientID, subject: request.GetSubject(), audience: audience, scopes: slices.Clone(request.GetScopes()), amr: slices.Clone(amr), authTime: authTime, accessID: accessID}
	s.refresh[newHash] = record
	s.access[accessID] = accessRecord{id: accessID, clientID: clientID, subject: request.GetSubject(), audience: slices.Clone(audience), scopes: slices.Clone(request.GetScopes()), expires: expires, issuedAt: now, authTime: authTime, amr: slices.Clone(amr), familyID: family.id}
	return accessID, newToken, expires, nil
}

func (s *Store) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	record := s.refresh[hash]
	if record == nil {
		return nil, op.ErrInvalidRefreshToken
	}
	family := s.families[record.familyID]
	if record.consumed {
		s.revokeFamilyLocked(record.familyID)
		return nil, oidc.ErrInvalidGrant()
	}
	if family == nil || family.revoked || !now.Before(family.expires) {
		return nil, oidc.ErrInvalidGrant()
	}
	return &RefreshRequest{clientID: record.clientID, subject: record.subject, audience: slices.Clone(record.audience), scopes: slices.Clone(record.scopes), amr: slices.Clone(record.amr), authTime: record.authTime, familyID: record.familyID}, nil
}

func (s *Store) revokeFamilyLocked(id string) {
	if family := s.families[id]; family != nil {
		family.revoked = true
	}
	for _, record := range s.refresh {
		if record.familyID == id {
			record.consumed = true
			delete(s.access, record.accessID)
		}
	}
}

func (s *Store) TerminateSession(_ context.Context, userID, clientID string) error {
	if userID == "" || clientID == "" {
		return errors.New("logout requires a verified subject and client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	for id, record := range s.access {
		if record.subject == userID && record.clientID == clientID {
			delete(s.access, id)
			if record.familyID != "" {
				s.revokeFamilyLocked(record.familyID)
			}
		}
	}
	for id, family := range s.families {
		if family.subject == userID && family.clientID == clientID {
			s.revokeFamilyLocked(id)
		}
	}
	return nil
}

func (s *Store) GetRefreshTokenInfo(_ context.Context, clientID, token string) (string, string, error) {
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	record := s.refresh[hash]
	if record == nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	family := s.families[record.familyID]
	if record.clientID != clientID || record.consumed || family == nil || family.revoked {
		return "", "", op.ErrInvalidRefreshToken
	}
	return record.subject, token, nil
}

func (s *Store) RevokeToken(_ context.Context, tokenOrID, _ string, clientID string) *oidc.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	if access := s.access[tokenOrID]; access.id != "" {
		if access.clientID == clientID {
			delete(s.access, tokenOrID)
			if access.familyID != "" {
				s.revokeFamilyLocked(access.familyID)
			}
		}
		return nil
	}
	hash := sha256.Sum256([]byte(tokenOrID))
	record := s.refresh[hash]
	if record != nil && record.clientID == clientID {
		s.revokeFamilyLocked(record.familyID)
	}
	return nil
}

func (s *Store) SigningKey(context.Context) (op.SigningKey, error) { return &s.signing, nil }
func (s *Store) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (s *Store) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{&s.signing}}, nil
}

func (s *Store) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	client := s.clients[id]
	if client == nil {
		return nil, fmt.Errorf("client %q not found", id)
	}
	return client, nil
}
func (s *Store) AuthorizeClientIDSecret(_ context.Context, id, secret string) error {
	client := s.clients[id]
	if client == nil || client.config.Type != config.ClientTypeService {
		bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(secret))
		return errors.New("invalid client credentials")
	}
	if bcrypt.CompareHashAndPassword([]byte(client.config.SecretHash), []byte(secret)) != nil {
		return errors.New("invalid client credentials")
	}
	return nil
}
func (s *Store) ClientCredentials(ctx context.Context, id, secret string) (op.Client, error) {
	if err := s.AuthorizeClientIDSecret(ctx, id, secret); err != nil {
		return nil, err
	}
	return s.GetClientByClientID(ctx, id)
}
func (s *Store) ClientCredentialsTokenRequest(_ context.Context, id string, scopes []string) (op.TokenRequest, error) {
	client := s.clients[id]
	if client == nil || client.config.Type != config.ClientTypeService {
		return nil, oidc.ErrInvalidClient()
	}
	if len(scopes) == 0 {
		return nil, oidc.ErrInvalidScope().WithDescription("at least one scope is required")
	}
	for _, scope := range scopes {
		if !slices.Contains(client.config.AllowedScopes, scope) || !slices.Contains(client.config.Permissions, scope) {
			return nil, oidc.ErrInvalidScope()
		}
	}
	return &serviceRequest{clientID: id, subject: id, audience: slices.Clone(client.config.Audiences), scopes: slices.Clone(scopes)}, nil
}

func (s *Store) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}
func (s *Store) SetUserinfoFromRequest(_ context.Context, info *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setUserinfoLocked(info, request.GetSubject(), scopes)
}
func (s *Store) SetUserinfoFromToken(_ context.Context, info *oidc.UserInfo, tokenID, subject, origin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	record, ok := s.access[tokenID]
	if !ok || record.subject != subject {
		return errors.New("invalid_token")
	}
	if origin != "" {
		client := s.clients[record.clientID]
		if client == nil || !slices.Contains(client.config.Origins, origin) {
			return errors.New("invalid_token")
		}
	}
	return s.setUserinfoLocked(info, record.subject, record.scopes)
}
func (s *Store) setUserinfoLocked(info *oidc.UserInfo, subject string, scopes []string) error {
	user, ok := s.users[subject]
	if !ok {
		return errors.New("user not found")
	}
	info.Subject = user.ID
	if slices.Contains(scopes, oidc.ScopeProfile) {
		info.Name = user.Name
		info.PreferredUsername = user.Username
	}
	if slices.Contains(scopes, oidc.ScopeEmail) {
		info.Email = user.Email
		info.EmailVerified = oidc.Bool(user.EmailVerified)
	}
	return nil
}
func (s *Store) SetIntrospectionFromToken(_ context.Context, response *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	record, ok := s.access[tokenID]
	if !ok || record.subject != subject || record.clientID != clientID {
		response.Active = false
		return errors.New("token is inactive")
	}
	response.Active = true
	response.Scope = oidc.SpaceDelimitedArray(record.scopes)
	response.ClientID = record.clientID
	response.TokenType = string(oidc.BearerToken)
	response.Expiration = oidc.FromTime(record.expires)
	response.IssuedAt = oidc.FromTime(record.issuedAt)
	response.Subject = record.subject
	response.Audience = oidc.Audience(record.audience)
	response.JWTID = record.id
	return nil
}
func (s *Store) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (s *Store) GetPrivateClaimsFromRequest(_ context.Context, request op.TokenRequest, _ []string) (map[string]any, error) {
	clientID, _, _, err := tokenRequestInfo(request)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{"scope": oidc.SpaceDelimitedArray(request.GetScopes())}
	client := s.clients[clientID]
	if client == nil {
		return nil, errors.New("client not found")
	}
	roles := client.config.Roles
	permissions := applicationScopes(request.GetScopes())
	if user, ok := s.users[request.GetSubject()]; ok {
		claims["name"] = user.Name
		claims["preferred_username"] = user.Username
		roles = user.Roles
	}
	claims["role"] = append([]string{}, roles...)
	claims["permission"] = permissions
	return claims, nil
}
func applicationScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess:
		default:
			result = append(result, scope)
		}
	}
	return result
}
func (s *Store) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT client authentication is unsupported")
}
func (s *Store) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, oidc.ErrUnsupportedGrantType()
}
func (s *Store) Health(context.Context) error { return nil }

type AuthRequest struct {
	id, clientID, redirectURI, state, nonce, subject string
	codeChallenge                                    *oidc.CodeChallenge
	scopes, audience, amr                            []string
	responseType                                     oidc.ResponseType
	responseMode                                     oidc.ResponseMode
	created, expires, authTime                       time.Time
	done, accessAudienceReturned                     bool
}

func (r *AuthRequest) GetID() string    { return r.id }
func (r *AuthRequest) GetACR() string   { return "" }
func (r *AuthRequest) GetAMR() []string { return slices.Clone(r.amr) }
func (r *AuthRequest) GetAudience() []string {
	if !r.accessAudienceReturned {
		r.accessAudienceReturned = true
		return slices.Clone(r.audience)
	}
	return []string{r.clientID}
}
func (r *AuthRequest) GetAuthTime() time.Time                { return r.authTime }
func (r *AuthRequest) GetClientID() string                   { return r.clientID }
func (r *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return r.codeChallenge }
func (r *AuthRequest) GetNonce() string                      { return r.nonce }
func (r *AuthRequest) GetRedirectURI() string                { return r.redirectURI }
func (r *AuthRequest) GetResponseType() oidc.ResponseType    { return r.responseType }
func (r *AuthRequest) GetResponseMode() oidc.ResponseMode    { return r.responseMode }
func (r *AuthRequest) GetScopes() []string                   { return slices.Clone(r.scopes) }
func (r *AuthRequest) GetState() string                      { return r.state }
func (r *AuthRequest) GetSubject() string                    { return r.subject }
func (r *AuthRequest) Done() bool                            { return r.done }

type RefreshRequest struct {
	clientID, subject, familyID string
	audience, scopes, amr       []string
	authTime                    time.Time
	accessAudienceReturned      bool
}

func (r *RefreshRequest) GetAMR() []string { return slices.Clone(r.amr) }
func (r *RefreshRequest) GetAudience() []string {
	if !r.accessAudienceReturned {
		r.accessAudienceReturned = true
		return slices.Clone(r.audience)
	}
	return []string{r.clientID}
}
func (r *RefreshRequest) GetAuthTime() time.Time           { return r.authTime }
func (r *RefreshRequest) GetClientID() string              { return r.clientID }
func (r *RefreshRequest) GetScopes() []string              { return slices.Clone(r.scopes) }
func (r *RefreshRequest) GetSubject() string               { return r.subject }
func (r *RefreshRequest) SetCurrentScopes(scopes []string) { r.scopes = slices.Clone(scopes) }

type serviceRequest struct {
	clientID, subject string
	audience, scopes  []string
}

func (r *serviceRequest) GetSubject() string    { return r.subject }
func (r *serviceRequest) GetAudience() []string { return slices.Clone(r.audience) }
func (r *serviceRequest) GetScopes() []string   { return slices.Clone(r.scopes) }

func tokenRequestInfo(request op.TokenRequest) (string, time.Time, []string, error) {
	switch r := request.(type) {
	case *AuthRequest:
		return r.clientID, r.authTime, r.amr, nil
	case *RefreshRequest:
		return r.clientID, r.authTime, r.amr, nil
	case *serviceRequest:
		return r.clientID, time.Time{}, nil, nil
	default:
		return "", time.Time{}, nil, fmt.Errorf("unsupported token request %T", request)
	}
}

func constantTimeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
