package idp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type fakeClock struct {
	current time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.current
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.current = c.current.Add(duration)
}

func newTestStore(t *testing.T, clock Clock) *Store {
	t.Helper()
	return NewStore(testConfig(t), nil, "test-kid", clock)
}

func BenchmarkAuthRequestByIDWithActiveState(b *testing.B) {
	clock := &fakeClock{current: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	store := NewStore(testConfig(b), nil, "test-kid", clock)
	const requestCount = 10_000
	for i := range requestCount {
		id := fmt.Sprintf("request-%d", i)
		store.authRequests[id] = &AuthRequest{id: id, expires: clock.Now().Add(5 * time.Minute)}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := store.AuthRequestByID(context.Background(), "request-5000"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRevokeFamilyWithManyFamilies(b *testing.B) {
	store := NewStore(testConfig(b), nil, "test-kid", nil)
	const familyCount = 10_000
	for i := range familyCount {
		familyID := fmt.Sprintf("family-%d", i)
		hash := sha256.Sum256([]byte(familyID))
		store.families[familyID] = &refreshFamily{id: familyID, tokens: [][32]byte{hash}}
		store.refresh[hash] = &refreshRecord{hash: hash, familyID: familyID}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		store.revokeFamilyLocked("family-5000")
	}
}

func TestAuthorizationCodeIsConsumedExactlyOnce(t *testing.T) {
	clock := &fakeClock{current: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	store := newTestStore(t, clock)
	request := &AuthRequest{
		id: "request-id", clientID: "react-spa", subject: "alice", done: true,
		expires: clock.Now().Add(5 * time.Minute), scopes: []string{"openid", "api.read"},
	}
	store.authRequests[request.id] = request
	if err := store.SaveAuthCode(context.Background(), request.id, "one-time-code"); err != nil {
		t.Fatalf("SaveAuthCode() error = %v", err)
	}
	other := &AuthRequest{
		id: "other-request", clientID: "react-spa", subject: "alice", done: true,
		expires: clock.Now().Add(5 * time.Minute), scopes: []string{"openid"},
	}
	store.authRequests[other.id] = other
	if err := store.SaveAuthCode(context.Background(), other.id, "one-time-code"); err == nil {
		t.Fatal("authorization code collision overwrote an existing code")
	}
	if err := store.SaveAuthCode(context.Background(), other.id, "other-code"); err != nil {
		t.Fatalf("request was consumed by rejected code collision: %v", err)
	}
	if err := store.SaveAuthCode(context.Background(), request.id, "second-code"); err == nil {
		t.Fatal("second authorization code was issued for the same request")
	}
	first, err := store.AuthRequestByCode(context.Background(), "one-time-code")
	if err != nil || first.GetID() != request.id {
		t.Fatalf("first code redemption = (%v, %v)", first, err)
	}
	if _, err := store.AuthRequestByCode(context.Background(), "one-time-code"); err == nil {
		t.Fatal("second code redemption unexpectedly succeeded")
	}
	if _, err := store.AuthRequestByCode(context.Background(), "second-code"); err == nil {
		t.Fatal("rejected second code was stored")
	}
	if redeemed, err := store.AuthRequestByCode(context.Background(), "other-code"); err != nil || redeemed.GetID() != other.id {
		t.Fatalf("other code redemption = (%v, %v)", redeemed, err)
	}
}

func TestAuthenticationIntersectsClientAndUserScopes(t *testing.T) {
	clock := &fakeClock{current: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	store := newTestStore(t, clock)
	request := &AuthRequest{
		id: "request-id", clientID: "react-spa", expires: clock.Now().Add(5 * time.Minute),
		scopes: []string{"openid", "profile", "offline_access", "api.read", "api.write"},
	}
	store.authRequests[request.id] = request
	if err := store.Authenticate(request.id, "  ALICE ", "alice-password"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if err := store.Authenticate(request.id, "alice", "alice-password"); err == nil {
		t.Fatal("completed authorization request accepted another authentication")
	}
	if !request.done || request.subject != "alice" || !slices.Equal(request.amr, []string{"pwd"}) {
		t.Fatalf("authentication state = done:%v subject:%q amr:%v", request.done, request.subject, request.amr)
	}
	wantScopes := []string{"openid", "profile", "offline_access", "api.read"}
	if !slices.Equal(request.scopes, wantScopes) {
		t.Fatalf("granted scopes = %v, want %v", request.scopes, wantScopes)
	}
	claims, err := store.GetPrivateClaimsFromRequest(context.Background(), request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(claims["role"].([]string), []string{"admin"}) || !slices.Equal(claims["permission"].([]string), []string{"api.read"}) {
		t.Fatalf("authorization claims = %#v", claims)
	}

	client := store.clients["react-spa"]
	idScopes := client.RestrictAdditionalIdTokenScopes()([]string{"profile", "email", "api.read", "offline_access"})
	if !slices.Equal(idScopes, []string{"profile", "email"}) {
		t.Fatalf("additional ID-token scopes = %v", idScopes)
	}
}
func TestSelectIdentityCompletesAuthorizationWithoutPassword(t *testing.T) {
	clock := &fakeClock{current: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	store := newTestStore(t, clock)
	request := &AuthRequest{
		id: "request-id", clientID: "react-spa", expires: clock.Now().Add(5 * time.Minute),
		scopes: []string{"openid", "profile", "api.read", "api.write"},
	}
	store.authRequests[request.id] = request

	if err := store.SelectIdentity(request.id, "alice"); err != nil {
		t.Fatalf("SelectIdentity() error = %v", err)
	}
	if !request.done || request.subject != "alice" || !slices.Equal(request.amr, []string{"dev-select"}) {
		t.Fatalf("selection state = done:%v subject:%q amr:%v", request.done, request.subject, request.amr)
	}
	if want := []string{"openid", "profile", "api.read"}; !slices.Equal(request.scopes, want) {
		t.Fatalf("granted scopes = %v, want %v", request.scopes, want)
	}
	if err := store.SelectIdentity(request.id, "missing"); err == nil {
		t.Fatal("SelectIdentity() accepted an unknown identity")
	}
}

func TestTokenAudienceSelectionIsRaceSafe(t *testing.T) {
	request := &AuthRequest{clientID: "react-spa", audience: []string{"hoocloak-api"}}
	const calls = 32
	results := make(chan []string, calls)
	var group sync.WaitGroup
	for range calls {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- request.GetAudience()
		}()
	}
	group.Wait()
	close(results)

	resourceAudiences := 0
	clientAudiences := 0
	for audience := range results {
		switch {
		case slices.Equal(audience, []string{"hoocloak-api"}):
			resourceAudiences++
		case slices.Equal(audience, []string{"react-spa"}):
			clientAudiences++
		default:
			t.Fatalf("unexpected audience: %v", audience)
		}
	}
	if resourceAudiences != 1 || clientAudiences != calls-1 {
		t.Fatalf("audience selection = resource:%d client:%d", resourceAudiences, clientAudiences)
	}
}

func TestRefreshRotationAndAncestorReplayRevokesFamily(t *testing.T) {
	clock := &fakeClock{current: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	store := newTestStore(t, clock)
	request := &AuthRequest{
		clientID: "react-spa", subject: "alice", audience: []string{"hoocloak-api"},
		scopes: []string{"openid", "offline_access", "api.read"}, authTime: clock.Now(), amr: []string{"pwd"},
	}
	firstAccess, firstRefresh, _, err := store.CreateAccessAndRefreshTokens(context.Background(), request, "")
	if err != nil {
		t.Fatalf("create refresh family: %v", err)
	}
	rotationRequest, err := store.TokenRequestByRefreshToken(context.Background(), firstRefresh)
	if err != nil {
		t.Fatalf("read first refresh token: %v", err)
	}
	secondAccess, secondRefresh, _, err := store.CreateAccessAndRefreshTokens(context.Background(), rotationRequest, firstRefresh)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if firstRefresh == secondRefresh || firstAccess == secondAccess {
		t.Fatal("rotation reused a token identifier")
	}
	if _, exists := store.access[firstAccess]; exists {
		t.Fatal("rotation left predecessor access metadata active")
	}
	if _, err := store.TokenRequestByRefreshToken(context.Background(), secondRefresh); err != nil {
		t.Fatalf("successor was not active before replay: %v", err)
	}
	if _, err := store.TokenRequestByRefreshToken(context.Background(), firstRefresh); err == nil {
		t.Fatal("consumed ancestor replay unexpectedly succeeded")
	}
	if _, err := store.TokenRequestByRefreshToken(context.Background(), secondRefresh); err == nil {
		t.Fatal("successor remained usable after ancestor replay")
	}
	if _, exists := store.access[secondAccess]; exists {
		t.Fatal("family replay left successor access metadata active")
	}
}

func TestRefreshFamilyUsesNonSlidingAbsoluteExpiry(t *testing.T) {
	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := &fakeClock{current: start}
	store := newTestStore(t, clock)
	request := &AuthRequest{
		clientID: "react-spa", subject: "alice", audience: []string{"hoocloak-api"},
		scopes: []string{"openid", "offline_access", "api.read"}, authTime: start, amr: []string{"pwd"},
	}
	_, firstRefresh, _, err := store.CreateAccessAndRefreshTokens(context.Background(), request, "")
	if err != nil {
		t.Fatal(err)
	}
	firstHash := sha256.Sum256([]byte(firstRefresh))
	familyID := store.refresh[firstHash].familyID
	wantExpiry := start.Add(testConfig(t).Tokens.RefreshTTL.Duration)
	if got := store.families[familyID].expires; !got.Equal(wantExpiry) {
		t.Fatalf("initial family expiry = %v, want %v", got, wantExpiry)
	}

	clock.Advance(7 * time.Hour)
	rotationRequest, err := store.TokenRequestByRefreshToken(context.Background(), firstRefresh)
	if err != nil {
		t.Fatal(err)
	}
	_, successor, _, err := store.CreateAccessAndRefreshTokens(context.Background(), rotationRequest, firstRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.families[familyID].expires; !got.Equal(wantExpiry) {
		t.Fatalf("rotation slid family expiry to %v, want %v", got, wantExpiry)
	}

	clock.Advance(time.Hour)
	if _, err := store.TokenRequestByRefreshToken(context.Background(), successor); err == nil {
		t.Fatal("refresh successor remained active at absolute family expiry")
	}
	if _, exists := store.families[familyID]; exists {
		t.Fatal("expired family was not pruned")
	}
	if _, exists := store.refresh[sha256.Sum256([]byte(successor))]; exists {
		t.Fatal("expired refresh record was not pruned")
	}
}

func TestInjectedClockControlsAccessAndCodeExpiryPruning(t *testing.T) {
	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := &fakeClock{current: start}
	store := newTestStore(t, clock)
	request := &serviceRequest{clientID: "worker", subject: "worker", audience: []string{"hoocloak-api"}, scopes: []string{"api.read"}}
	accessID, expiry, err := store.CreateAccessToken(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := start.Add(testConfig(t).Tokens.AccessTTL.Duration)
	if !expiry.Equal(wantExpiry) {
		t.Fatalf("access expiry = %v, want %v", expiry, wantExpiry)
	}

	auth := &AuthRequest{id: "expires", clientID: "react-spa", done: true, expires: start.Add(5 * time.Minute)}
	store.authRequests[auth.id] = auth
	if err := store.SaveAuthCode(context.Background(), auth.id, "expires"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Minute)
	if _, err := store.AuthRequestByID(context.Background(), auth.id); err == nil {
		t.Fatal("authorization request remained active at expiry")
	}
	if _, err := store.AuthRequestByCode(context.Background(), "expires"); err == nil {
		t.Fatal("authorization code remained active at expiry")
	}

	clock.current = wantExpiry
	response := new(oidc.IntrospectionResponse)
	if err := store.SetIntrospectionFromToken(context.Background(), response, accessID, "worker", "worker"); err == nil {
		t.Fatal("expired access metadata was accepted for introspection")
	}
	if response.Active {
		t.Fatal("access metadata remained active at expiry")
	}
	if _, exists := store.access[accessID]; exists {
		t.Fatal("expired access metadata was not pruned")
	}
}

type sequenceClock struct {
	times []time.Time
	index int
}

func (c *sequenceClock) Now() time.Time {
	if c.index >= len(c.times) {
		return c.times[len(c.times)-1]
	}
	value := c.times[c.index]
	c.index++
	return value
}

func TestAuthenticationRechecksExpiryAfterPasswordVerification(t *testing.T) {
	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := &sequenceClock{times: []time.Time{start, start.Add(2 * time.Second)}}
	store := newTestStore(t, clock)
	request := &AuthRequest{
		id:       "expires-during-password-check",
		clientID: "react-spa",
		expires:  start.Add(time.Second),
		scopes:   []string{"openid"},
	}
	store.authRequests[request.id] = request

	if err := store.Authenticate(request.id, "alice", "alice-password"); err == nil {
		t.Fatal("Authenticate() accepted a request that expired during password verification")
	}
	if request.done {
		t.Fatal("expired authorization request was marked complete")
	}
}
