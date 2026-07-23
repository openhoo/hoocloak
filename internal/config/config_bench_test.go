package config

import (
	"fmt"
	"testing"
	"time"
)

var benchmarkConfigError error

func BenchmarkConfigValidate(b *testing.B) {
	for _, realmCount := range []int{1, 25} {
		cfg := benchmarkConfig(realmCount, 20, 10)
		b.Run(fmt.Sprintf("Realms%d", realmCount), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchmarkConfigError = cfg.Validate()
			}
		})
	}
}

func benchmarkConfig(realmCount, usersPerRealm, clientsPerRealm int) Config {
	const passwordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5c1QUP5m6d43kYdV9He6Bpv/bVhhme"
	cfg := Config{
		BaseURL: "http://hoocloak.localhost:8080/",
		Listen:  "127.0.0.1:8080",
		Tokens: TokenConfig{
			AccessTTL:  Duration{Duration: 5 * time.Minute},
			IDTTL:      Duration{Duration: 5 * time.Minute},
			RefreshTTL: Duration{Duration: 8 * time.Hour},
		},
		Realms: make([]Realm, realmCount),
	}
	for realmIndex := range realmCount {
		realmName := fmt.Sprintf("realm-%d", realmIndex)
		realm := Realm{
			Name:    realmName,
			Users:   make([]User, usersPerRealm),
			Clients: make([]Client, clientsPerRealm),
		}
		for userIndex := range usersPerRealm {
			realm.Users[userIndex] = User{
				ID: fmt.Sprintf("user-%d", userIndex), Username: fmt.Sprintf("user-%d", userIndex),
				PasswordHash: passwordHash, Name: "Benchmark User", Email: fmt.Sprintf("user-%d@example.test", userIndex),
				Roles: []string{"member"}, Permissions: []string{"api.read", "api.write"},
			}
		}
		for clientIndex := range clientsPerRealm {
			clientID := fmt.Sprintf("client-%d", clientIndex)
			realm.Clients[clientIndex] = Client{
				ID: clientID, Type: ClientTypeSPA, Name: "Benchmark Client",
				RedirectURIs:           []string{fmt.Sprintf("http://app-%d.localhost:5173/auth/callback", clientIndex)},
				PostLogoutRedirectURIs: []string{fmt.Sprintf("http://app-%d.localhost:5173/auth/logout/callback", clientIndex)},
				Origins:                []string{fmt.Sprintf("http://app-%d.localhost:5173", clientIndex)},
				Audiences:              []string{"benchmark-api"},
				AllowedScopes:          []string{"openid", "profile", "email", "offline_access", "api.read", "api.write"},
			}
		}
		cfg.Realms[realmIndex] = realm
	}
	return cfg
}
