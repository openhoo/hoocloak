package idp

import (
	"net/url"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/openhoo/hoocloak/internal/config"
)

type Client struct {
	config   config.Client
	idTTL    time.Duration
	basePath string
	dev      bool
}

func newClient(c config.Client, idTTL time.Duration, basePath string) *Client {
	dev := false
	if c.Type == config.ClientTypeSPA {
		for _, raw := range c.RedirectURIs {
			u, _ := url.Parse(raw)
			if u != nil && u.Scheme == "http" && config.IsLocalHost(u.Hostname()) {
				dev = true
			}
		}
	}
	return &Client{config: c, idTTL: idTTL, basePath: basePath, dev: dev}
}

func (c *Client) GetID() string          { return c.config.ID }
func (c *Client) RedirectURIs() []string { return slices.Clone(c.config.RedirectURIs) }
func (c *Client) PostLogoutRedirectURIs() []string {
	return slices.Clone(c.config.PostLogoutRedirectURIs)
}
func (c *Client) ApplicationType() op.ApplicationType {
	if c.config.Type == config.ClientTypeSPA {
		return op.ApplicationTypeUserAgent
	}
	return op.ApplicationTypeWeb
}
func (c *Client) AuthMethod() oidc.AuthMethod {
	if c.config.Type == config.ClientTypeSPA {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}
func (c *Client) ResponseTypes() []oidc.ResponseType {
	if c.config.Type == config.ClientTypeSPA {
		return []oidc.ResponseType{oidc.ResponseTypeCode}
	}
	return nil
}
func (c *Client) GrantTypes() []oidc.GrantType {
	if c.config.Type == config.ClientTypeSPA {
		return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
	}
	return []oidc.GrantType{oidc.GrantTypeClientCredentials}
}
func (c *Client) LoginURL(requestID string) string {
	return c.basePath + "/login?authRequestID=" + url.QueryEscape(requestID)
}
func (c *Client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *Client) IDTokenLifetime() time.Duration      { return c.idTTL }
func (c *Client) DevMode() bool                       { return c.dev }
func (c *Client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string {
		result := make([]string, 0, 2)
		for _, scope := range scopes {
			if (scope == oidc.ScopeProfile || scope == oidc.ScopeEmail) && slices.Contains(c.config.AllowedScopes, scope) {
				result = append(result, scope)
			}
		}
		return result
	}
}
func (c *Client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string {
		result := make([]string, 0, len(scopes))
		for _, scope := range scopes {
			if slices.Contains(c.config.AllowedScopes, scope) {
				result = append(result, scope)
			}
		}
		return result
	}
}
func (c *Client) IsScopeAllowed(scope string) bool {
	return slices.Contains(c.config.AllowedScopes, scope)
}
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return c.config.Type == config.ClientTypeSPA }
func (c *Client) ClockSkew() time.Duration             { return 0 }

var _ op.Client = (*Client)(nil)
