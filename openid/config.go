package openid

import "github.com/1f349/lavender/url"

type Config struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
	ClaimsSupported        []string `json:"claims_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	JwksUri                string   `json:"jwks_uri"`
}

func GenConfig(baseUrl *url.URL, scopes, claims []string) Config {

	return Config{
		Issuer:                 baseUrl.String(),
		AuthorizationEndpoint:  baseUrl.Resolve("authorize").String(),
		TokenEndpoint:          baseUrl.Resolve("token").String(),
		UserInfoEndpoint:       baseUrl.Resolve("userinfo").String(),
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        scopes,
		ClaimsSupported:        claims,
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		JwksUri:                baseUrl.Resolve(".well-known/jwks.json").String(),
	}
}
