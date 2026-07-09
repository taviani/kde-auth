package domain

type ClientID string

type OAuthClient struct {
	ID               string
	ClientID         ClientID
	ClientSecretHash PasswordHash
	Name             string
	RedirectURIs     []string
}

func (c OAuthClient) AllowsRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}
