package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/taviani/kde-auth/internal/adapter/crypto"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

const (
	authCodeTTL    = 5 * time.Minute
	accessTokenTTL = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

type Authorize struct {
	clients  port.ClientRepository
	tokens   port.TokenRepository
	sessions *ResolveSession
	clock    port.Clock
}

func NewAuthorize(clients port.ClientRepository, tokens port.TokenRepository, sessions *ResolveSession, clock port.Clock) *Authorize {
	return &Authorize{clients: clients, tokens: tokens, sessions: sessions, clock: clock}
}

type AuthorizeInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	SessionToken        string
}

type AuthorizeResult struct {
	RedirectURL string
}

func (uc *Authorize) Execute(ctx context.Context, in AuthorizeInput) (AuthorizeResult, error) {
	if in.ResponseType != "code" {
		return AuthorizeResult{}, domain.ErrInvalidGrant
	}
	if err := domain.ParseScope(in.Scope); err != nil {
		return AuthorizeResult{}, err
	}
	if in.State == "" {
		return AuthorizeResult{}, domain.ValidationError{Field: "state", Message: "state is required"}
	}

	client, err := uc.clients.ByClientID(ctx, domain.ClientID(in.ClientID))
	if err != nil {
		return AuthorizeResult{}, domain.ErrInvalidClient
	}
	if !client.AllowsRedirectURI(in.RedirectURI) {
		return AuthorizeResult{}, domain.ErrInvalidRedirectURI
	}

	user, err := uc.sessions.Execute(ctx, in.SessionToken)
	if err != nil {
		return AuthorizeResult{}, err
	}

	rawCode, err := crypto.RandomToken(32)
	if err != nil {
		return AuthorizeResult{}, err
	}
	now := uc.clock.Now()
	code := domain.AuthorizationCode{
		UserID:      user.ID,
		ClientID:    client.ClientID,
		RedirectURI: in.RedirectURI,
		Scope:       in.Scope,
		ExpiresAt:   now.Add(authCodeTTL),
	}
	if err := uc.tokens.CreateAuthorizationCode(ctx, code, crypto.HashToken(rawCode)); err != nil {
		return AuthorizeResult{}, err
	}

	redirectURL, err := buildRedirect(in.RedirectURI, rawCode, in.State)
	if err != nil {
		return AuthorizeResult{}, err
	}
	return AuthorizeResult{RedirectURL: redirectURL}, nil
}

func buildRedirect(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", domain.ErrInvalidRedirectURI
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type ExchangeToken struct {
	clients port.ClientRepository
	tokens  port.TokenRepository
	users   port.UserRepository
	hasher  port.PasswordHasher
	issuer  port.TokenIssuer
	clock   port.Clock
}

func NewExchangeToken(
	clients port.ClientRepository,
	tokens port.TokenRepository,
	users port.UserRepository,
	hasher port.PasswordHasher,
	issuer port.TokenIssuer,
	clock port.Clock,
) *ExchangeToken {
	return &ExchangeToken{
		clients: clients,
		tokens:  tokens,
		users:   users,
		hasher:  hasher,
		issuer:  issuer,
		clock:   clock,
	}
}

type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
}

type TokenResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	Scope        string
}

func (uc *ExchangeToken) Execute(ctx context.Context, in TokenInput) (TokenResult, error) {
	switch in.GrantType {
	case "authorization_code":
		return uc.exchangeCode(ctx, in)
	case "refresh_token":
		return uc.refresh(ctx, in)
	default:
		return TokenResult{}, domain.ErrInvalidGrant
	}
}

func (uc *ExchangeToken) exchangeCode(ctx context.Context, in TokenInput) (TokenResult, error) {
	client, err := uc.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return TokenResult{}, err
	}

	now := uc.clock.Now()
	code, err := uc.tokens.ConsumeAuthorizationCode(ctx, crypto.HashToken(in.Code), now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return TokenResult{}, domain.ErrInvalidGrant
		}
		return TokenResult{}, err
	}
	if code.ClientID != client.ClientID || code.RedirectURI != in.RedirectURI {
		return TokenResult{}, domain.ErrInvalidGrant
	}

	user, err := uc.users.ByID(ctx, code.UserID)
	if err != nil {
		return TokenResult{}, domain.ErrInvalidGrant
	}
	if err := user.CanAuthorize(); err != nil {
		return TokenResult{}, domain.ErrInvalidGrant
	}

	return uc.issueTokens(ctx, user, client.ClientID, code.Scope)
}

func (uc *ExchangeToken) refresh(ctx context.Context, in TokenInput) (TokenResult, error) {
	client, err := uc.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return TokenResult{}, err
	}

	now := uc.clock.Now()
	refresh, err := uc.tokens.ConsumeRefreshToken(ctx, crypto.HashToken(in.RefreshToken), now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return TokenResult{}, domain.ErrInvalidGrant
		}
		return TokenResult{}, err
	}
	if refresh.ClientID != client.ClientID {
		return TokenResult{}, domain.ErrInvalidGrant
	}

	user, err := uc.users.ByID(ctx, refresh.UserID)
	if err != nil {
		return TokenResult{}, domain.ErrInvalidGrant
	}
	if err := user.CanAuthorize(); err != nil {
		return TokenResult{}, domain.ErrInvalidGrant
	}

	return uc.issueTokens(ctx, user, client.ClientID, fmt.Sprintf("%s %s", domain.ScopeOpenID, domain.ScopeEmail))
}

func (uc *ExchangeToken) authenticateClient(ctx context.Context, clientID, secret string) (domain.OAuthClient, error) {
	client, err := uc.clients.ByClientID(ctx, domain.ClientID(clientID))
	if err != nil {
		return domain.OAuthClient{}, domain.ErrInvalidClient
	}
	if !uc.hasher.Verify(client.ClientSecretHash, domain.PlainPassword(secret)) {
		return domain.OAuthClient{}, domain.ErrInvalidClient
	}
	return client, nil
}

func (uc *ExchangeToken) issueTokens(ctx context.Context, user domain.User, clientID domain.ClientID, scope string) (TokenResult, error) {
	now := uc.clock.Now()
	expiresAt := now.Add(accessTokenTTL)
	accessToken, err := uc.issuer.AccessToken(ctx, port.AccessClaims{
		Subject:       user.ID,
		Audience:      clientID,
		Email:         user.Email,
		EmailVerified: user.IsEmailVerified(),
		Role:          user.Role,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		return TokenResult{}, err
	}

	rawRefresh, err := crypto.RandomToken(32)
	if err != nil {
		return TokenResult{}, err
	}
	refresh := domain.RefreshToken{
		UserID:    user.ID,
		ClientID:  clientID,
		ExpiresAt: now.Add(refreshTokenTTL),
	}
	if err := uc.tokens.CreateRefreshToken(ctx, refresh, crypto.HashToken(rawRefresh)); err != nil {
		return TokenResult{}, err
	}

	return TokenResult{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: rawRefresh,
		Scope:        scope,
	}, nil
}

type UserInfo struct {
	issuer port.TokenIssuer
	users  port.UserRepository
}

func NewUserInfo(issuer port.TokenIssuer, users port.UserRepository) *UserInfo {
	return &UserInfo{issuer: issuer, users: users}
}

func (uc *UserInfo) Execute(ctx context.Context, claims port.AccessClaims) (map[string]any, error) {
	user, err := uc.users.ByID(ctx, claims.Subject)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	return map[string]any{
		"sub":            string(user.ID),
		"email":          user.Email.String(),
		"email_verified": user.IsEmailVerified(),
		"role":           string(user.Role),
	}, nil
}

type OIDCMetadata struct {
	issuer port.TokenIssuer
}

func NewOIDCMetadata(issuer port.TokenIssuer) *OIDCMetadata {
	return &OIDCMetadata{issuer: issuer}
}

func (uc *OIDCMetadata) Execute() map[string]any {
	issuer := uc.issuer.Issuer()
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{domain.ScopeOpenID, domain.ScopeEmail},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	}
}
