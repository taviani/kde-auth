package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type AccessClaims struct {
	Subject       domain.UserID
	Audience      domain.ClientID
	Email         domain.Email
	EmailVerified bool
	Role          domain.Role
	ExpiresAt     time.Time
}

type TokenIssuer interface {
	Issuer() string
	AccessToken(ctx context.Context, claims AccessClaims) (string, error)
	ParseAccessToken(ctx context.Context, token string) (AccessClaims, error)
	JWKS(ctx context.Context) (map[string]any, error)
}
