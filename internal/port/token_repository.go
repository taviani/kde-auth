package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type TokenRepository interface {
	CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode, codeHash string) error
	ConsumeAuthorizationCode(ctx context.Context, codeHash string, at time.Time) (domain.AuthorizationCode, error)
	CreateRefreshToken(ctx context.Context, token domain.RefreshToken, tokenHash string) error
	ConsumeRefreshToken(ctx context.Context, tokenHash string, at time.Time) (domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string, at time.Time) error
	CreateEmailVerificationToken(ctx context.Context, token domain.EmailVerificationToken, tokenHash string) error
	ConsumeEmailVerificationToken(ctx context.Context, tokenHash string, at time.Time) (domain.EmailVerificationToken, error)
}
