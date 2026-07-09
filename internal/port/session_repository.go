package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type SessionRepository interface {
	Create(ctx context.Context, session domain.Session, tokenHash string) error
	ByTokenHash(ctx context.Context, tokenHash string, at time.Time) (domain.Session, error)
	Revoke(ctx context.Context, tokenHash string, at time.Time) error
}
