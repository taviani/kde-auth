package port

import (
	"context"

	"github.com/taviani/kde-auth/internal/domain"
)

type PasswordHasher interface {
	Hash(ctx context.Context, password domain.PlainPassword) (domain.PasswordHash, error)
	Verify(hash domain.PasswordHash, password domain.PlainPassword) bool
}
