package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user domain.User) (domain.UserID, error)
	ByEmail(ctx context.Context, email domain.Email) (domain.User, error)
	ByID(ctx context.Context, id domain.UserID) (domain.User, error)
	MarkEmailVerified(ctx context.Context, id domain.UserID, at time.Time) error
	ExistsByEmail(ctx context.Context, email domain.Email) (bool, error)
}
