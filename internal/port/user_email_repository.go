package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type UserEmailRepository interface {
	ListByUser(ctx context.Context, userID domain.UserID) ([]domain.UserEmail, error)
	ByEmail(ctx context.Context, email domain.Email) (domain.UserEmail, error)
	HasSecondary(ctx context.Context, userID domain.UserID) (bool, error)
	CountVerified(ctx context.Context, userID domain.UserID) (int, error)
	InsertPendingSecondary(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) (domain.UserEmail, error)
	MarkVerified(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) error
	DeletePendingSecondary(ctx context.Context, userID domain.UserID) error
	DeleteVerified(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) error
}
