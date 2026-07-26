package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type UserAdminRepository interface {
	List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error)
	Count(ctx context.Context, filter domain.UserListFilter) (int, error)
	Stats(ctx context.Context, now time.Time) (domain.UserStats, error)
	SetStatus(ctx context.Context, id domain.UserID, status domain.UserStatus, at time.Time) error
	ListClientIDsForUsers(ctx context.Context, userIDs []domain.UserID) (map[domain.UserID][]domain.ClientID, error)
}

type AppAccessRepository interface {
	Upsert(ctx context.Context, access domain.UserAppAccess) error
	HasAccess(ctx context.Context, userID domain.UserID, clientID domain.ClientID) (bool, error)
}

type InviteRepository interface {
	Create(ctx context.Context, invite domain.Invite, tokenHash string) error
	ByTokenHash(ctx context.Context, tokenHash string) (domain.Invite, error)
	ListByClient(ctx context.Context, clientID domain.ClientID) ([]domain.Invite, error)
	Consume(ctx context.Context, id string, at time.Time) error
	Revoke(ctx context.Context, id string, at time.Time) error
}
