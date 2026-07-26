package usecase

import (
	"context"
	"net/url"
	"strings"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type AdminUsers struct {
	users port.UserAdminRepository
	clock port.Clock
}

func NewAdminUsers(users port.UserAdminRepository, clock port.Clock) *AdminUsers {
	return &AdminUsers{users: users, clock: clock}
}

type AdminUserRow struct {
	User     domain.User
	ClientIDs []domain.ClientID
}

type AdminUsersResult struct {
	Users  []AdminUserRow
	Total  int
	Filter domain.UserListFilter
	Stats  domain.UserStats
}

func (uc *AdminUsers) Dashboard(ctx context.Context) (domain.UserStats, error) {
	return uc.users.Stats(ctx, uc.clock.Now())
}

func (uc *AdminUsers) List(ctx context.Context, filter domain.UserListFilter) (AdminUsersResult, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	users, err := uc.users.List(ctx, filter)
	if err != nil {
		return AdminUsersResult{}, err
	}
	total, err := uc.users.Count(ctx, filter)
	if err != nil {
		return AdminUsersResult{}, err
	}
	ids := make([]domain.UserID, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	apps, err := uc.users.ListClientIDsForUsers(ctx, ids)
	if err != nil {
		return AdminUsersResult{}, err
	}
	rows := make([]AdminUserRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, AdminUserRow{User: u, ClientIDs: apps[u.ID]})
	}
	stats, err := uc.users.Stats(ctx, uc.clock.Now())
	if err != nil {
		return AdminUsersResult{}, err
	}
	return AdminUsersResult{Users: rows, Total: total, Filter: filter, Stats: stats}, nil
}

func (uc *AdminUsers) SetStatus(ctx context.Context, actor domain.User, id domain.UserID, status domain.UserStatus) error {
	if !actor.IsAdmin() {
		return domain.ErrForbidden
	}
	switch status {
	case domain.UserStatusActive, domain.UserStatusSuspended, domain.UserStatusPending:
	default:
		return domain.ValidationError{Field: "status", Message: "invalid status"}
	}
	if actor.ID == id && status == domain.UserStatusSuspended {
		return domain.ValidationError{Field: "status", Message: "cannot suspend your own account"}
	}
	return uc.users.SetStatus(ctx, id, status, uc.clock.Now())
}

type RecordAppAccess struct {
	accesses port.AppAccessRepository
	clock    port.Clock
}

func NewRecordAppAccess(accesses port.AppAccessRepository, clock port.Clock) *RecordAppAccess {
	return &RecordAppAccess{accesses: accesses, clock: clock}
}

func (uc *RecordAppAccess) Execute(ctx context.Context, userID domain.UserID, clientID domain.ClientID, redirectURI string) error {
	if userID == "" || clientID == "" {
		return nil
	}
	now := uc.clock.Now()
	return uc.accesses.Upsert(ctx, domain.UserAppAccess{
		UserID:      userID,
		ClientID:    clientID,
		EntryDomain: hostFromURI(redirectURI),
		FirstSeenAt: now,
		LastSeenAt:  now,
	})
}

func (uc *RecordAppAccess) HasAccess(ctx context.Context, userID domain.UserID, clientID domain.ClientID) (bool, error) {
	return uc.accesses.HasAccess(ctx, userID, clientID)
}

func hostFromURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
