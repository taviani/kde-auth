package usecase

import (
	"context"
	"errors"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type ChangePassword struct {
	users    port.UserRepository
	sessions port.SessionRepository
	hasher   port.PasswordHasher
	clock    port.Clock
}

func NewChangePassword(
	users port.UserRepository,
	sessions port.SessionRepository,
	hasher port.PasswordHasher,
	clock port.Clock,
) *ChangePassword {
	return &ChangePassword{users: users, sessions: sessions, hasher: hasher, clock: clock}
}

type ChangePasswordInput struct {
	UserID              domain.UserID
	CurrentPassword     string
	NewPassword         string
	NewPasswordConfirm  string
}

func (uc *ChangePassword) Execute(ctx context.Context, in ChangePasswordInput) error {
	if in.CurrentPassword == "" {
		return domain.ValidationError{Field: "current_password", Message: "current password is required"}
	}
	if in.NewPassword != in.NewPasswordConfirm {
		return domain.ValidationError{Field: "new_password_confirm", Message: "passwords do not match"}
	}
	newPassword, err := domain.NewPlainPassword(in.NewPassword)
	if err != nil {
		return err
	}
	if in.NewPassword == in.CurrentPassword {
		return domain.ValidationError{Field: "new_password", Message: "new password must be different"}
	}

	user, err := uc.users.ByID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrUnauthorized
		}
		return err
	}
	if err := user.CanAuthorize(); err != nil {
		return domain.ErrUnauthorized
	}
	if !uc.hasher.Verify(user.PasswordHash, domain.PlainPassword(in.CurrentPassword)) {
		return domain.ErrInvalidCredentials
	}

	hash, err := uc.hasher.Hash(ctx, newPassword)
	if err != nil {
		return err
	}
	now := uc.clock.Now()
	if err := uc.users.UpdatePassword(ctx, user.ID, hash, now); err != nil {
		return err
	}
	return uc.sessions.RevokeAllForUser(ctx, user.ID, now)
}
