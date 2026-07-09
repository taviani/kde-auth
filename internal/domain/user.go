package domain

import "time"

type UserID string

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type UserStatus string

const (
	UserStatusPending   UserStatus = "pending"
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
)

type User struct {
	ID              UserID
	Email           Email
	PasswordHash    PasswordHash
	Role            Role
	Status          UserStatus
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (u User) IsEmailVerified() bool {
	return u.EmailVerifiedAt != nil
}

func (u User) CanAuthenticate() error {
	if u.Status == UserStatusSuspended {
		return ErrForbidden
	}
	return nil
}

func (u User) CanAuthorize() error {
	if err := u.CanAuthenticate(); err != nil {
		return err
	}
	if !u.IsEmailVerified() {
		return ErrForbidden
	}
	return nil
}
